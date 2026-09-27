"""Offline BSAM-aligned coverage mapping for K'amal BLE assessments.

This module maps already-collected assessment evidence to the Bluetooth Security
Assessment Methodology (BSAM) control set. It does not perform RF operations and
it does not convert evidence presence into a BSAM pass/fail determination.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from kamal.ble_correlation import load_assessment_source
from kamal.catalog_provenance import normalize_catalog_provenance
from kamal.evidence_contracts import EVIDENCE_CONTRACT_VERSION
from kamal.findings import resolve_evidence_path, validate_findings


BSAM_MAPPING_SCHEMA_VERSION = "0.12.0"
BSAM_PROFILE_VERSION = "kamal-bsam-2026-09-25.1"
BSAM_SOURCE_URL = "https://www.tarlogic.com/bsam/controls/"

# BSAM is maintained externally and can evolve. This embedded profile is a
# reproducible K'amal mapping profile, not a claim that upstream BSAM is frozen.
BSAM_CONTROLS = (
    ("BSAM-IG-01", "Information gathering", "Bluetooth controller lifecycle status"),
    ("BSAM-IG-02", "Information gathering", "Known Bluetooth controller vulnerabilities"),
    ("BSAM-IG-03", "Information gathering", "Known Bluetooth host stack vulnerabilities"),
    ("BSAM-IG-04", "Information gathering", "Known Bluetooth standard version vulnerabilities"),
    ("BSAM-DI-01", "Discovery", "Operation modes (BR/EDR and BLE)"),
    ("BSAM-DI-02", "Discovery", "Adequate device's signal"),
    ("BSAM-DI-03", "Discovery", "Generic device naming"),
    ("BSAM-DI-04", "Discovery", "Sensitive data exposure"),
    ("BSAM-DI-05", "Discovery", "Device discoverablility"),
    ("BSAM-DI-06", "Discovery", "Use random MAC address"),
    ("BSAM-PA-01", "Pairing", "Pairable mode by default"),
    ("BSAM-PA-02", "Pairing", "Input and output capabilities"),
    ("BSAM-PA-03", "Pairing", "Bluetooth OOB channel security"),
    ("BSAM-PA-04", "Pairing", "Rejection of legacy pairing"),
    ("BSAM-PA-05", "Pairing", "Pairing without user interaction"),
    ("BSAM-PA-06", "Pairing", "Known Pin Codes"),
    ("BSAM-PA-07", "Pairing", "Predictable PIN codes"),
    ("BSAM-PA-08", "Pairing", "Bluetooth link key removal"),
    ("BSAM-PA-09", "Pairing", "Minimum PIN code length"),
    ("BSAM-PA-10", "Pairing", "Storage of Bluetooth Link keys"),
    ("BSAM-AU-01", "Authentication", "Role switch before authentication"),
    ("BSAM-AU-02", "Authentication", "Mutual authentication"),
    ("BSAM-AU-03", "Authentication", "Forced disconnection"),
    ("BSAM-EN-01", "Encryption", "Role changes before encryption"),
    ("BSAM-EN-02", "Encryption", "Forced bluetooth encryption"),
    ("BSAM-EN-03", "Encryption", "Minimum encryption key size"),
    ("BSAM-SE-01", "Services", "Hidden Bluetooth SDP services"),
    ("BSAM-SE-02", "Services", "Hidden GATT Bluetooth services"),
    ("BSAM-SE-03", "Services", "Bluetooth Service access control"),
    ("BSAM-AP-01", "Application", "Controller firmware update"),
    ("BSAM-AP-02", "Application", "Bluetooth stack update"),
    ("BSAM-AP-03", "Application", "Application update"),
    ("BSAM-AP-04", "Application", "Digital signature of updates"),
    ("BSAM-AP-05", "Application", "Replay attacks"),
    ("BSAM-AP-06", "Application", "Bluetooth packet injection attacks"),
    ("BSAM-AP-07", "Application", "Secure applications"),
)

_FINDING_CONTROL_MAP = {
    "BLE-GATT-001": ("BSAM-SE-03",),
}

_CONTEXT_CONTROL_MAP = {
    "manufacturer": ("BSAM-IG-01", "BSAM-IG-02"),
    "device_family": ("BSAM-IG-01", "BSAM-IG-02"),
    "product_model": ("BSAM-IG-01", "BSAM-IG-02"),
    "chipset": ("BSAM-IG-01", "BSAM-IG-02"),
    "device_function": ("BSAM-SE-03",),
    "gatt_service_purpose": ("BSAM-SE-03",),
    "gatt_characteristic_purpose": ("BSAM-SE-03",),
    "gatt_descriptor_purpose": ("BSAM-SE-03",),
    "security_context": ("BSAM-SE-03",),
}

_PUBLIC_ADVERTISING_FIELDS = (
    "manufacturer_data",
    "service_data",
    "service_uuids",
    "service_uuids_16",
    "service_uuids_32",
    "service_uuids_128",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _require_nonempty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _validate_sha256(value, field="sha256"):
    text = _require_nonempty_string(value, field).lower()
    if len(text) != 64:
        raise ValueError(f"{field} must contain 64 hexadecimal characters")
    try:
        int(text, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must contain 64 hexadecimal characters") from exc
    return text


def _profile_sha256():
    material = json.dumps(
        [list(item) for item in BSAM_CONTROLS],
        ensure_ascii=True,
        sort_keys=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _control_template(control_id, group, title):
    return {
        "control_id": control_id,
        "group": group,
        "title": title,
        "coverage_state": "not_assessed",
        "review_state": "no_conclusion",
        "signals": [],
        "finding_references": [],
        "context_claims": [],
        "assessment_statement": (
            "K'amal has not assessed this BSAM control with the supplied evidence."
        ),
        "limitations": [
            "Absence of mapped evidence is not evidence that the control passes or that no issue exists."
        ],
    }


def _signal_key(signal):
    return (
        signal["observation_id"],
        signal["evidence_path"],
        signal["signal_kind"],
        signal["summary"],
    )


def _add_signal(control, observation, *, path, kind, summary):
    report = observation.get("report")
    if not isinstance(report, dict):
        raise ValueError("assessment observation.report must be an object")
    resolve_evidence_path(report, path)
    signal = {
        "state": "observed",
        "confidence": "high",
        "observation_id": _require_nonempty_string(
            observation.get("observation_id"), "observation_id"
        ),
        "source_id": _require_nonempty_string(observation.get("source_id"), "source_id"),
        "evidence_path": path,
        "signal_kind": kind,
        "summary": summary,
    }
    if _signal_key(signal) not in {_signal_key(item) for item in control["signals"]}:
        control["signals"].append(signal)


def _extract_passive_signals(observation, controls):
    report = observation["report"]
    advertisers = report.get("advertisers", [])
    if not isinstance(advertisers, list):
        raise ValueError("passive_ble report.advertisers must be a list")

    for advertiser_index, advertiser in enumerate(advertisers):
        if not isinstance(advertiser, dict):
            raise ValueError("passive_ble advertiser must be an object")
        base = f"/advertisers/{advertiser_index}"

        _add_signal(
            controls["BSAM-DI-01"], observation,
            path=base,
            kind="ble_mode_observed",
            summary="A BLE advertiser was observed; this is evidence of BLE operation, not a determination that enabled modes are appropriate.",
        )
        _add_signal(
            controls["BSAM-DI-05"], observation,
            path=base,
            kind="ble_discovery_observed",
            summary="The device was observed during BLE discovery/advertising; duration and intended discoverability were not established.",
        )

        for field in ("name", "local_name"):
            value = advertiser.get(field)
            if isinstance(value, str) and value.strip():
                _add_signal(
                    controls["BSAM-DI-03"], observation,
                    path=f"{base}/{field}",
                    kind="advertised_name_observed",
                    summary="A device name was exposed in discovery evidence; K'amal does not determine from the name alone whether it is appropriately generic.",
                )

        names = advertiser.get("names")
        if names is not None:
            if not isinstance(names, list):
                raise ValueError("passive_ble advertiser.names must be a list")
            for name_index, value in enumerate(names):
                if isinstance(value, str) and value.strip():
                    _add_signal(
                        controls["BSAM-DI-03"], observation,
                        path=f"{base}/names/{name_index}",
                        kind="advertised_name_observed",
                        summary="A device name was exposed in discovery evidence; K'amal does not determine from the name alone whether it is appropriately generic.",
                    )

        for field in _PUBLIC_ADVERTISING_FIELDS:
            value = advertiser.get(field)
            if value in (None, [], {}):
                continue
            _add_signal(
                controls["BSAM-DI-04"], observation,
                path=f"{base}/{field}",
                kind="public_discovery_data_observed",
                summary="Public advertising/discovery data was observed; sensitivity cannot be determined without device-specific context.",
            )

        if "address" in advertiser and "address_type" in advertiser:
            _add_signal(
                controls["BSAM-DI-06"], observation,
                path=f"{base}/address_type",
                kind="address_type_observed",
                summary="An address type was recorded; this does not establish address rotation, resolvability, or stable device identity.",
            )


def _extract_active_signals(observation, controls):
    report = observation["report"]
    if report.get("evidence_type") == "active_gatt":
        _add_signal(
            controls["BSAM-DI-01"], observation,
            path="/evidence_type",
            kind="ble_mode_observed",
            summary="Active BLE GATT evidence establishes BLE operation for this observation, not whether other enabled modes are necessary.",
        )

    gatt = report.get("gatt")
    if not isinstance(gatt, dict) or not gatt.get("enumerated") or gatt.get("error") is not None:
        return
    services = gatt.get("services")
    if not isinstance(services, list):
        raise ValueError("active_gatt report.gatt.services must be a list")

    _add_signal(
        controls["BSAM-SE-02"], observation,
        path="/gatt/services",
        kind="gatt_service_enumeration_observed",
        summary="GATT services were enumerated through the normal discovery path; alternative discovery needed to test for hidden services was not performed.",
    )
    _add_signal(
        controls["BSAM-SE-03"], observation,
        path="/gatt/services",
        kind="gatt_metadata_observed",
        summary="GATT service/characteristic metadata is available for access-control review; metadata alone does not prove effective authorization, authentication, or encryption requirements.",
    )


def _map_findings(assessment, controls):
    findings = assessment.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("assessment.findings must be a list")

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("assessment finding must be an object")
        rule_id = finding.get("rule_id")
        target_controls = _FINDING_CONTROL_MAP.get(rule_id, ())
        if not target_controls:
            continue
        finding_id = _require_nonempty_string(finding.get("finding_id"), "finding_id")
        status = _require_nonempty_string(finding.get("status"), "finding status")
        reference = {
            "finding_id": finding_id,
            "rule_id": _require_nonempty_string(rule_id, "finding rule_id"),
            "status": status,
            "severity": _require_nonempty_string(finding.get("severity"), "finding severity"),
            "confidence": _require_nonempty_string(finding.get("confidence"), "finding confidence"),
            "title": _require_nonempty_string(finding.get("title"), "finding title"),
            "evidence": deepcopy(finding.get("evidence", [])),
        }
        for control_id in target_controls:
            controls[control_id]["finding_references"].append(deepcopy(reference))


def _load_enrichment_source(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("enrichment must be a JSON object")
    if payload.get("schema_version") != BSAM_MAPPING_SCHEMA_VERSION:
        raise ValueError("enrichment schema version is unsupported")
    if payload.get("record_type") != "ble_device_intelligence_enrichment":
        raise ValueError("unsupported enrichment record type")
    if payload.get("contract_version") != EVIDENCE_CONTRACT_VERSION:
        raise ValueError("enrichment evidence contract version is unsupported")
    if not isinstance(payload.get("claims"), list):
        raise ValueError("enrichment.claims must be a list")
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "enrichment_source_id": f"sha256:{digest}",
        "path": str(path),
        "sha256": digest,
        "enrichment": payload,
    }


def load_bsam_enrichment_source(path):
    """Load one K'amal device-intelligence enrichment with byte provenance."""
    return _load_enrichment_source(path)


def _validate_enrichment_binding(enrichment_source, assessment_source):
    enrichment = enrichment_source["enrichment"]
    binding = enrichment.get("assessment_source")
    if not isinstance(binding, dict):
        raise ValueError("enrichment assessment_source must be an object")
    expected_sha = _validate_sha256(assessment_source.get("sha256"), "assessment sha256")
    if binding.get("sha256") != expected_sha:
        raise ValueError("enrichment does not reference the supplied assessment sha256")
    if binding.get("assessment_source_id") != f"sha256:{expected_sha}":
        raise ValueError("enrichment assessment_source_id does not match supplied assessment")
    if binding.get("assessment_id") != assessment_source.get("assessment_id"):
        raise ValueError("enrichment assessment_id does not match supplied assessment")


def _map_context_claims(enrichment_source, controls, observation_ids):
    if enrichment_source is None:
        return
    enrichment = enrichment_source["enrichment"]
    claims = enrichment.get("claims", [])
    for claim in claims:
        if not isinstance(claim, dict):
            raise ValueError("enrichment claim must be an object")
        category = claim.get("category")
        target_controls = _CONTEXT_CONTROL_MAP.get(category, ())
        if not target_controls:
            continue
        state = _require_nonempty_string(claim.get("state"), "claim state")
        if state not in {"documented", "inferred", "validated"}:
            raise ValueError(f"unsupported intelligence claim state: {state}")
        observation_id = _require_nonempty_string(
            claim.get("observation_id"), "claim observation_id"
        )
        if observation_id not in observation_ids:
            raise ValueError("enrichment claim references unknown assessment observation")
        limitations = claim.get("limitations", [])
        if not isinstance(limitations, list) or any(
            not isinstance(item, str) or not item.strip() for item in limitations
        ):
            raise ValueError("claim limitations must be a list of non-empty strings")
        if state == "validated":
            validation = claim.get("validation")
            if not isinstance(validation, dict):
                raise ValueError("validated enrichment claim requires validation metadata")
            normalized_validation = {
                "reviewer": _require_nonempty_string(validation.get("reviewer"), "validation reviewer"),
                "validated_at_utc": _require_nonempty_string(
                    validation.get("validated_at_utc"), "validation timestamp"
                ),
                "basis": _require_nonempty_string(validation.get("basis"), "validation basis"),
            }
        else:
            normalized_validation = None
        context = {
            "claim_id": _require_nonempty_string(claim.get("claim_id"), "claim_id"),
            "category": _require_nonempty_string(category, "claim category"),
            "value": _require_nonempty_string(claim.get("value"), "claim value"),
            "state": state,
            "confidence": _require_nonempty_string(claim.get("confidence"), "claim confidence"),
            "observation_id": observation_id,
            "catalog_source_id": _require_nonempty_string(
                claim.get("catalog_source_id"), "claim catalog_source_id"
            ),
            "catalog_record_id": _require_nonempty_string(
                claim.get("catalog_record_id"), "claim catalog_record_id"
            ),
            "limitations": [item.strip() for item in limitations],
        }
        if normalized_validation is not None:
            context["validation"] = normalized_validation
        for control_id in target_controls:
            controls[control_id]["context_claims"].append(deepcopy(context))


def _finalize_control(control):
    control["signals"].sort(key=lambda item: (
        item["observation_id"], item["evidence_path"], item["signal_kind"], item["summary"]
    ))
    control["finding_references"].sort(key=lambda item: item["finding_id"])
    control["context_claims"].sort(key=lambda item: (
        item["category"], item["value"], item["claim_id"]
    ))

    if control["signals"] or control["finding_references"]:
        control["coverage_state"] = "evidence_available"

    statuses = {item["status"] for item in control["finding_references"]}
    if "confirmed" in statuses:
        control["review_state"] = "confirmed_finding"
        control["assessment_statement"] = (
            "The supplied assessment contains a confirmed K'amal finding mapped to this control. "
            "That finding is not automatically a BSAM pass/fail determination."
        )
    elif "potential" in statuses:
        control["review_state"] = "candidate_concern"
        control["assessment_statement"] = (
            "Mapped evidence includes a candidate security concern requiring analyst review; "
            "the BSAM control has not been given a pass/fail result."
        )
    elif control["coverage_state"] == "evidence_available":
        control["assessment_statement"] = (
            "Supplied evidence is relevant to this BSAM control but is insufficient for a pass/fail determination."
        )

    if control["context_claims"]:
        control["limitations"].append(
            "Device-intelligence claims are context only; documented, inferred, or validated claim state does not by itself assess this BSAM control."
        )
    return control


def _group_summary(controls):
    groups = []
    seen = []
    for _, group, _ in BSAM_CONTROLS:
        if group not in seen:
            seen.append(group)
    for group in seen:
        members = [item for item in controls if item["group"] == group]
        groups.append({
            "group": group,
            "control_count": len(members),
            "not_assessed_count": sum(item["coverage_state"] == "not_assessed" for item in members),
            "evidence_available_count": sum(item["coverage_state"] == "evidence_available" for item in members),
            "candidate_concern_count": sum(item["review_state"] == "candidate_concern" for item in members),
            "confirmed_finding_count": sum(item["review_state"] == "confirmed_finding" for item in members),
        })
    return groups


def build_bsam_mapping(
    assessment_source,
    *,
    enrichment_source=None,
    created_at_utc=None,
):
    """Build a conservative BSAM coverage map from existing offline evidence."""
    if not isinstance(assessment_source, dict):
        raise ValueError("assessment_source must be an object")
    assessment = assessment_source.get("assessment")
    if not isinstance(assessment, dict):
        raise ValueError("assessment_source must include assessment")
    if assessment.get("schema_version") != "0.9.0":
        raise ValueError("assessment schema version is unsupported")
    if assessment.get("evidence_contract_version") != EVIDENCE_CONTRACT_VERSION:
        raise ValueError("assessment evidence contract version is unsupported")

    assessment_id = _require_nonempty_string(
        assessment_source.get("assessment_id"), "assessment_id"
    )
    if assessment.get("assessment_id") != assessment_id:
        raise ValueError("assessment_source assessment_id does not match assessment")
    assessment_sha256 = _validate_sha256(
        assessment_source.get("sha256"), "assessment sha256"
    )
    assessment_source_id = _require_nonempty_string(
        assessment_source.get("assessment_source_id"), "assessment_source_id"
    )
    if assessment_source_id != f"sha256:{assessment_sha256}":
        raise ValueError("assessment_source_id must match assessment sha256")

    if enrichment_source is not None:
        if not isinstance(enrichment_source, dict):
            raise ValueError("enrichment_source must be an object")
        enrichment_sha256 = _validate_sha256(
            enrichment_source.get("sha256"), "enrichment sha256"
        )
        enrichment_source_id = _require_nonempty_string(
            enrichment_source.get("enrichment_source_id"), "enrichment_source_id"
        )
        if enrichment_source_id != f"sha256:{enrichment_sha256}":
            raise ValueError("enrichment_source_id must match enrichment sha256")
        _validate_enrichment_binding(enrichment_source, assessment_source)

    controls = {
        control_id: _control_template(control_id, group, title)
        for control_id, group, title in BSAM_CONTROLS
    }
    observations = assessment.get("observations")
    if not isinstance(observations, list):
        raise ValueError("assessment.observations must be a list")
    observation_reports = {}
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("assessment observation must be an object")
        observation_id = _require_nonempty_string(
            observation.get("observation_id"), "observation_id"
        )
        report = observation.get("report")
        if not isinstance(report, dict):
            raise ValueError("assessment observation.report must be an object")
        if observation_id in observation_reports:
            raise ValueError(f"Duplicate assessment observation ID: {observation_id}")
        observation_reports[observation_id] = report
    validate_findings(assessment.get("findings", []), observation_reports)

    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("assessment observation must be an object")
        if observation.get("protocol") != "ble":
            continue
        evidence_type = observation.get("evidence_type")
        if evidence_type == "passive_ble":
            _extract_passive_signals(observation, controls)
        elif evidence_type == "active_gatt":
            _extract_active_signals(observation, controls)

    _map_findings(assessment, controls)
    _map_context_claims(enrichment_source, controls, set(observation_reports))

    ordered_controls = [_finalize_control(controls[item[0]]) for item in BSAM_CONTROLS]
    catalog_provenance = assessment.get("catalog_provenance", [])
    if enrichment_source is not None:
        catalog_provenance = enrichment_source["enrichment"].get(
            "catalog_provenance", catalog_provenance
        )
    catalog_provenance = normalize_catalog_provenance(catalog_provenance)

    summary = {
        "control_count": len(ordered_controls),
        "not_assessed_count": sum(item["coverage_state"] == "not_assessed" for item in ordered_controls),
        "evidence_available_count": sum(item["coverage_state"] == "evidence_available" for item in ordered_controls),
        "candidate_concern_count": sum(item["review_state"] == "candidate_concern" for item in ordered_controls),
        "confirmed_finding_count": sum(item["review_state"] == "confirmed_finding" for item in ordered_controls),
        "full_bsam_coverage_claimed": False,
        "pass_fail_determinations_made": False,
    }

    result = {
        "schema_version": BSAM_MAPPING_SCHEMA_VERSION,
        "record_type": "bsam_assessment_mapping",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "created_at_utc": created_at_utc or utc_now(),
        "profile": {
            "framework": "BSAM",
            "publisher": "Tarlogic Security",
            "profile_version": BSAM_PROFILE_VERSION,
            "control_catalog_sha256": _profile_sha256(),
            "control_count": len(BSAM_CONTROLS),
            "source_locator": BSAM_SOURCE_URL,
            "source_license": "CC BY 4.0",
            "source_reviewed_date": "2026-09-25",
            "upstream_revision_pinned": False,
            "scope": "coverage_mapping_not_compliance",
        },
        "assessment_source": {
            "assessment_source_id": assessment_source_id,
            "assessment_id": assessment_id,
            "path": _require_nonempty_string(assessment_source.get("path"), "assessment path"),
            "sha256": assessment_sha256,
        },
        "catalog_provenance": catalog_provenance,
        "controls": ordered_controls,
        "group_summary": _group_summary(ordered_controls),
        "summary": summary,
        "execution": {
            "status": "offline_mapping",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [
            "This artifact is a K'amal evidence-to-BSAM coverage map, not a BSAM certification or compliance result.",
            "No pass, fail, or no-issue-observed conclusion is inferred from missing findings or missing evidence.",
            "BSAM is maintained externally and may evolve; this artifact identifies K'amal's embedded control profile by version and SHA-256 rather than claiming an upstream revision pin.",
            "Mapped evidence and intelligence context remain subject to the limitations of their source artifacts.",
        ],
    }
    if enrichment_source is not None:
        enrichment_sha = _validate_sha256(
            enrichment_source.get("sha256"), "enrichment sha256"
        )
        result["enrichment_source"] = {
            "enrichment_source_id": _require_nonempty_string(
                enrichment_source.get("enrichment_source_id"), "enrichment_source_id"
            ),
            "path": _require_nonempty_string(enrichment_source.get("path"), "enrichment path"),
            "sha256": enrichment_sha,
        }
    return result


__all__ = [
    "BSAM_CONTROLS",
    "BSAM_MAPPING_SCHEMA_VERSION",
    "BSAM_PROFILE_VERSION",
    "build_bsam_mapping",
    "load_assessment_source",
    "load_bsam_enrichment_source",
]

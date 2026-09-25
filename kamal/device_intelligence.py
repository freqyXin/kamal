"""Offline BLE device-context enrichment for K'amal assessments.

This module consumes already-collected assessment evidence plus a local,
provenance-bearing intelligence catalog. It performs no RF operations and never
promotes manufacturer, name, GATT, or payload hints into stable device identity.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import defaultdict
from copy import deepcopy
from pathlib import Path

from kamal.ble_correlation import load_assessment_source
from kamal.evidence_contracts import EVIDENCE_CONTRACT_VERSION
from kamal.catalog_provenance import (
    build_device_catalog_provenance,
    has_bluetooth_provenance,
    merge_catalog_provenance,
    sources_require_bluetooth_snapshot,
)


INTELLIGENCE_SCHEMA_VERSION = "0.12.0"
SUPPORTED_ASSESSMENT_SCHEMA_VERSION = "0.9.0"
_ALLOWED_STATES = {"documented", "inferred", "validated"}
_ALLOWED_CONFIDENCE = {"low", "medium", "high"}
_ALLOWED_MATCH_KINDS = {
    "bluetooth_company_id",
    "advertised_name_exact",
    "manufacturer_data_prefix",
    "gatt_uuid",
}
_ALLOWED_GATT_ATTRIBUTE_TYPES = {
    "advertised_service",
    "service",
    "characteristic",
    "descriptor",
}
_ALLOWED_CLAIM_CATEGORIES = {
    "manufacturer",
    "device_family",
    "product_model",
    "chipset",
    "device_function",
    "gatt_service_purpose",
    "gatt_characteristic_purpose",
    "gatt_descriptor_purpose",
    "security_context",
}
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_BLUETOOTH_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def _require_nonempty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _validate_sha256(value, field="sha256"):
    text = _require_nonempty_string(value, field).lower()
    if len(text) != 64 or _HEX.fullmatch(text) is None:
        raise ValueError(f"{field} must contain 64 hexadecimal characters")
    return text


def _normalize_company_id(value):
    if isinstance(value, bool):
        raise ValueError("Bluetooth company identifier must be an integer from 0 to 65535")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip().lower()
        try:
            number = int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError as exc:
            raise ValueError(
                "Bluetooth company identifier must be an integer from 0 to 65535"
            ) from exc
    else:
        raise ValueError("Bluetooth company identifier must be an integer from 0 to 65535")
    if not 0 <= number <= 0xFFFF:
        raise ValueError("Bluetooth company identifier must be an integer from 0 to 65535")
    return number


def _normalize_hex(value, field, *, allow_empty=False):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be hexadecimal text")
    text = "".join(value.strip().split()).replace(":", "").replace("-", "")
    if not text:
        if allow_empty:
            return ""
        raise ValueError(f"{field} must be non-empty hexadecimal text")
    if len(text) % 2 or _HEX.fullmatch(text) is None:
        raise ValueError(f"{field} must contain complete hexadecimal bytes")
    return text.lower()


def _normalize_uuid(value):
    text = _require_nonempty_string(value, "UUID").lower()
    if text.startswith("0x"):
        text = text[2:]
    compact = text.replace("-", "")
    if len(compact) == 4 and _HEX.fullmatch(compact):
        return f"0000{compact}{_BLUETOOTH_BASE_SUFFIX}"
    if len(compact) == 8 and _HEX.fullmatch(compact):
        return f"{compact}{_BLUETOOTH_BASE_SUFFIX}"
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid UUID: {value}") from exc


def _normalize_source(source, *, record_id):
    if not isinstance(source, dict):
        raise ValueError(f"catalog record {record_id}: source must be an object")
    return {
        "source_type": _require_nonempty_string(
            source.get("source_type"), f"catalog record {record_id} source.source_type"
        ),
        "title": _require_nonempty_string(
            source.get("title"), f"catalog record {record_id} source.title"
        ),
        "locator": _require_nonempty_string(
            source.get("locator"), f"catalog record {record_id} source.locator"
        ),
    }


def _normalize_match(match, *, record_id):
    if not isinstance(match, dict):
        raise ValueError(f"catalog record {record_id}: match must be an object")
    kind = _require_nonempty_string(
        match.get("kind"), f"catalog record {record_id} match.kind"
    )
    if kind not in _ALLOWED_MATCH_KINDS:
        raise ValueError(f"catalog record {record_id}: unsupported match kind: {kind}")

    if kind == "bluetooth_company_id":
        return {"kind": kind, "company_id": _normalize_company_id(match.get("company_id"))}

    if kind == "advertised_name_exact":
        return {
            "kind": kind,
            "name": _require_nonempty_string(
                match.get("name"), f"catalog record {record_id} match.name"
            ),
        }

    if kind == "manufacturer_data_prefix":
        return {
            "kind": kind,
            "company_id": _normalize_company_id(match.get("company_id")),
            "payload_prefix_hex": _normalize_hex(
                match.get("payload_prefix_hex"),
                f"catalog record {record_id} match.payload_prefix_hex",
            ),
        }

    attribute_type = _require_nonempty_string(
        match.get("attribute_type"),
        f"catalog record {record_id} match.attribute_type",
    )
    if attribute_type not in _ALLOWED_GATT_ATTRIBUTE_TYPES:
        raise ValueError(
            f"catalog record {record_id}: unsupported GATT attribute type: {attribute_type}"
        )
    return {
        "kind": kind,
        "attribute_type": attribute_type,
        "uuid": _normalize_uuid(match.get("uuid")),
    }


def _normalize_claim(claim, *, record_id):
    if not isinstance(claim, dict):
        raise ValueError(f"catalog record {record_id}: claim must be an object")
    category = _require_nonempty_string(
        claim.get("category"), f"catalog record {record_id} claim.category"
    )
    if category not in _ALLOWED_CLAIM_CATEGORIES:
        raise ValueError(f"catalog record {record_id}: unsupported claim category: {category}")
    value = _require_nonempty_string(
        claim.get("value"), f"catalog record {record_id} claim.value"
    )
    return {"category": category, "value": value}


def _normalize_catalog_record(record):
    if not isinstance(record, dict):
        raise ValueError("catalog record must be an object")
    record_id = _require_nonempty_string(record.get("record_id"), "record_id")
    state = _require_nonempty_string(record.get("state"), f"catalog record {record_id} state")
    if state not in _ALLOWED_STATES:
        raise ValueError(f"catalog record {record_id}: unsupported state: {state}")
    confidence = _require_nonempty_string(
        record.get("confidence"), f"catalog record {record_id} confidence"
    )
    if confidence not in _ALLOWED_CONFIDENCE:
        raise ValueError(f"catalog record {record_id}: unsupported confidence: {confidence}")

    normalized = {
        "record_id": record_id,
        "match": _normalize_match(record.get("match"), record_id=record_id),
        "claim": _normalize_claim(record.get("claim"), record_id=record_id),
        "state": state,
        "confidence": confidence,
        "source": _normalize_source(record.get("source"), record_id=record_id),
        "limitations": [],
    }

    limitations = record.get("limitations", [])
    if not isinstance(limitations, list) or any(
        not isinstance(item, str) or not item.strip() for item in limitations
    ):
        raise ValueError(f"catalog record {record_id}: limitations must be a list of strings")
    normalized["limitations"] = [item.strip() for item in limitations]

    if state == "validated":
        validation = record.get("validation")
        if not isinstance(validation, dict):
            raise ValueError(
                f"catalog record {record_id}: validated records require validation metadata"
            )
        normalized["validation"] = {
            "reviewer": _require_nonempty_string(
                validation.get("reviewer"),
                f"catalog record {record_id} validation.reviewer",
            ),
            "validated_at_utc": _require_nonempty_string(
                validation.get("validated_at_utc"),
                f"catalog record {record_id} validation.validated_at_utc",
            ),
            "basis": _require_nonempty_string(
                validation.get("basis"),
                f"catalog record {record_id} validation.basis",
            ),
        }
    elif "validation" in record:
        raise ValueError(
            f"catalog record {record_id}: validation metadata is only valid for state=validated"
        )

    return normalized


def load_intelligence_catalog(path):
    """Load and validate a local intelligence catalog with byte provenance."""
    path = Path(path).resolve()
    raw = path.read_bytes()
    catalog = json.loads(raw)
    if not isinstance(catalog, dict):
        raise ValueError("intelligence catalog must be a JSON object")
    if catalog.get("schema_version") != INTELLIGENCE_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported intelligence catalog schema version: "
            f"{catalog.get('schema_version')!r}; expected {INTELLIGENCE_SCHEMA_VERSION!r}"
        )
    catalog_id = _require_nonempty_string(catalog.get("catalog_id"), "catalog_id")
    records = catalog.get("records")
    if not isinstance(records, list):
        raise ValueError("intelligence catalog records must be a list")

    normalized_records = []
    seen = set()
    for record in records:
        normalized = _normalize_catalog_record(record)
        if normalized["record_id"] in seen:
            raise ValueError(f"Duplicate intelligence record_id: {normalized['record_id']}")
        seen.add(normalized["record_id"])
        normalized_records.append(normalized)
    normalized_records.sort(key=lambda item: item["record_id"])

    digest = hashlib.sha256(raw).hexdigest()
    catalog_revision = catalog.get("catalog_revision")
    if catalog_revision is None:
        catalog_revision = f"sha256:{digest}"
    else:
        catalog_revision = _require_nonempty_string(
            catalog_revision, "catalog_revision"
        )
    return {
        "catalog_source_id": f"sha256:{digest}",
        "path": str(path),
        "sha256": digest,
        "catalog_id": catalog_id,
        "catalog_revision": catalog_revision,
        "schema_version": INTELLIGENCE_SCHEMA_VERSION,
        "records": normalized_records,
    }


def _fact_id(observation_id, kind, path, canonical_value):
    material = f"{observation_id}\0{kind}\0{path}\0{canonical_value}"
    return "observed-fact:sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _observed_fact(observation, *, kind, value, path, metadata=None):
    observation_id = _require_nonempty_string(observation.get("observation_id"), "observation_id")
    source_id = _require_nonempty_string(observation.get("source_id"), "source_id")
    if isinstance(value, int):
        canonical = str(value)
    else:
        canonical = str(value)
    fact = {
        "record_type": "intelligence_fact",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "fact_id": _fact_id(observation_id, kind, path, canonical),
        "state": "observed",
        "confidence": "high",
        "observation_id": observation_id,
        "source_id": source_id,
        "fact_kind": kind,
        "value": value,
        "evidence_path": path,
    }
    if metadata:
        fact["metadata"] = metadata
    return fact


def _extract_passive_facts(observation, report, warnings):
    advertisers = report.get("advertisers", [])
    if not isinstance(advertisers, list):
        raise ValueError("passive_ble report.advertisers must be a list")
    facts = []
    for advertiser_index, advertiser in enumerate(advertisers):
        if not isinstance(advertiser, dict):
            raise ValueError("passive_ble advertiser must be an object")
        base = f"/advertisers/{advertiser_index}"

        names = []
        if isinstance(advertiser.get("name"), str):
            names.append((advertiser["name"], f"{base}/name"))
        if isinstance(advertiser.get("local_name"), str):
            names.append((advertiser["local_name"], f"{base}/local_name"))
        if isinstance(advertiser.get("names"), list):
            for index, name in enumerate(advertiser["names"]):
                if isinstance(name, str):
                    names.append((name, f"{base}/names/{index}"))
        for name, path in names:
            stripped = name.strip()
            if stripped:
                facts.append(_observed_fact(
                    observation,
                    kind="advertised_name",
                    value=stripped,
                    path=path,
                ))

        manufacturer_data = advertiser.get("manufacturer_data", [])
        if manufacturer_data is None:
            manufacturer_data = []
        if not isinstance(manufacturer_data, list):
            raise ValueError("passive_ble advertiser.manufacturer_data must be a list")
        for index, entry in enumerate(manufacturer_data):
            if not isinstance(entry, dict):
                raise ValueError("manufacturer_data entry must be an object")
            entry_base = f"{base}/manufacturer_data/{index}"
            try:
                company_id = _normalize_company_id(entry.get("company_id"))
            except ValueError:
                warnings.append({
                    "code": "invalid_company_identifier",
                    "observation_id": observation.get("observation_id"),
                    "path": f"{entry_base}/company_id",
                })
                continue
            facts.append(_observed_fact(
                observation,
                kind="bluetooth_company_id",
                value=company_id,
                path=f"{entry_base}/company_id",
            ))
            payload = entry.get("payload_hex")
            if payload is not None:
                try:
                    payload_hex = _normalize_hex(
                        payload, f"{entry_base}/payload_hex", allow_empty=True
                    )
                except ValueError:
                    warnings.append({
                        "code": "invalid_manufacturer_payload",
                        "observation_id": observation.get("observation_id"),
                        "path": f"{entry_base}/payload_hex",
                    })
                    continue
                facts.append(_observed_fact(
                    observation,
                    kind="manufacturer_data",
                    value=payload_hex,
                    path=f"{entry_base}/payload_hex",
                    metadata={"company_id": company_id},
                ))

        for field in ("service_uuids", "service_uuids_16", "service_uuids_32", "service_uuids_128"):
            values = advertiser.get(field, [])
            if values is None:
                continue
            if not isinstance(values, list):
                raise ValueError(f"passive_ble advertiser.{field} must be a list")
            for index, raw_uuid in enumerate(values):
                try:
                    normalized_uuid = _normalize_uuid(raw_uuid)
                except ValueError:
                    warnings.append({
                        "code": "invalid_gatt_uuid",
                        "observation_id": observation.get("observation_id"),
                        "path": f"{base}/{field}/{index}",
                    })
                    continue
                facts.append(_observed_fact(
                    observation,
                    kind="gatt_uuid",
                    value=normalized_uuid,
                    path=f"{base}/{field}/{index}",
                    metadata={"attribute_type": "advertised_service"},
                ))
    return facts


def _extract_active_gatt_facts(observation, report, warnings):
    facts = []
    discovery = report.get("discovery")
    if isinstance(discovery, dict):
        for field in ("name", "local_name"):
            if isinstance(discovery.get(field), str) and discovery[field].strip():
                facts.append(_observed_fact(
                    observation,
                    kind="advertised_name",
                    value=discovery[field].strip(),
                    path=f"/discovery/{field}",
                ))

    gatt = report.get("gatt")
    if not isinstance(gatt, dict):
        return facts
    services = gatt.get("services", [])
    if not isinstance(services, list):
        raise ValueError("active_gatt report.gatt.services must be a list")

    def add_uuid(raw_uuid, *, path, attribute_type):
        try:
            normalized_uuid = _normalize_uuid(raw_uuid)
        except ValueError:
            warnings.append({
                "code": "invalid_gatt_uuid",
                "observation_id": observation.get("observation_id"),
                "path": path,
            })
            return
        facts.append(_observed_fact(
            observation,
            kind="gatt_uuid",
            value=normalized_uuid,
            path=path,
            metadata={"attribute_type": attribute_type},
        ))

    for service_index, service in enumerate(services):
        if not isinstance(service, dict):
            raise ValueError("GATT service must be an object")
        service_base = f"/gatt/services/{service_index}"
        if "uuid" in service:
            add_uuid(service["uuid"], path=f"{service_base}/uuid", attribute_type="service")
        characteristics = service.get("characteristics", [])
        if not isinstance(characteristics, list):
            raise ValueError("GATT characteristics must be a list")
        for char_index, characteristic in enumerate(characteristics):
            if not isinstance(characteristic, dict):
                raise ValueError("GATT characteristic must be an object")
            char_base = f"{service_base}/characteristics/{char_index}"
            if "uuid" in characteristic:
                add_uuid(
                    characteristic["uuid"],
                    path=f"{char_base}/uuid",
                    attribute_type="characteristic",
                )
            descriptors = characteristic.get("descriptors", [])
            if not isinstance(descriptors, list):
                raise ValueError("GATT descriptors must be a list")
            for desc_index, descriptor in enumerate(descriptors):
                if not isinstance(descriptor, dict):
                    raise ValueError("GATT descriptor must be an object")
                if "uuid" in descriptor:
                    add_uuid(
                        descriptor["uuid"],
                        path=f"{char_base}/descriptors/{desc_index}/uuid",
                        attribute_type="descriptor",
                    )
    return facts


def extract_observed_intelligence_facts(assessment, *, warnings=None):
    """Extract identity-neutral BLE facts from one assessment."""
    if warnings is None:
        warnings = []
    if not isinstance(assessment, dict):
        raise ValueError("assessment must be an object")
    observations = assessment.get("observations")
    if not isinstance(observations, list):
        raise ValueError("assessment.observations must be a list")

    facts = []
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("assessment observation must be an object")
        if observation.get("protocol") != "ble":
            continue
        report = observation.get("report")
        if not isinstance(report, dict):
            raise ValueError("observation.report must be an object")
        if observation.get("evidence_type") == "passive_ble":
            facts.extend(_extract_passive_facts(observation, report, warnings))
        elif observation.get("evidence_type") == "active_gatt":
            facts.extend(_extract_active_gatt_facts(observation, report, warnings))

    facts.sort(key=lambda item: (
        item["observation_id"],
        item["evidence_path"],
        item["fact_kind"],
        str(item["value"]),
    ))
    return facts


def _record_matches_fact(record, fact):
    match = record["match"]
    kind = match["kind"]
    if kind == "bluetooth_company_id":
        return (
            fact["fact_kind"] == "bluetooth_company_id"
            and fact["value"] == match["company_id"]
        )
    if kind == "advertised_name_exact":
        return fact["fact_kind"] == "advertised_name" and fact["value"] == match["name"]
    if kind == "manufacturer_data_prefix":
        return (
            fact["fact_kind"] == "manufacturer_data"
            and fact.get("metadata", {}).get("company_id") == match["company_id"]
            and fact["value"].startswith(match["payload_prefix_hex"])
        )
    return (
        fact["fact_kind"] == "gatt_uuid"
        and fact["value"] == match["uuid"]
        and fact.get("metadata", {}).get("attribute_type") == match["attribute_type"]
    )


def _claim_id(record_id, fact_id):
    material = f"{record_id}\0{fact_id}"
    return "intelligence-claim:sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _build_claim(record, fact, *, catalog_source_id, catalog_revision):
    claim = {
        "record_type": "intelligence_claim",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "claim_id": _claim_id(record["record_id"], fact["fact_id"]),
        "observation_id": fact["observation_id"],
        "source_id": fact["source_id"],
        "observed_fact_id": fact["fact_id"],
        "catalog_source_id": catalog_source_id,
        "catalog_revision": catalog_revision,
        "catalog_record_id": record["record_id"],
        "category": record["claim"]["category"],
        "value": record["claim"]["value"],
        "state": record["state"],
        "confidence": record["confidence"],
        "source": deepcopy(record["source"]),
        "match": deepcopy(record["match"]),
        "limitations": list(dict.fromkeys([
            *deepcopy(record["limitations"]),
            "Catalog source metadata is provenance supplied by the catalog; "
            "K'amal did not independently fetch or verify that source during enrichment.",
            "Enrichment context does not establish stable physical device identity.",
        ])),
        "identity_assertion": False,
        "stable_identity": False,
    }
    if "validation" in record:
        claim["validation"] = deepcopy(record["validation"])
    return claim


def _conflict_warnings(claims):
    grouped = defaultdict(set)
    for claim in claims:
        grouped[(claim["observation_id"], claim["category"])].add(claim["value"])
    warnings = []
    for (observation_id, category), values in sorted(grouped.items()):
        if len(values) > 1:
            warnings.append({
                "code": "conflicting_intelligence_claims",
                "observation_id": observation_id,
                "category": category,
                "values": sorted(values),
            })
    return warnings


def build_ble_intelligence_enrichment(
    assessment_source,
    catalog_source,
    *,
    catalog_provenance=None,
):
    """Enrich an assessment from a local catalog without asserting identity."""
    if not isinstance(assessment_source, dict):
        raise ValueError("assessment_source must be an object")
    if not isinstance(catalog_source, dict):
        raise ValueError("catalog_source must be an object")

    assessment = assessment_source.get("assessment")
    if not isinstance(assessment, dict):
        raise ValueError("assessment_source must include assessment")
    if assessment.get("schema_version") != SUPPORTED_ASSESSMENT_SCHEMA_VERSION:
        raise ValueError("assessment schema version is unsupported")
    if assessment.get("evidence_contract_version") != EVIDENCE_CONTRACT_VERSION:
        raise ValueError("assessment evidence contract version is unsupported")
    if catalog_source.get("schema_version") != INTELLIGENCE_SCHEMA_VERSION:
        raise ValueError("catalog source schema version is unsupported")

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

    records = catalog_source.get("records")
    if not isinstance(records, list):
        raise ValueError("catalog_source records must be a list")
    normalized_records = []
    seen_record_ids = set()
    for record in records:
        normalized = _normalize_catalog_record(record)
        if normalized["record_id"] in seen_record_ids:
            raise ValueError(f"Duplicate intelligence record_id: {normalized['record_id']}")
        seen_record_ids.add(normalized["record_id"])
        normalized_records.append(normalized)
    normalized_records.sort(key=lambda item: item["record_id"])

    catalog_sha256 = _validate_sha256(
        catalog_source.get("sha256"), "catalog sha256"
    )
    catalog_source_id = _require_nonempty_string(
        catalog_source.get("catalog_source_id"), "catalog_source_id"
    )
    if catalog_source_id != f"sha256:{catalog_sha256}":
        raise ValueError("catalog_source_id must match catalog sha256")
    catalog_revision = catalog_source.get("catalog_revision") or f"sha256:{catalog_sha256}"
    catalog_revision = _require_nonempty_string(catalog_revision, "catalog_revision")

    device_catalog_provenance = build_device_catalog_provenance(
        {**catalog_source, "catalog_revision": catalog_revision},
        usage="consulted",
    )
    merged_catalog_provenance = merge_catalog_provenance(
        assessment.get("catalog_provenance", []),
        [] if catalog_provenance is None else catalog_provenance,
        [device_catalog_provenance],
    )
    if (
        sources_require_bluetooth_snapshot(assessment.get("observations", []))
        and not has_bluetooth_provenance(merged_catalog_provenance)
    ):
        raise ValueError(
            "catalog-resolved BLE evidence requires pinned Bluetooth catalog provenance"
        )

    warnings = []
    facts = extract_observed_intelligence_facts(assessment, warnings=warnings)
    claims = []
    for fact in facts:
        for record in normalized_records:
            if _record_matches_fact(record, fact):
                claims.append(_build_claim(
                    record,
                    fact,
                    catalog_source_id=catalog_source_id,
                    catalog_revision=catalog_revision,
                ))
    claims.sort(key=lambda item: (
        item["observation_id"],
        item["category"],
        item["value"],
        item["catalog_record_id"],
        item["observed_fact_id"],
    ))
    warnings.extend(_conflict_warnings(claims))
    warnings.sort(key=lambda item: (
        item.get("observation_id", ""),
        item["code"],
        item.get("category", ""),
        item.get("path", ""),
    ))

    return {
        "schema_version": INTELLIGENCE_SCHEMA_VERSION,
        "record_type": "ble_device_intelligence_enrichment",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "assessment_source": {
            "assessment_source_id": assessment_source_id,
            "assessment_id": assessment_id,
            "path": _require_nonempty_string(assessment_source.get("path"), "assessment path"),
            "sha256": assessment_sha256,
        },
        "catalog_source": {
            "catalog_source_id": catalog_source_id,
            "catalog_id": _require_nonempty_string(catalog_source.get("catalog_id"), "catalog_id"),
            "catalog_revision": catalog_revision,
            "path": _require_nonempty_string(catalog_source.get("path"), "catalog path"),
            "sha256": catalog_sha256,
        },
        "catalog_provenance": merged_catalog_provenance,
        "observed_facts": facts,
        "claims": claims,
        "integrity": {
            "observed_fact_count": len(facts),
            "claim_count": len(claims),
            "warning_count": len(warnings),
            "warnings": warnings,
        },
    }


__all__ = [
    "INTELLIGENCE_SCHEMA_VERSION",
    "build_ble_intelligence_enrichment",
    "extract_observed_intelligence_facts",
    "load_assessment_source",
    "load_intelligence_catalog",
]

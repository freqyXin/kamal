"""Deterministic offline BLE correlation across K'amal assessments.

Correlation in this module never performs RF operations and never promotes a
Bluetooth address to a stable asset identity. Exact address equality is emitted
only as an evidence-backed identity candidate for analyst review.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from kamal.evidence_contracts import EVIDENCE_CONTRACT_VERSION


CORRELATION_SCHEMA_VERSION = "0.12.0"
SUPPORTED_ASSESSMENT_SCHEMA_VERSION = "0.9.0"
_BLE_ADDRESS = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
_RANDOM_ADDRESS_TYPES = {
    "random",
    "random-resolvable",
    "random-non-resolvable",
    "random-static",
    "resolvable-private",
    "non-resolvable-private",
    "private",
}
_PUBLIC_ADDRESS_TYPES = {"public", "public-identity"}


def _require_nonempty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_sha256(value):
    value = _require_nonempty_string(value, "sha256")
    if len(value) != 64:
        raise ValueError("sha256 must contain 64 hexadecimal characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError("sha256 must contain 64 hexadecimal characters") from exc
    return value.lower()


def normalize_ble_address(value):
    """Return canonical uppercase BLE address text or raise ValueError."""
    value = _require_nonempty_string(value, "BLE address")
    if _BLE_ADDRESS.fullmatch(value) is None:
        raise ValueError(f"Invalid BLE address: {value}")
    return value.upper()


def load_assessment_source(path):
    """Load one assessment while retaining original-byte provenance."""
    path = Path(path).resolve()
    raw = path.read_bytes()
    assessment = json.loads(raw)

    if not isinstance(assessment, dict):
        raise ValueError(f"Assessment must be a JSON object: {path}")

    assessment_id = _require_nonempty_string(
        assessment.get("assessment_id"),
        "assessment_id",
    )
    schema_version = assessment.get("schema_version")
    if schema_version != SUPPORTED_ASSESSMENT_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported assessment schema version: "
            f"{schema_version!r}; expected {SUPPORTED_ASSESSMENT_SCHEMA_VERSION!r}"
        )
    contract_version = assessment.get("evidence_contract_version")
    if contract_version != EVIDENCE_CONTRACT_VERSION:
        raise ValueError(
            "Unsupported evidence contract version: "
            f"{contract_version!r}; expected {EVIDENCE_CONTRACT_VERSION!r}"
        )

    observations = assessment.get("observations")
    if not isinstance(observations, list):
        raise ValueError("assessment.observations must be a list")

    digest = hashlib.sha256(raw).hexdigest()
    return {
        "assessment_source_id": f"sha256:{digest}",
        "path": str(path),
        "sha256": digest,
        "assessment_id": assessment_id,
        "assessment": assessment,
    }


def _normalize_address_type(value):
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower().replace("_", "-")


def _claim(
    *,
    assessment_source_id,
    assessment_id,
    observation,
    address,
    address_type,
    evidence_paths,
):
    return {
        "assessment_source_id": assessment_source_id,
        "assessment_id": assessment_id,
        "observation_id": _require_nonempty_string(
            observation.get("observation_id"),
            "observation_id",
        ),
        "source_id": _require_nonempty_string(
            observation.get("source_id"),
            "source_id",
        ),
        "identifier_type": "ble_address",
        "identifier": address,
        "address_type": _normalize_address_type(address_type),
        "evidence_paths": sorted(set(evidence_paths)),
    }


def _extract_observation_claims(source, warnings):
    assessment = source["assessment"]
    assessment_id = source["assessment_id"]
    assessment_source_id = source["assessment_source_id"]
    claims = []

    for observation in assessment["observations"]:
        if not isinstance(observation, dict):
            raise ValueError("assessment observation must be an object")
        if observation.get("protocol") != "ble":
            continue

        report = observation.get("report")
        if not isinstance(report, dict):
            raise ValueError("observation.report must be an object")

        evidence_type = observation.get("evidence_type")
        raw_claims = []

        if evidence_type == "passive_ble":
            advertisers = report.get("advertisers", [])
            if not isinstance(advertisers, list):
                raise ValueError("passive_ble report.advertisers must be a list")
            for index, advertiser in enumerate(advertisers):
                if not isinstance(advertiser, dict):
                    raise ValueError("passive_ble advertiser must be an object")
                if "address" not in advertiser:
                    continue
                raw_claims.append((
                    advertiser.get("address"),
                    advertiser.get("address_type"),
                    f"/advertisers/{index}/address",
                ))

        elif evidence_type == "active_gatt":
            if isinstance(report.get("target"), str):
                raw_claims.append((report["target"], None, "/target"))
            discovery = report.get("discovery")
            if isinstance(discovery, dict) and isinstance(discovery.get("address"), str):
                raw_claims.append((discovery["address"], None, "/discovery/address"))
        else:
            continue

        merged = {}
        for raw_address, address_type, path in raw_claims:
            try:
                address = normalize_ble_address(raw_address)
            except ValueError:
                warnings.append({
                    "code": "invalid_ble_address",
                    "assessment_id": assessment_id,
                    "observation_id": observation.get("observation_id"),
                    "path": path,
                })
                continue

            entry = merged.setdefault(address, {
                "address_types": set(),
                "paths": set(),
            })
            normalized_type = _normalize_address_type(address_type)
            if normalized_type is not None:
                entry["address_types"].add(normalized_type)
            entry["paths"].add(path)

        for address, entry in sorted(merged.items()):
            address_types = sorted(entry["address_types"])
            if len(address_types) == 1:
                address_type = address_types[0]
            elif address_types:
                address_type = "conflicting"
            else:
                address_type = None
            claims.append(_claim(
                assessment_source_id=assessment_source_id,
                assessment_id=assessment_id,
                observation=observation,
                address=address,
                address_type=address_type,
                evidence_paths=entry["paths"],
            ))

    return claims


def _identity_confidence(claims):
    types = {claim["address_type"] for claim in claims if claim["address_type"]}
    if "conflicting" in types or types.intersection(_RANDOM_ADDRESS_TYPES):
        return "low", [
            "At least one observation marks the address as random/private or "
            "reports conflicting address types; address continuity is not stable identity."
        ]
    if types and types.issubset(_PUBLIC_ADDRESS_TYPES):
        return "medium", [
            "An exact public-address match supports identifier continuity, but BLE "
            "addresses can be spoofed or cloned and are not stable asset identity by default."
        ]
    return "low", [
        "Address type is missing or not sufficient to establish stable identity; exact "
        "BLE address equality alone does not prove the same physical asset."
    ]


def _candidate_id(address):
    digest = hashlib.sha256(f"ble-address\0{address}".encode("utf-8")).hexdigest()
    return f"asset-identity-candidate:sha256:{digest}"


def build_ble_cross_run_correlation(sources):
    """Build deterministic cross-run BLE identity candidates.

    ``sources`` must contain records returned by ``load_assessment_source``.
    Candidates are produced only when the same normalized BLE address is present
    in at least two distinct assessments. No candidate is a confirmed asset link.
    """
    if not isinstance(sources, list) or len(sources) < 2:
        raise ValueError("At least two assessment sources are required")

    seen_assessments = set()
    source_records = []
    warnings = []
    claims = []

    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("assessment source must be an object")
        assessment_id = _require_nonempty_string(
            source.get("assessment_id"),
            "assessment_id",
        )
        if assessment_id in seen_assessments:
            raise ValueError(f"Duplicate assessment_id: {assessment_id}")
        seen_assessments.add(assessment_id)

        source_id = _require_nonempty_string(
            source.get("assessment_source_id"),
            "assessment_source_id",
        )
        sha256 = _validate_sha256(source.get("sha256"))
        if source_id != f"sha256:{sha256}":
            raise ValueError("assessment_source_id must match sha256")
        assessment = source.get("assessment")
        if not isinstance(assessment, dict):
            raise ValueError("assessment source must include an assessment object")
        if assessment.get("assessment_id") != assessment_id:
            raise ValueError("assessment source assessment_id does not match assessment")
        if assessment.get("schema_version") != SUPPORTED_ASSESSMENT_SCHEMA_VERSION:
            raise ValueError(
                "Unsupported assessment schema version: "
                f"{assessment.get('schema_version')!r}"
            )
        if assessment.get("evidence_contract_version") != EVIDENCE_CONTRACT_VERSION:
            raise ValueError(
                "Unsupported evidence contract version: "
                f"{assessment.get('evidence_contract_version')!r}"
            )
        if not isinstance(assessment.get("observations"), list):
            raise ValueError("assessment.observations must be a list")

        source_records.append({
            "assessment_source_id": source_id,
            "assessment_id": assessment_id,
            "path": _require_nonempty_string(source.get("path"), "path"),
            "sha256": sha256,
        })
        claims.extend(_extract_observation_claims(source, warnings))

    grouped = defaultdict(list)
    for claim in claims:
        grouped[claim["identifier"]].append(claim)

    candidates = []
    for address, address_claims in sorted(grouped.items()):
        assessment_ids = {claim["assessment_id"] for claim in address_claims}
        if len(assessment_ids) < 2:
            continue

        confidence, limitations = _identity_confidence(address_claims)
        evidence = sorted(
            address_claims,
            key=lambda item: (
                item["assessment_id"],
                item["observation_id"],
                item["source_id"],
            ),
        )
        candidates.append({
            "record_type": "asset_identity_link_candidate",
            "contract_version": EVIDENCE_CONTRACT_VERSION,
            "candidate_id": _candidate_id(address),
            "protocol": "ble",
            "identifier_type": "ble_address",
            "identifier": address,
            "match_method": "exact_identifier_match",
            "match_confidence": "high",
            "asset_identity_confidence": confidence,
            "status": "needs_review",
            "stable_identity": False,
            "evidence": evidence,
            "limitations": limitations,
        })

    source_records.sort(key=lambda item: item["assessment_id"])
    warnings.sort(key=lambda item: (
        item["assessment_id"],
        str(item.get("observation_id")),
        item["path"],
    ))

    return {
        "schema_version": CORRELATION_SCHEMA_VERSION,
        "record_type": "ble_cross_run_correlation",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "assessment_sources": source_records,
        "identity_candidates": candidates,
        "integrity": {
            "assessment_count": len(source_records),
            "identity_candidate_count": len(candidates),
            "warning_count": len(warnings),
            "warnings": warnings,
        },
    }

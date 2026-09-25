"""Immutable catalog provenance and pinning for K'amal artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path

from kamal.evidence_contracts import EVIDENCE_CONTRACT_VERSION
from kamal.identifiers import resolve_gatt_uuid


CATALOG_PROVENANCE_SCHEMA_VERSION = "0.12.0"
BLUETOOTH_CATALOG_TYPE = "bluetooth_sig_assigned_numbers"
DEVICE_CATALOG_TYPE = "ble_device_intelligence"
BLUETOOTH_CATALOG_ID = "bluetooth-sig-assigned-numbers"
_ALLOWED_USAGE = {"available", "consulted"}
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_REQUIRED_BLUETOOTH_REGISTRIES = (
    "characteristic_uuids",
    "company_identifiers",
    "descriptor_uuids",
    "member_uuids",
    "service_uuids",
)
_PASSIVE_REGISTRIES = (
    "company_identifiers",
    "service_uuids",
    "member_uuids",
)
_GATT_REGISTRY_BY_NAMESPACE = {
    "service": "service_uuids",
    "characteristic": "characteristic_uuids",
    "descriptor": "descriptor_uuids",
}


def _require_nonempty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _validate_sha256(value, field):
    text = _require_nonempty_string(value, field).lower()
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{field} must contain 64 hexadecimal characters")
    return text


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _read_json_bytes(path, field):
    raw = Path(path).read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a JSON object")
    return raw, value


def _normalize_bluetooth_record(record):
    revision = _require_nonempty_string(record.get("revision"), "catalog revision").lower()
    if _COMMIT_RE.fullmatch(revision) is None:
        raise ValueError("Bluetooth catalog revision must be a full 40-character commit")
    usage = _require_nonempty_string(record.get("usage"), "catalog usage")
    if usage not in _ALLOWED_USAGE:
        raise ValueError(f"unsupported catalog usage: {usage}")
    registries = record.get("registries")
    if not isinstance(registries, dict) or set(registries) != set(_REQUIRED_BLUETOOTH_REGISTRIES):
        raise ValueError("Bluetooth catalog provenance registry set is incomplete")

    normalized_registries = {}
    for name in _REQUIRED_BLUETOOTH_REGISTRIES:
        entry = registries[name]
        if not isinstance(entry, dict):
            raise ValueError(f"Bluetooth registry provenance must be an object: {name}")
        filename = _require_nonempty_string(entry.get("filename"), f"{name} filename")
        if filename != f"{name}.json":
            raise ValueError(f"unexpected Bluetooth registry filename: {filename}")
        normalized_registries[name] = {
            "filename": filename,
            "normalized_sha256": _validate_sha256(
                entry.get("normalized_sha256"), f"{name} normalized_sha256"
            ),
            "source_file": _require_nonempty_string(
                entry.get("source_file"), f"{name} source_file"
            ),
            "source_sha256": _validate_sha256(
                entry.get("source_sha256"), f"{name} source_sha256"
            ),
        }

    normalized = {
        "record_type": "catalog_provenance",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "schema_version": CATALOG_PROVENANCE_SCHEMA_VERSION,
        "catalog_type": BLUETOOTH_CATALOG_TYPE,
        "catalog_id": BLUETOOTH_CATALOG_ID,
        "revision": revision,
        "usage": usage,
        "path": _require_nonempty_string(record.get("path"), "catalog path"),
        "manifest_sha256": _validate_sha256(
            record.get("manifest_sha256"), "Bluetooth manifest_sha256"
        ),
        "registries": normalized_registries,
    }
    for field in ("source_repository", "importer_version"):
        if field in record:
            normalized[field] = _require_nonempty_string(record[field], field)
    if "binding" in record:
        binding = record["binding"]
        if not isinstance(binding, dict):
            raise ValueError("catalog binding must be an object")
        normalized["binding"] = deepcopy(binding)
    return normalized


def _normalize_device_record(record):
    usage = _require_nonempty_string(record.get("usage"), "catalog usage")
    if usage not in _ALLOWED_USAGE:
        raise ValueError(f"unsupported catalog usage: {usage}")
    sha256 = _validate_sha256(record.get("sha256"), "device catalog sha256")
    revision = _require_nonempty_string(record.get("revision"), "catalog revision")
    normalized = {
        "record_type": "catalog_provenance",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "schema_version": CATALOG_PROVENANCE_SCHEMA_VERSION,
        "catalog_type": DEVICE_CATALOG_TYPE,
        "catalog_id": _require_nonempty_string(record.get("catalog_id"), "catalog_id"),
        "revision": revision,
        "usage": usage,
        "path": _require_nonempty_string(record.get("path"), "catalog path"),
        "sha256": sha256,
    }
    if revision.startswith("sha256:") and revision != f"sha256:{sha256}":
        raise ValueError("device catalog revision does not match catalog sha256")
    return normalized


def normalize_catalog_provenance_record(record):
    if not isinstance(record, dict):
        raise ValueError("catalog provenance record must be an object")
    catalog_type = _require_nonempty_string(record.get("catalog_type"), "catalog_type")
    if catalog_type == BLUETOOTH_CATALOG_TYPE:
        return _normalize_bluetooth_record(record)
    if catalog_type == DEVICE_CATALOG_TYPE:
        return _normalize_device_record(record)
    raise ValueError(f"unsupported catalog provenance type: {catalog_type}")


def normalize_catalog_provenance(records):
    if records is None:
        return []
    if not isinstance(records, list):
        raise ValueError("catalog_provenance must be a list")
    normalized = [normalize_catalog_provenance_record(item) for item in records]
    normalized.sort(key=lambda item: (item["catalog_type"], item["catalog_id"], item["revision"]))
    seen = set()
    for item in normalized:
        key = (item["catalog_type"], item["catalog_id"])
        if key in seen:
            raise ValueError(f"duplicate catalog provenance record: {key[0]}:{key[1]}")
        seen.add(key)
    return normalized


def _immutable_identity(record):
    if record["catalog_type"] == BLUETOOTH_CATALOG_TYPE:
        return {
            "revision": record["revision"],
            "manifest_sha256": record["manifest_sha256"],
            "registries": record["registries"],
        }
    return {
        "revision": record["revision"],
        "sha256": record["sha256"],
    }


def merge_catalog_provenance(*collections):
    merged = {}
    for collection in collections:
        if collection is None:
            continue
        if not isinstance(collection, list):
            raise ValueError("catalog provenance collection must be a list")
        for raw in collection:
            item = normalize_catalog_provenance_record(raw)
            key = (item["catalog_type"], item["catalog_id"])
            current = merged.get(key)
            if current is None:
                merged[key] = item
                continue
            if _immutable_identity(current) != _immutable_identity(item):
                raise ValueError(
                    "catalog provenance revision/hash mismatch for "
                    f"{item['catalog_type']}:{item['catalog_id']}"
                )
            if item["usage"] == "consulted":
                current["usage"] = "consulted"
            current["path"] = min(current["path"], item["path"])
            if "binding" in item:
                current["binding"] = deepcopy(item["binding"])
    result = list(merged.values())
    result.sort(key=lambda item: (item["catalog_type"], item["catalog_id"], item["revision"]))
    return result


def load_bluetooth_snapshot(path):
    """Verify an immutable Bluetooth SIG snapshot and return provenance plus data."""
    snapshot_dir = Path(path).resolve()
    manifest_path = snapshot_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"Bluetooth snapshot is missing manifest: {snapshot_dir}")
    manifest_raw, manifest = _read_json_bytes(manifest_path, "Bluetooth snapshot manifest")
    if manifest.get("schema_version") != "1.0.0":
        raise ValueError("Bluetooth snapshot manifest has an unsupported schema")
    revision = _require_nonempty_string(manifest.get("source_commit"), "source_commit").lower()
    if _COMMIT_RE.fullmatch(revision) is None:
        raise ValueError("Bluetooth snapshot source_commit must be a full commit hash")
    registries = manifest.get("registries")
    if not isinstance(registries, dict) or set(registries) != set(_REQUIRED_BLUETOOTH_REGISTRIES):
        raise ValueError("Bluetooth snapshot manifest registry set is incomplete")

    provenance_registries = {}
    loaded_registries = {}
    for name in _REQUIRED_BLUETOOTH_REGISTRIES:
        entry = registries[name]
        if not isinstance(entry, dict):
            raise ValueError(f"Bluetooth snapshot manifest entry is invalid: {name}")
        filename = _require_nonempty_string(entry.get("filename"), f"{name} filename")
        if filename != f"{name}.json":
            raise ValueError(f"Bluetooth snapshot filename mismatch: {name}")
        normalized_sha256 = _validate_sha256(
            entry.get("normalized_sha256"), f"{name} normalized_sha256"
        )
        source_sha256 = _validate_sha256(entry.get("source_sha256"), f"{name} source_sha256")
        source_file = _require_nonempty_string(entry.get("source_file"), f"{name} source_file")
        registry_path = snapshot_dir / filename
        if not registry_path.is_file():
            raise ValueError(f"Bluetooth snapshot is missing registry: {filename}")
        raw, registry = _read_json_bytes(registry_path, f"Bluetooth registry {name}")
        if _sha256_bytes(raw) != normalized_sha256:
            raise ValueError(f"Bluetooth snapshot normalized hash mismatch: {name}")
        if registry.get("source_commit") != revision:
            raise ValueError(f"Bluetooth registry revision mismatch: {name}")
        if registry.get("source_file") != source_file:
            raise ValueError(f"Bluetooth registry source file mismatch: {name}")
        if registry.get("source_sha256") != source_sha256:
            raise ValueError(f"Bluetooth registry source hash mismatch: {name}")
        if not isinstance(registry.get("identifiers"), dict):
            raise ValueError(f"Bluetooth registry identifiers are invalid: {name}")
        loaded_registries[name] = registry
        provenance_registries[name] = {
            "filename": filename,
            "normalized_sha256": normalized_sha256,
            "source_file": source_file,
            "source_sha256": source_sha256,
        }

    provenance = normalize_catalog_provenance_record({
        "catalog_type": BLUETOOTH_CATALOG_TYPE,
        "catalog_id": BLUETOOTH_CATALOG_ID,
        "revision": revision,
        "usage": "available",
        "path": str(snapshot_dir),
        "manifest_sha256": _sha256_bytes(manifest_raw),
        "registries": provenance_registries,
        "source_repository": manifest.get("source_repository", "unknown"),
        "importer_version": manifest.get("importer_version", "unknown"),
    })
    return {
        "provenance": provenance,
        "manifest": manifest,
        "registries": loaded_registries,
    }


def _validate_passive_binding(report, snapshot_source):
    metadata = report.get("identifier_registries")
    if not isinstance(metadata, dict):
        raise ValueError("passive report catalog provenance is incomplete")
    revision = snapshot_source["provenance"]["revision"]
    for name in _PASSIVE_REGISTRIES:
        embedded = metadata.get(name)
        if not isinstance(embedded, dict):
            raise ValueError(f"passive report catalog provenance is incomplete: {name}")
        registry = snapshot_source["registries"][name]
        expected = {
            "source": registry.get("source"),
            "source_commit": revision,
            "source_file": registry.get("source_file"),
            "generated_at_utc": registry.get("generated_at_utc"),
        }
        for field, value in expected.items():
            if not isinstance(embedded.get(field), str) or embedded.get(field) != value:
                raise ValueError(
                    "passive report catalog provenance does not match pinned snapshot: "
                    f"{name}.{field}"
                )


def _iter_gatt_resolutions(report):
    gatt = report.get("gatt")
    if not isinstance(gatt, dict):
        return
    services = gatt.get("services", [])
    if not isinstance(services, list):
        return
    for service in services:
        if not isinstance(service, dict):
            continue
        if "resolution" in service:
            yield "service", service.get("uuid"), service["resolution"]
        characteristics = service.get("characteristics", [])
        if not isinstance(characteristics, list):
            continue
        for characteristic in characteristics:
            if not isinstance(characteristic, dict):
                continue
            if "resolution" in characteristic:
                yield "characteristic", characteristic.get("uuid"), characteristic["resolution"]
            descriptors = characteristic.get("descriptors", [])
            if not isinstance(descriptors, list):
                continue
            for descriptor in descriptors:
                if isinstance(descriptor, dict) and "resolution" in descriptor:
                    yield "descriptor", descriptor.get("uuid"), descriptor["resolution"]


def _validate_active_binding(report, snapshot_source):
    count = 0
    for namespace, value, observed in _iter_gatt_resolutions(report):
        if not isinstance(observed, dict):
            raise ValueError("GATT resolution provenance is malformed")
        registry_name = _GATT_REGISTRY_BY_NAMESPACE[namespace]
        expected = resolve_gatt_uuid(
            value,
            namespace,
            snapshot_source["registries"][registry_name],
        )
        if observed != expected:
            raise ValueError(
                "GATT resolution does not match pinned Bluetooth snapshot: "
                f"{namespace}:{value}"
            )
        count += 1
    return count


def sources_require_bluetooth_snapshot(sources):
    """Return True when source evidence contains Bluetooth registry-derived data."""
    if not isinstance(sources, list):
        raise ValueError("sources must be a list")
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("source must be an object")
        report = source.get("report")
        if not isinstance(report, dict):
            continue
        if source.get("evidence_type") == "passive_ble":
            if isinstance(report.get("identifier_registries"), dict):
                return True
        elif source.get("evidence_type") == "active_gatt":
            if any(True for _ in _iter_gatt_resolutions(report)):
                return True
    return False


def has_bluetooth_provenance(records):
    return any(
        item["catalog_type"] == BLUETOOTH_CATALOG_TYPE
        for item in normalize_catalog_provenance(records)
    )


def bind_bluetooth_snapshot(snapshot_source, sources):
    """Bind a verified snapshot to source reports and mark whether it was consulted."""
    if not isinstance(snapshot_source, dict) or "provenance" not in snapshot_source:
        raise ValueError("snapshot_source is invalid")
    if not isinstance(sources, list):
        raise ValueError("sources must be a list")

    passive_count = 0
    gatt_resolution_count = 0
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("source must be an object")
        report = source.get("report")
        if not isinstance(report, dict):
            raise ValueError("source report must be an object")
        if source.get("evidence_type") == "passive_ble":
            if isinstance(report.get("identifier_registries"), dict):
                _validate_passive_binding(report, snapshot_source)
                passive_count += 1
        elif source.get("evidence_type") == "active_gatt":
            gatt_resolution_count += _validate_active_binding(report, snapshot_source)

    provenance = deepcopy(snapshot_source["provenance"])
    if passive_count or gatt_resolution_count:
        provenance["usage"] = "consulted"
    provenance["binding"] = {
        "passive_report_count": passive_count,
        "validated_gatt_resolution_count": gatt_resolution_count,
    }
    return normalize_catalog_provenance_record(provenance)


def build_device_catalog_provenance(catalog_source, *, usage="consulted"):
    if not isinstance(catalog_source, dict):
        raise ValueError("catalog_source must be an object")
    sha256 = _validate_sha256(catalog_source.get("sha256"), "catalog sha256")
    revision = catalog_source.get("catalog_revision") or f"sha256:{sha256}"
    return normalize_catalog_provenance_record({
        "catalog_type": DEVICE_CATALOG_TYPE,
        "catalog_id": _require_nonempty_string(catalog_source.get("catalog_id"), "catalog_id"),
        "revision": revision,
        "usage": usage,
        "path": _require_nonempty_string(catalog_source.get("path"), "catalog path"),
        "sha256": sha256,
    })


__all__ = [
    "BLUETOOTH_CATALOG_ID",
    "BLUETOOTH_CATALOG_TYPE",
    "CATALOG_PROVENANCE_SCHEMA_VERSION",
    "DEVICE_CATALOG_TYPE",
    "bind_bluetooth_snapshot",
    "build_device_catalog_provenance",
    "has_bluetooth_provenance",
    "load_bluetooth_snapshot",
    "merge_catalog_provenance",
    "normalize_catalog_provenance",
    "normalize_catalog_provenance_record",
    "sources_require_bluetooth_snapshot",
]

"""Fixtures for immutable catalog-provenance tests."""

import hashlib
import json
from pathlib import Path


REGISTRY_NAMES = (
    "company_identifiers",
    "service_uuids",
    "member_uuids",
    "characteristic_uuids",
    "descriptor_uuids",
)


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def write_bluetooth_snapshot(root, *, revision=None):
    revision = revision or ("a" * 40)
    root = Path(root)
    snapshot = root / revision
    snapshot.mkdir(parents=True)
    identifiers = {
        "company_identifiers": {"0x004c": "Example Manufacturer"},
        "service_uuids": {"0x1800": "GAP", "0x180f": "Battery Service"},
        "member_uuids": {"0xfe07": "Example Member"},
        "characteristic_uuids": {"0x2a19": "Battery Level"},
        "descriptor_uuids": {"0x2902": "Client Characteristic Configuration"},
    }
    source_files = {
        "company_identifiers": "company.yaml",
        "service_uuids": "service.yaml",
        "member_uuids": "member.yaml",
        "characteristic_uuids": "characteristic.yaml",
        "descriptor_uuids": "descriptor.yaml",
    }
    manifest_entries = {}
    for name in REGISTRY_NAMES:
        source_sha = _sha(f"source:{name}".encode())
        registry = {
            "schema_version": "1.1.0",
            "importer_version": "2.0.0",
            "source": "Synthetic Bluetooth SIG registry",
            "source_repository": "https://example.invalid/bluetooth-sig.git",
            "source_file": source_files[name],
            "source_commit": revision,
            "source_sha256": source_sha,
            "generated_at_utc": "2026-09-17T00:00:00+00:00",
            "identifiers": identifiers[name],
        }
        raw = _json_bytes(registry)
        filename = f"{name}.json"
        (snapshot / filename).write_bytes(raw)
        manifest_entries[name] = {
            "filename": filename,
            "identifier_count": len(identifiers[name]),
            "normalized_sha256": _sha(raw),
            "source_file": source_files[name],
            "source_sha256": source_sha,
        }
    manifest = {
        "schema_version": "1.0.0",
        "importer_version": "2.0.0",
        "source": "Bluetooth SIG Assigned Numbers",
        "source_repository": "https://example.invalid/bluetooth-sig.git",
        "source_commit": revision,
        "source_commit_time_utc": "2026-09-17T00:00:00+00:00",
        "imported_at_utc": "2026-09-24T00:00:00+00:00",
        "registries": manifest_entries,
    }
    (snapshot / "manifest.json").write_bytes(_json_bytes(manifest))
    return snapshot

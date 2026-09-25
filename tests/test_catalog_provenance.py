"""Tests for immutable catalog provenance and pinning."""

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from catalog_fixtures import write_bluetooth_snapshot
from report_fixtures import passive_report

from kamal.catalog_provenance import (
    bind_bluetooth_snapshot,
    build_device_catalog_provenance,
    load_bluetooth_snapshot,
    merge_catalog_provenance,
    normalize_catalog_provenance,
)
from kamal.identifiers import resolve_gatt_uuid


class CatalogProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def snapshot(self, revision=None):
        return load_bluetooth_snapshot(
            write_bluetooth_snapshot(self.root, revision=revision)
        )

    def test_snapshot_records_manifest_and_registry_hashes(self):
        source = self.snapshot()
        provenance = source["provenance"]
        self.assertEqual(provenance["revision"], "a" * 40)
        self.assertEqual(provenance["usage"], "available")
        self.assertEqual(len(provenance["manifest_sha256"]), 64)
        self.assertEqual(
            set(provenance["registries"]),
            {
                "company_identifiers",
                "service_uuids",
                "member_uuids",
                "characteristic_uuids",
                "descriptor_uuids",
            },
        )
        self.assertTrue(all(
            len(item["normalized_sha256"]) == 64
            for item in provenance["registries"].values()
        ))

    def test_corrupt_registry_is_rejected(self):
        path = write_bluetooth_snapshot(self.root)
        registry = path / "service_uuids.json"
        registry.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "normalized hash mismatch"):
            load_bluetooth_snapshot(path)

    def test_passive_report_binding_marks_snapshot_consulted(self):
        source = self.snapshot()
        bound = bind_bluetooth_snapshot(source, [{
            "evidence_type": "passive_ble",
            "report": passive_report(),
        }])
        self.assertEqual(bound["usage"], "consulted")
        self.assertEqual(bound["binding"]["passive_report_count"], 1)

    def test_passive_report_revision_mismatch_fails_closed(self):
        source = self.snapshot()
        report = passive_report()
        report["identifier_registries"]["service_uuids"]["source_commit"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "does not match pinned snapshot"):
            bind_bluetooth_snapshot(source, [{
                "evidence_type": "passive_ble",
                "report": report,
            }])

    def test_active_gatt_resolution_is_verified_against_snapshot(self):
        source = self.snapshot()
        resolution = resolve_gatt_uuid(
            "180F", "service", source["registries"]["service_uuids"]
        )
        report = {
            "gatt": {
                "services": [{
                    "uuid": "180F",
                    "resolution": resolution,
                    "characteristics": [],
                }],
            },
        }
        bound = bind_bluetooth_snapshot(source, [{
            "evidence_type": "active_gatt",
            "report": report,
        }])
        self.assertEqual(bound["usage"], "consulted")
        self.assertEqual(bound["binding"]["validated_gatt_resolution_count"], 1)

        bad = deepcopy(report)
        bad["gatt"]["services"][0]["resolution"]["name"] = "Wrong"
        with self.assertRaisesRegex(ValueError, "does not match pinned"):
            bind_bluetooth_snapshot(source, [{
                "evidence_type": "active_gatt",
                "report": bad,
            }])

    def test_merge_upgrades_available_to_consulted(self):
        available = self.snapshot()["provenance"]
        consulted = deepcopy(available)
        consulted["usage"] = "consulted"
        merged = merge_catalog_provenance([available], [consulted])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["usage"], "consulted")

    def test_merge_rejects_different_revisions(self):
        first = self.snapshot("a" * 40)["provenance"]
        second_root = self.root / "other"
        second = load_bluetooth_snapshot(
            write_bluetooth_snapshot(second_root, revision="b" * 40)
        )["provenance"]
        with self.assertRaisesRegex(ValueError, "revision/hash mismatch"):
            merge_catalog_provenance([first], [second])

    def test_device_catalog_revision_is_hash_pinned_by_default(self):
        digest = "c" * 64
        provenance = build_device_catalog_provenance({
            "catalog_id": "device-context",
            "path": "/tmp/catalog.json",
            "sha256": digest,
        })
        self.assertEqual(provenance["revision"], f"sha256:{digest}")
        self.assertEqual(provenance["usage"], "consulted")

    def test_normalization_rejects_incomplete_bluetooth_record(self):
        with self.assertRaisesRegex(ValueError, "registry set is incomplete"):
            normalize_catalog_provenance([{
                "catalog_type": "bluetooth_sig_assigned_numbers",
                "revision": "a" * 40,
                "usage": "available",
                "path": "/tmp/snapshot",
                "manifest_sha256": "b" * 64,
                "registries": {},
            }])


if __name__ == "__main__":
    unittest.main()

"""Offline tests for the unified assessment foundation."""

import json
import tempfile
import unittest
from pathlib import Path

from report_fixtures import active_report, passive_report

from kamal.assessment import (
    SCHEMA_VERSION,
    build_assessment,
    load_source,
)


class AssessmentTests(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_report(self, filename, report):
        path = self.root / filename
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def test_import_passive_report(self):
        path = self.write_report("passive.json", passive_report())

        source = load_source(path)

        self.assertEqual(source["evidence_type"], "passive_ble")
        self.assertEqual(source["schema_version"], "0.6.0")
        self.assertTrue(source["source_id"].startswith("sha256:"))

    def test_import_active_report(self):
        path = self.write_report("active.json", active_report())

        source = load_source(path)

        self.assertEqual(source["evidence_type"], "active_gatt")

    def test_preserves_reports_without_correlating(self):
        passive = load_source(self.write_report("passive.json", passive_report(devices=[{
            "address": "AA:BB:CC:DD:EE:FF",
            "address_type": "random",
        }])))

        active = load_source(self.write_report("active.json", active_report()))

        assessment = build_assessment(
            [active, passive],
            assessment_id="test-assessment",
            created_at_utc="2026-09-17T00:00:00+00:00",
        )

        self.assertEqual(assessment["schema_version"], SCHEMA_VERSION)
        self.assertEqual(len(assessment["sources"]), 2)
        self.assertEqual(len(assessment["observations"]), 2)
        self.assertEqual(assessment["relationships"], [])
        self.assertEqual(assessment["catalog_provenance"], [])
        self.assertEqual(assessment["findings"], [])
        self.assertEqual(assessment["integrity"]["finding_count"], 0)
        self.assertEqual(assessment["evidence_contract_version"], "0.12.0")
        for source in assessment["sources"]:
            self.assertEqual(source["record_type"], "evidence_source")
            self.assertEqual(source["contract_version"], "0.12.0")
            self.assertIn(source["collection_mode"], {"passive", "active"})
        for observation in assessment["observations"]:
            self.assertEqual(observation["record_type"], "observation")
            self.assertEqual(observation["contract_version"], "0.12.0")
            self.assertIsNone(observation["authorization_ref"])

        reports = [
            observation["report"]
            for observation in assessment["observations"]
        ]

        self.assertEqual(
            {report["schema_version"] for report in reports},
            {"0.6.0", "0.7.0"},
        )

    def test_active_report_authorization_is_carried_to_observation(self):
        report = active_report()
        report["authorization"] = {
            "authorization_id": "auth:survey-1",
            "sha256": "a" * 64,
            "operation_class": "enumerate_gatt_metadata",
        }
        source = load_source(self.write_report("active-auth.json", report))

        assessment = build_assessment(
            [source],
            assessment_id="authorized-active",
        )

        self.assertEqual(
            assessment["observations"][0]["authorization_ref"],
            "auth:survey-1",
        )

    def test_preserves_explicit_catalog_provenance(self):
        source = load_source(self.write_report("active.json", active_report()))
        digest = "b" * 64
        assessment = build_assessment(
            [source],
            assessment_id="catalog-test",
            catalog_provenance=[{
                "catalog_type": "ble_device_intelligence",
                "catalog_id": "test-catalog",
                "revision": f"sha256:{digest}",
                "usage": "available",
                "path": "/tmp/test-catalog.json",
                "sha256": digest,
            }],
        )
        provenance = assessment["catalog_provenance"][0]
        self.assertEqual(provenance["catalog_id"], "test-catalog")
        self.assertEqual(provenance["revision"], f"sha256:{digest}")
        self.assertEqual(provenance["usage"], "available")

    def test_rejects_duplicate_source(self):
        source = load_source(self.write_report("passive.json", passive_report()))

        with self.assertRaisesRegex(ValueError, "Duplicate source"):
            build_assessment(
                [source, source],
                assessment_id="test-assessment",
            )

    def test_load_source_rejects_malformed_passive_report(self):
        report = passive_report()
        report["advertiser_count"] = 2
        path = self.write_report("malformed-passive.json", report)

        with self.assertRaisesRegex(ValueError, "advertiser_count"):
            load_source(path)

    def test_load_source_rejects_malformed_active_report(self):
        report = active_report()
        report["gatt"]["services"] = {}
        path = self.write_report("malformed-active.json", report)

        with self.assertRaisesRegex(ValueError, "gatt.services"):
            load_source(path)

    def test_rejects_unknown_schema(self):
        path = self.write_report("unknown.json", {
            "schema_version": "9.9.9",
            "advertisers": [],
        })

        with self.assertRaisesRegex(ValueError, "Unsupported"):
            load_source(path)


if __name__ == "__main__":
    unittest.main()

"""Offline tests for the unified assessment foundation."""

import json
import tempfile
import unittest
from pathlib import Path

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
        path = self.write_report("passive.json", {
            "schema_version": "0.6.0",
            "source_pcap": "/tmp/capture.pcap",
            "advertisers": [],
        })

        source = load_source(path)

        self.assertEqual(source["evidence_type"], "passive_ble")
        self.assertEqual(source["schema_version"], "0.6.0")
        self.assertTrue(source["source_id"].startswith("sha256:"))

    def test_import_active_report(self):
        path = self.write_report("active.json", {
            "schema_version": "0.7.0",
            "evidence_type": "active_gatt",
            "target": "AA:BB:CC:DD:EE:FF",
        })

        source = load_source(path)

        self.assertEqual(source["evidence_type"], "active_gatt")

    def test_preserves_reports_without_correlating(self):
        passive = load_source(self.write_report("passive.json", {
            "schema_version": "0.6.0",
            "source_pcap": "/tmp/capture.pcap",
            "advertisers": [{
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "random",
            }],
        }))

        active = load_source(self.write_report("active.json", {
            "schema_version": "0.7.0",
            "evidence_type": "active_gatt",
            "target": "AA:BB:CC:DD:EE:FF",
        }))

        assessment = build_assessment(
            [active, passive],
            assessment_id="test-assessment",
            created_at_utc="2026-09-17T00:00:00+00:00",
        )

        self.assertEqual(assessment["schema_version"], SCHEMA_VERSION)
        self.assertEqual(len(assessment["sources"]), 2)
        self.assertEqual(len(assessment["observations"]), 2)
        self.assertEqual(assessment["relationships"], [])

        reports = [
            observation["report"]
            for observation in assessment["observations"]
        ]

        self.assertEqual(
            {report["schema_version"] for report in reports},
            {"0.6.0", "0.7.0"},
        )

    def test_rejects_duplicate_source(self):
        source = load_source(self.write_report("passive.json", {
            "schema_version": "0.6.0",
            "source_pcap": "/tmp/capture.pcap",
            "advertisers": [],
        }))

        with self.assertRaisesRegex(ValueError, "Duplicate source"):
            build_assessment(
                [source, source],
                assessment_id="test-assessment",
            )

    def test_rejects_unknown_schema(self):
        path = self.write_report("unknown.json", {
            "schema_version": "9.9.9",
            "advertisers": [],
        })

        with self.assertRaisesRegex(ValueError, "Unsupported"):
            load_source(path)


if __name__ == "__main__":
    unittest.main()

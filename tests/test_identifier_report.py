"""Regression checks for a generated K'amal BLE inventory report."""

import json
import os
import unittest
from pathlib import Path


class IdentifierReportTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        filename = os.environ.get("KAMAL_TEST_REPORT")

        if not filename:
            raise unittest.SkipTest(
                "Set KAMAL_TEST_REPORT to validate a generated capture report"
            )

        cls.report = json.loads(Path(filename).read_text(encoding="utf-8"))

    def test_schema_and_provenance(self):
        self.assertEqual(self.report["schema_version"], "0.6.0")

        registries = self.report["identifier_registries"]
        self.assertEqual(
            set(registries),
            {"company_identifiers", "service_uuids", "member_uuids"},
        )

        revisions = {
            registry["source_commit"]
            for registry in registries.values()
        }

        self.assertEqual(len(revisions), 1)
        self.assertEqual(len(next(iter(revisions))), 40)

    def test_raw_and_resolved_identifiers(self):
        for advertiser in self.report["advertisers"]:
            raw_companies = {
                entry["company_id"]
                for entry in advertiser["manufacturer_data"]
            }

            resolved_companies = [
                entry["id"]
                for entry in advertiser["manufacturer_identifiers_resolved"]
            ]

            self.assertEqual(raw_companies, set(resolved_companies))
            self.assertEqual(
                len(resolved_companies),
                len(set(resolved_companies)),
            )

            self.assertEqual(
                set(advertiser["service_uuids_16"]),
                {
                    entry["id"]
                    for entry in advertiser["service_uuids_16_resolved"]
                },
            )

    def test_no_identity_or_gatt_inference(self):
        for advertiser in self.report["advertisers"]:
            evidence = advertiser["profile"]["evidence"]

            self.assertFalse(evidence["gatt_enumerated"])
            self.assertFalse(evidence["physical_identity_confirmed"])

            for entry in advertiser["manufacturer_identifiers_resolved"]:
                self.assertFalse(entry["identity_inference"])

            for entry in advertiser["service_uuids_16_resolved"]:
                self.assertFalse(entry["identity_inference"])
                self.assertFalse(entry["gatt_enumerated"])

    def test_expected_capture_identifiers(self):
        """Verify the identifiers previously observed in this test capture."""
        members = {
            (entry["id"], entry["name"], entry["namespace"])
            for advertiser in self.report["advertisers"]
            for entry in advertiser["service_uuids_16_resolved"]
            if entry["namespace"] == "member"
        }

        self.assertTrue({
            ("0xfe07", "Sonos, Inc.", "member"),
            ("0xfef3", "Google LLC", "member"),
            ("0xfef8", "Aplix Corporation", "member"),
        }.issubset(members))


if __name__ == "__main__":
    unittest.main()

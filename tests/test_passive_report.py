"""Offline tests for passive BLE report construction."""

import unittest

from kamal.passive_report import SCHEMA_VERSION, build_report


class PassiveReportTests(unittest.TestCase):

    def setUp(self):
        self.registries = {
            name: {
                "source": "Bluetooth SIG Assigned Numbers",
                "source_commit": "a" * 40,
                "source_file": f"{name}.yaml",
                "generated_at_utc": "2026-09-17T00:00:00+00:00",
            }
            for name in ("company", "service", "member")
        }

    def test_schema_and_provenance(self):
        report = self.make_report()

        self.assertEqual(SCHEMA_VERSION, "0.6.0")
        self.assertEqual(report["schema_version"], "0.6.0")
        self.assertEqual(
            set(report["identifier_registries"]),
            {"company_identifiers", "service_uuids", "member_uuids"},
        )

        revisions = {
            registry["source_commit"]
            for registry in report["identifier_registries"].values()
        }

        self.assertEqual(revisions, {"a" * 40})

    def test_preserves_observations(self):
        device = {
            "address": "aa:bb:cc:dd:ee:ff",
            "packet_count": 3,
            "profile": {
                "evidence": {
                    "gatt_enumerated": False,
                    "physical_identity_confirmed": False,
                }
            },
        }

        report = self.make_report(
            devices=[device],
            scan_request_targets=[{"address": "11:22:33:44:55:66"}],
        )

        self.assertEqual(report["advertiser_count"], 1)
        self.assertEqual(report["advertisers"], [device])
        self.assertEqual(len(report["scan_request_targets"]), 1)
        self.assertFalse(
            report["advertisers"][0]["profile"]["evidence"]["gatt_enumerated"]
        )

    def test_integrity_and_warnings(self):
        report = self.make_report()

        self.assertEqual(
            report["integrity"],
            {
                "scope": "frames with advertising address",
                "valid": 3,
                "invalid": 1,
                "unknown": 0,
            },
        )
        self.assertEqual(report["warnings"], ["Synthetic warning"])
        self.assertEqual(report["source_pcap"], "/tmp/synthetic.pcap")
        self.assertEqual(report["skipped_ambiguous_packets"], 0)
        self.assertIsNone(report["source_metadata"])

    def make_report(self, **overrides):
        arguments = {
            "source_pcap": "/tmp/synthetic.pcap",
            "source_metadata": None,
            "devices": [],
            "skipped": 0,
            "integrity": {"valid": 3, "invalid": 1, "unknown": 0},
            "warnings": ["Synthetic warning"],
            "scan_request_targets": [],
            "registries": self.registries,
        }
        arguments.update(overrides)
        return build_report(**arguments)


if __name__ == "__main__":
    unittest.main()

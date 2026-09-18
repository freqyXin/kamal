"""Regression tests for K'amal source-report validation."""

import copy
import unittest

from kamal.report_validation import validate_report
from report_fixtures import active_report, passive_report


class ReportValidationTests(unittest.TestCase):

    def test_accepts_valid_passive_report(self):
        validate_report(passive_report(), "passive_ble")

    def test_accepts_failed_gatt_connection(self):
        validate_report(active_report(), "active_gatt")

    def test_rejects_missing_passive_field(self):
        report = passive_report()
        del report["source_metadata"]

        with self.assertRaisesRegex(ValueError, "source_metadata"):
            validate_report(report, "passive_ble")

    def test_rejects_mismatched_advertiser_count(self):
        report = passive_report()
        report["advertiser_count"] = 1

        with self.assertRaisesRegex(ValueError, "advertiser_count"):
            validate_report(report, "passive_ble")

    def test_rejects_boolean_packet_count(self):
        report = passive_report()
        report["skipped_ambiguous_packets"] = True

        with self.assertRaisesRegex(
            ValueError, "skipped_ambiguous_packets"
        ):
            validate_report(report, "passive_ble")

    def test_rejects_malformed_advertiser(self):
        report = passive_report()
        report["advertisers"] = ["not an advertiser"]
        report["advertiser_count"] = 1

        with self.assertRaisesRegex(ValueError, "advertisers"):
            validate_report(report, "passive_ble")

    def test_rejects_missing_connection_state(self):
        report = active_report()
        del report["connection"]["attempted"]

        with self.assertRaisesRegex(ValueError, "connection.attempted"):
            validate_report(report, "active_gatt")

    def test_rejects_invalid_gatt_services_type(self):
        report = active_report()
        report["gatt"]["services"] = {}

        with self.assertRaisesRegex(ValueError, "gatt.services"):
            validate_report(report, "active_gatt")

    def test_rejects_malformed_nested_characteristic(self):
        report = active_report()
        report["gatt"]["services"] = [{
            "handle": 1,
            "uuid": "1800",
            "characteristics": [{
                "handle": 2,
                "uuid": "2A00",
                "properties": "read",
                "descriptors": [],
            }],
        }]

        with self.assertRaisesRegex(ValueError, "properties"):
            validate_report(report, "active_gatt")

    def test_rejects_connected_without_attempt(self):
        report = active_report()
        report["connection"]["attempted"] = False
        report["connection"]["connected"] = True

        with self.assertRaisesRegex(ValueError, "requires attempted"):
            validate_report(report, "active_gatt")

    def test_rejects_enumeration_without_connection(self):
        report = active_report()
        report["gatt"]["enumeration_attempted"] = True

        with self.assertRaisesRegex(ValueError, "requires connected"):
            validate_report(report, "active_gatt")

    def test_rejects_unsupported_evidence_type(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            validate_report(passive_report(), "wifi")

    def test_does_not_modify_valid_report(self):
        report = passive_report()
        original = copy.deepcopy(report)

        validate_report(report, "passive_ble")

        self.assertEqual(report, original)


if __name__ == "__main__":
    unittest.main()

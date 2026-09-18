"""Tests for finding collection validation."""

import unittest

from kamal.findings import validate_findings


class FindingCollectionTests(unittest.TestCase):
    def setUp(self):
        self.reports = {
            "observation:test": {"gatt": {"services": [{}]}}
        }

    def finding(self, finding_id):
        return {
            "finding_id": finding_id,
            "rule_id": "BLE-GATT-001",
            "title": "Test finding",
            "severity": "informational",
            "confidence": "low",
            "status": "potential",
            "evidence": [{
                "observation_id": "observation:test",
                "path": "/gatt/services/0",
            }],
            "description": "Observed condition.",
            "interpretation": "Potential relevance.",
            "limitations": "Further testing required.",
        }

    def test_accepts_empty_collection(self):
        self.assertEqual(validate_findings([], self.reports), [])

    def test_rejects_non_list_collection(self):
        with self.assertRaisesRegex(ValueError, "must be a list"):
            validate_findings({}, self.reports)

    def test_rejects_duplicate_ids(self):
        findings = [
            self.finding("finding:one"),
            self.finding("finding:one"),
        ]
        with self.assertRaisesRegex(ValueError, "Duplicate finding ID"):
            validate_findings(findings, self.reports)

    def test_accepts_unique_ids(self):
        findings = [
            self.finding("finding:one"),
            self.finding("finding:two"),
        ]
        self.assertIs(validate_findings(findings, self.reports), findings)


if __name__ == "__main__":
    unittest.main()

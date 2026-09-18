"""Regression tests for malformed evidence references."""

import unittest

from kamal.findings import validate_finding


class MalformedEvidenceTests(unittest.TestCase):
    def test_rejects_unhashable_observation_id(self):
        finding = {
            "finding_id": "finding:test",
            "rule_id": "BLE-GATT-001",
            "title": "Test",
            "severity": "informational",
            "confidence": "low",
            "status": "potential",
            "description": "Observed condition.",
            "interpretation": "Potential relevance.",
            "limitations": "Further testing required.",
            "evidence": [{
                "observation_id": ["invalid", "list"],
                "path": "/gatt/services/0",
            }],
        }

        reports = {
            "observation:test": {"gatt": {"services": [{}]}}
        }

        with self.assertRaisesRegex(
            ValueError, "Invalid evidence observation ID"
        ):
            validate_finding(finding, reports)


if __name__ == "__main__":
    unittest.main()

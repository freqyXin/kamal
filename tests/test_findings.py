"""Tests for evidence-backed security finding validation."""

import unittest

from kamal.findings import validate_finding, validate_findings


class FindingValidationTests(unittest.TestCase):
    def valid_finding(self):
        return {
            "finding_id": "finding:test",
            "rule_id": "BLE-GATT-001",
            "title": "Test finding",
            "severity": "informational",
            "confidence": "low",
            "status": "potential",
            "evidence": [{
                "observation_id": "observation:test",
                "path": "/gatt/services/0",
            }],
            "description": "Observed test condition.",
            "interpretation": "Potential security relevance.",
            "limitations": "Further validation is required.",
        }

    def test_accepts_valid_finding(self):
        finding = self.valid_finding()
        result = validate_finding(
            finding,
            {"observation:test": {"gatt": {"services": [{}]}}},
        )
        self.assertIs(result, finding)

    def test_rejects_invalid_severity(self):
        finding = self.valid_finding()
        finding["severity"] = "severe"
        with self.assertRaisesRegex(ValueError, "severity"):
            validate_finding(finding, {"observation:test": {"gatt": {"services": [{}]}}})

    def test_rejects_invalid_confidence(self):
        finding = self.valid_finding()
        finding["confidence"] = "certain"
        with self.assertRaisesRegex(ValueError, "confidence"):
            validate_finding(finding, {"observation:test": {"gatt": {"services": [{}]}}})

    def test_rejects_missing_evidence(self):
        finding = self.valid_finding()
        finding["evidence"] = []
        with self.assertRaisesRegex(ValueError, "requires evidence"):
            validate_finding(finding, {"observation:test": {"gatt": {"services": [{}]}}})

    def test_rejects_unknown_observation(self):
        finding = self.valid_finding()
        with self.assertRaisesRegex(ValueError, "Unknown evidence observation"):
            validate_finding(finding, {"observation:other": {"gatt": {"services": [{}]}}})

    def test_rejects_invalid_evidence_path(self):
        finding = self.valid_finding()
        finding["evidence"][0]["path"] = "gatt/services/0"
        with self.assertRaisesRegex(ValueError, "Invalid evidence path"):
            validate_finding(finding, {"observation:test": {"gatt": {"services": [{}]}}})


    def test_rejects_nonexistent_evidence_path(self):
        finding = self.valid_finding()
        finding["evidence"][0]["path"] = "/gatt/services/99"
        reports = {"observation:test": {"gatt": {"services": [{}]}}}

        with self.assertRaisesRegex(
            ValueError, "Evidence path does not resolve"
        ):
            validate_finding(finding, reports)


if __name__ == "__main__":
    unittest.main()

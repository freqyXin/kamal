"""Integration tests for assessment findings."""

import unittest

from kamal.assessment import build_assessment


class AssessmentFindingTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            "source_id": "sha256:test",
            "path": "/tmp/test.json",
            "sha256": "test",
            "evidence_type": "active_gatt",
            "schema_version": "0.7.0",
            "report": {
                "gatt": {
                    "services": [{"uuid": "1800"}]
                }
            },
        }

    def finding(self, finding_id="finding:test", path="/gatt/services/0"):
        return {
            "finding_id": finding_id,
            "rule_id": "BLE-GATT-001",
            "title": "Test finding",
            "severity": "informational",
            "confidence": "low",
            "status": "potential",
            "evidence": [{
                "observation_id": "observation:sha256:test",
                "path": path,
            }],
            "description": "Observed condition.",
            "interpretation": "Potential relevance.",
            "limitations": "Further testing required.",
        }

    def test_accepts_valid_finding(self):
        finding = self.finding()

        assessment = build_assessment(
            [self.source],
            assessment_id="test",
            findings=[finding],
        )

        self.assertEqual(assessment["findings"], [finding])
        self.assertEqual(assessment["integrity"]["finding_count"], 1)

    def test_rejects_nonexistent_evidence(self):
        with self.assertRaisesRegex(
            ValueError, "Evidence path does not resolve"
        ):
            build_assessment(
                [self.source],
                assessment_id="test",
                findings=[self.finding(path="/gatt/services/99")],
            )

    def test_rejects_duplicate_finding_ids(self):
        with self.assertRaisesRegex(ValueError, "Duplicate finding ID"):
            build_assessment(
                [self.source],
                assessment_id="test",
                findings=[
                    self.finding(),
                    self.finding(),
                ],
            )


    def test_findings_are_independent_of_caller(self):
        finding = self.finding()
        findings = [finding]

        assessment = build_assessment(
            [self.source],
            assessment_id="test",
            findings=findings,
        )

        findings.append(self.finding("finding:second"))
        finding["title"] = "Changed title"
        finding["evidence"][0]["path"] = "/invalid"

        self.assertEqual(assessment["integrity"]["finding_count"], 1)
        self.assertEqual(len(assessment["findings"]), 1)
        self.assertEqual(
            assessment["findings"][0]["title"],
            "Test finding",
        )
        self.assertEqual(
            assessment["findings"][0]["evidence"][0]["path"],
            "/gatt/services/0",
        )


if __name__ == "__main__":
    unittest.main()

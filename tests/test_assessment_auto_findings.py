"""Integration tests for automatic BLE assessment findings."""

import unittest

from kamal.assessment import build_assessment


class AssessmentAutoFindingTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            "source_id": "sha256:test",
            "path": "/tmp/test.json",
            "sha256": "test",
            "evidence_type": "active_gatt",
            "schema_version": "0.7.0",
            "report": {
                "gatt": {
                    "enumerated": True,
                    "services": [{
                        "characteristics": [{
                            "uuid": "1234",
                            "properties": ["write-without-response"],
                        }],
                    }],
                },
            },
        }

    def test_generates_finding_by_default(self):
        assessment = build_assessment(
            [self.source],
            assessment_id="test",
        )

        self.assertEqual(len(assessment["findings"]), 1)
        self.assertEqual(
            assessment["findings"][0]["rule_id"],
            "BLE-GATT-001",
        )
        self.assertEqual(assessment["integrity"]["finding_count"], 1)

    def test_explicit_empty_list_disables_generation(self):
        assessment = build_assessment(
            [self.source],
            assessment_id="test",
            findings=[],
        )

        self.assertEqual(assessment["findings"], [])
        self.assertEqual(assessment["integrity"]["finding_count"], 0)

    def test_explicit_findings_replace_generated_findings(self):
        finding = {
            "finding_id": "finding:manual",
            "rule_id": "MANUAL-001",
            "title": "Manual review",
            "severity": "informational",
            "confidence": "low",
            "status": "potential",
            "evidence": [{
                "observation_id": "observation:sha256:test",
                "path": "/gatt/services/0",
            }],
            "description": "Manually recorded observation.",
            "interpretation": "Requires further review.",
            "limitations": "No security behavior was tested.",
        }

        assessment = build_assessment(
            [self.source],
            assessment_id="test",
            findings=[finding],
        )

        self.assertEqual(assessment["findings"], [finding])
        self.assertEqual(assessment["integrity"]["finding_count"], 1)


if __name__ == "__main__":
    unittest.main()

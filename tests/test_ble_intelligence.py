"""Tests for conservative BLE GATT intelligence."""

import unittest

from kamal.ble_intelligence import analyze_gatt_observation
from kamal.findings import validate_findings


class BLEIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.observation = {
            "observation_id": "observation:test",
            "evidence_type": "active_gatt",
            "report": {
                "gatt": {
                    "enumerated": True,
                    "services": [{
                        "characteristics": [{
                            "uuid": "1234",
                            "properties": ["read", "write-without-response"],
                        }],
                    }],
                },
            },
        }

    def test_detects_write_without_response(self):
        findings = analyze_gatt_observation(self.observation)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "BLE-GATT-001")
        self.assertEqual(findings[0]["severity"], "informational")
        self.assertEqual(findings[0]["confidence"], "low")
        self.assertEqual(findings[0]["status"], "potential")

    def test_skips_failed_enumeration(self):
        self.observation["report"]["gatt"]["enumerated"] = False

        self.assertEqual(
            analyze_gatt_observation(self.observation),
            [],
        )

    def test_skips_nonmatching_properties(self):
        characteristic = self.observation["report"]["gatt"][
            "services"
        ][0]["characteristics"][0]

        characteristic["properties"] = ["read", "notify"]

        self.assertEqual(
            analyze_gatt_observation(self.observation),
            [],
        )

    def test_evidence_path_resolves(self):
        findings = analyze_gatt_observation(self.observation)

        self.assertEqual(
            findings[0]["evidence"][0]["path"],
            "/gatt/services/0/characteristics/0/properties",
        )

        reports = {
            self.observation["observation_id"]:
                self.observation["report"],
        }

        self.assertEqual(
            validate_findings(findings, reports),
            findings,
        )

    def test_skips_passive_observation(self):
        self.observation["evidence_type"] = "passive_ble"

        self.assertEqual(
            analyze_gatt_observation(self.observation),
            [],
        )


    def test_multiple_characteristics_have_unique_evidence(self):
        characteristics = self.observation["report"]["gatt"][
            "services"
        ][0]["characteristics"]

        characteristics.append({
            "uuid": "5678",
            "properties": ["write-without-response"],
        })

        findings = analyze_gatt_observation(self.observation)

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            len({finding["finding_id"] for finding in findings}),
            2,
        )
        self.assertEqual(
            [finding["evidence"][0]["path"] for finding in findings],
            [
                "/gatt/services/0/characteristics/0/properties",
                "/gatt/services/0/characteristics/1/properties",
            ],
        )

    def test_finding_ids_are_deterministic(self):
        first = analyze_gatt_observation(self.observation)
        second = analyze_gatt_observation(self.observation)

        self.assertEqual(
            [finding["finding_id"] for finding in first],
            [finding["finding_id"] for finding in second],
        )


    def test_partial_enumeration_does_not_generate_findings(self):
        self.observation["report"]["gatt"]["enumerated"] = False
        self.observation["report"]["gatt"]["error"] = (
            "Enumeration interrupted"
        )

        findings = analyze_gatt_observation(self.observation)

        self.assertEqual(findings, [])


    def test_enumeration_error_suppresses_findings(self):
        self.observation["report"]["gatt"]["enumerated"] = True
        self.observation["report"]["gatt"]["error"] = (
            "Enumeration incomplete"
        )

        self.assertEqual(
            analyze_gatt_observation(self.observation),
            [],
        )


if __name__ == "__main__":
    unittest.main()

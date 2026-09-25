"""Tests for conservative offline BSAM coverage mapping."""

import copy
import unittest

from kamal.bsam_mapping import (
    BSAM_CONTROLS,
    build_bsam_mapping,
)


ASSESSMENT_SHA = "a" * 64
ENRICHMENT_SHA = "b" * 64


def passive_observation(*, address_type="random"):
    return {
        "observation_id": "observation:passive",
        "source_id": "sha256:" + ("c" * 64),
        "protocol": "ble",
        "evidence_type": "passive_ble",
        "report": {
            "schema_version": "0.6.0",
            "advertisers": [{
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": address_type,
                "names": ["SensorTag"],
                "manufacturer_data": [{"company_id": 76, "payload_hex": "01ff"}],
                "service_uuids_16": ["180F"],
            }],
        },
    }


def active_observation(*, enumerated=True):
    return {
        "observation_id": "observation:active",
        "source_id": "sha256:" + ("d" * 64),
        "protocol": "ble",
        "evidence_type": "active_gatt",
        "report": {
            "schema_version": "0.7.0",
            "evidence_type": "active_gatt",
            "gatt": {
                "enumerated": enumerated,
                "error": None,
                "services": [{
                    "uuid": "180F",
                    "characteristics": [{
                        "uuid": "2A19",
                        "properties": ["read", "write-without-response"],
                        "descriptors": [],
                    }],
                }] if enumerated else [],
            },
        },
    }


def finding(*, status="potential", rule_id="BLE-GATT-001"):
    return {
        "finding_id": "finding:test",
        "rule_id": rule_id,
        "title": "Write Without Response characteristic requires review",
        "severity": "informational",
        "confidence": "low",
        "status": status,
        "evidence": [{
            "observation_id": "observation:active",
            "path": "/gatt/services/0/characteristics/0/properties",
        }],
        "description": "Synthetic finding.",
        "interpretation": "Review access control.",
        "limitations": "Synthetic test only.",
    }


def assessment_source(*observations, findings=None):
    assessment = {
        "schema_version": "0.9.0",
        "assessment_id": "run-a",
        "evidence_contract_version": "0.12.0",
        "observations": list(observations),
        "findings": [] if findings is None else list(findings),
        "catalog_provenance": [],
    }
    return {
        "assessment_source_id": "sha256:" + ASSESSMENT_SHA,
        "path": "/tmp/assessment.json",
        "sha256": ASSESSMENT_SHA,
        "assessment_id": "run-a",
        "assessment": assessment,
    }


def enrichment_source(*, assessment_sha=ASSESSMENT_SHA, claim_state="documented"):
    claim = {
        "claim_id": "claim:test",
        "category": "chipset",
        "value": "Example BLE SoC",
        "state": claim_state,
        "confidence": "medium",
        "observation_id": "observation:passive",
        "catalog_source_id": "sha256:" + ("e" * 64),
        "catalog_record_id": "chipset-test",
        "limitations": ["Context only."],
    }
    if claim_state == "validated":
        claim["validation"] = {
            "reviewer": "analyst-1",
            "validated_at_utc": "2026-09-25T00:00:00Z",
            "basis": "Lab verification.",
        }
    payload = {
        "schema_version": "0.12.0",
        "record_type": "ble_device_intelligence_enrichment",
        "contract_version": "0.12.0",
        "assessment_source": {
            "assessment_source_id": "sha256:" + assessment_sha,
            "assessment_id": "run-a",
            "path": "/tmp/assessment.json",
            "sha256": assessment_sha,
        },
        "catalog_provenance": [],
        "claims": [claim],
    }
    return {
        "enrichment_source_id": "sha256:" + ENRICHMENT_SHA,
        "path": "/tmp/enrichment.json",
        "sha256": ENRICHMENT_SHA,
        "enrichment": payload,
    }


def by_id(result, control_id):
    return next(item for item in result["controls"] if item["control_id"] == control_id)


class BSAMMappingTests(unittest.TestCase):
    def build(self, source, *, enrichment=None):
        return build_bsam_mapping(
            source,
            enrichment_source=enrichment,
            created_at_utc="2026-09-25T17:00:00+00:00",
        )

    def test_profile_contains_all_36_controls(self):
        result = self.build(assessment_source())
        self.assertEqual(len(BSAM_CONTROLS), 36)
        self.assertEqual(len(result["controls"]), 36)
        self.assertEqual(result["profile"]["control_count"], 36)
        self.assertEqual(len(result["profile"]["control_catalog_sha256"]), 64)
        self.assertFalse(result["profile"]["upstream_revision_pinned"])

    def test_no_evidence_remains_not_assessed(self):
        result = self.build(assessment_source())
        self.assertTrue(all(
            item["coverage_state"] == "not_assessed"
            for item in result["controls"]
        ))
        self.assertTrue(all(
            item["review_state"] == "no_conclusion"
            for item in result["controls"]
        ))
        self.assertFalse(result["summary"]["pass_fail_determinations_made"])

    def test_passive_ble_maps_discovery_evidence_without_pass_fail(self):
        result = self.build(assessment_source(passive_observation()))
        for control_id in ("BSAM-DI-01", "BSAM-DI-03", "BSAM-DI-04", "BSAM-DI-05", "BSAM-DI-06"):
            control = by_id(result, control_id)
            self.assertEqual(control["coverage_state"], "evidence_available")
            self.assertEqual(control["review_state"], "no_conclusion")
        self.assertEqual(by_id(result, "BSAM-DI-02")["coverage_state"], "not_assessed")

    def test_random_address_is_not_treated_as_privacy_pass(self):
        result = self.build(assessment_source(passive_observation(address_type="random")))
        control = by_id(result, "BSAM-DI-06")
        self.assertEqual(control["review_state"], "no_conclusion")
        self.assertIn("does not establish", control["signals"][0]["summary"])

    def test_active_gatt_maps_service_evidence(self):
        result = self.build(assessment_source(active_observation()))
        self.assertEqual(by_id(result, "BSAM-SE-02")["coverage_state"], "evidence_available")
        self.assertEqual(by_id(result, "BSAM-SE-03")["coverage_state"], "evidence_available")
        self.assertEqual(by_id(result, "BSAM-SE-02")["review_state"], "no_conclusion")

    def test_failed_gatt_enumeration_does_not_assess_service_controls(self):
        result = self.build(assessment_source(active_observation(enumerated=False)))
        self.assertEqual(by_id(result, "BSAM-SE-02")["coverage_state"], "not_assessed")
        self.assertEqual(by_id(result, "BSAM-SE-03")["coverage_state"], "not_assessed")

    def test_potential_gatt_finding_becomes_candidate_concern(self):
        result = self.build(assessment_source(active_observation(), findings=[finding()]))
        control = by_id(result, "BSAM-SE-03")
        self.assertEqual(control["review_state"], "candidate_concern")
        self.assertEqual(control["finding_references"][0]["status"], "potential")
        self.assertEqual(result["summary"]["candidate_concern_count"], 1)

    def test_confirmed_source_finding_is_preserved_without_bsam_fail(self):
        result = self.build(assessment_source(
            active_observation(), findings=[finding(status="confirmed")]
        ))
        control = by_id(result, "BSAM-SE-03")
        self.assertEqual(control["review_state"], "confirmed_finding")
        self.assertIn("not automatically", control["assessment_statement"])
        self.assertFalse(result["summary"]["pass_fail_determinations_made"])

    def test_unmapped_finding_does_not_change_bsam_review_state(self):
        result = self.build(assessment_source(
            active_observation(), findings=[finding(rule_id="OTHER-RULE")]
        ))
        self.assertEqual(by_id(result, "BSAM-SE-03")["review_state"], "no_conclusion")

    def test_enrichment_context_preserves_documented_state(self):
        result = self.build(
            assessment_source(passive_observation()),
            enrichment=enrichment_source(claim_state="documented"),
        )
        context = by_id(result, "BSAM-IG-01")["context_claims"][0]
        self.assertEqual(context["state"], "documented")
        self.assertEqual(by_id(result, "BSAM-IG-01")["coverage_state"], "not_assessed")

    def test_enrichment_context_preserves_validated_metadata(self):
        result = self.build(
            assessment_source(passive_observation()),
            enrichment=enrichment_source(claim_state="validated"),
        )
        context = by_id(result, "BSAM-IG-02")["context_claims"][0]
        self.assertEqual(context["state"], "validated")
        self.assertEqual(context["validation"]["reviewer"], "analyst-1")

    def test_enrichment_must_bind_exact_assessment_hash(self):
        with self.assertRaisesRegex(ValueError, "supplied assessment sha256"):
            self.build(
                assessment_source(passive_observation()),
                enrichment=enrichment_source(assessment_sha="f" * 64),
            )

    def test_output_records_offline_execution(self):
        result = self.build(assessment_source(passive_observation()))
        self.assertEqual(result["execution"]["status"], "offline_mapping")
        self.assertFalse(result["execution"]["rf_performed"])
        self.assertFalse(result["execution"]["network_performed"])
        self.assertFalse(result["summary"]["full_bsam_coverage_claimed"])

    def test_mapping_is_deterministic_with_fixed_timestamp(self):
        source = assessment_source(passive_observation(), active_observation())
        first = self.build(source)
        second = self.build(source)
        self.assertEqual(first, second)

    def test_inputs_are_not_mutated(self):
        source = assessment_source(passive_observation(), active_observation(), findings=[finding()])
        enrichment = enrichment_source()
        source_before = copy.deepcopy(source)
        enrichment_before = copy.deepcopy(enrichment)
        self.build(source, enrichment=enrichment)
        self.assertEqual(source, source_before)
        self.assertEqual(enrichment, enrichment_before)


if __name__ == "__main__":
    unittest.main()

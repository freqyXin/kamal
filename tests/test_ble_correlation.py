"""Tests for deterministic offline BLE cross-run correlation."""

import json
import tempfile
import unittest
from pathlib import Path

from kamal.ble_correlation import (
    build_ble_cross_run_correlation,
    load_assessment_source,
    normalize_ble_address,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def observation(
    observation_id,
    *,
    evidence_type="passive_ble",
    address="AA:BB:CC:DD:EE:FF",
    address_type="public",
    duplicate_active_address=False,
):
    if evidence_type == "passive_ble":
        report = {
            "advertisers": [{
                "address": address,
                "address_type": address_type,
            }],
        }
    else:
        report = {"target": address}
        if duplicate_active_address:
            report["discovery"] = {"address": address.lower()}
    return {
        "observation_id": observation_id,
        "source_id": f"sha256:{DIGEST_A if observation_id.endswith('a') else DIGEST_B}",
        "protocol": "ble",
        "evidence_type": evidence_type,
        "report": report,
    }


def source(assessment_id, observation_record, *, digest):
    return {
        "assessment_source_id": f"sha256:{digest}",
        "path": f"/tmp/{assessment_id}.json",
        "sha256": digest,
        "assessment_id": assessment_id,
        "assessment": {
            "schema_version": "0.9.0",
            "assessment_id": assessment_id,
            "evidence_contract_version": "0.12.0",
            "observations": [observation_record],
        },
    }


class BLECorrelationTests(unittest.TestCase):
    def test_normalizes_ble_address(self):
        self.assertEqual(
            normalize_ble_address("aa:bb:cc:dd:ee:ff"),
            "AA:BB:CC:DD:EE:FF",
        )
        with self.assertRaisesRegex(ValueError, "Invalid BLE address"):
            normalize_ble_address("not-an-address")

    def test_public_exact_match_is_candidate_not_stable_identity(self):
        first = source(
            "run-a",
            observation("observation:a"),
            digest=DIGEST_A,
        )
        second = source(
            "run-b",
            observation("observation:b"),
            digest=DIGEST_B,
        )

        result = build_ble_cross_run_correlation([first, second])
        self.assertEqual(len(result["identity_candidates"]), 1)
        candidate = result["identity_candidates"][0]
        self.assertEqual(candidate["identifier"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(candidate["match_confidence"], "high")
        self.assertEqual(candidate["asset_identity_confidence"], "medium")
        self.assertEqual(candidate["status"], "needs_review")
        self.assertFalse(candidate["stable_identity"])
        self.assertNotIn("asset_id", candidate)
        self.assertEqual(len(candidate["evidence"]), 2)

    def test_random_address_keeps_identity_confidence_low(self):
        first = source(
            "run-a",
            observation("observation:a", address_type="random"),
            digest=DIGEST_A,
        )
        second = source(
            "run-b",
            observation("observation:b", address_type="public"),
            digest=DIGEST_B,
        )
        candidate = build_ble_cross_run_correlation([first, second])[
            "identity_candidates"
        ][0]
        self.assertEqual(candidate["asset_identity_confidence"], "low")
        self.assertIn("random/private", candidate["limitations"][0])

    def test_same_address_in_only_one_run_is_not_cross_run_candidate(self):
        first = source(
            "run-a",
            observation("observation:a"),
            digest=DIGEST_A,
        )
        second = source(
            "run-b",
            observation(
                "observation:b",
                address="11:22:33:44:55:66",
            ),
            digest=DIGEST_B,
        )
        result = build_ble_cross_run_correlation([first, second])
        self.assertEqual(result["identity_candidates"], [])

    def test_active_target_and_discovery_are_deduplicated(self):
        first = source(
            "run-a",
            observation(
                "observation:a",
                evidence_type="active_gatt",
                duplicate_active_address=True,
            ),
            digest=DIGEST_A,
        )
        second = source(
            "run-b",
            observation("observation:b"),
            digest=DIGEST_B,
        )
        candidate = build_ble_cross_run_correlation([first, second])[
            "identity_candidates"
        ][0]
        active_evidence = candidate["evidence"][0]
        self.assertEqual(
            active_evidence["evidence_paths"],
            ["/discovery/address", "/target"],
        )
        self.assertEqual(len(candidate["evidence"]), 2)

    def test_output_is_deterministic_across_input_order(self):
        first = source(
            "run-a",
            observation("observation:a"),
            digest=DIGEST_A,
        )
        second = source(
            "run-b",
            observation("observation:b"),
            digest=DIGEST_B,
        )
        forward = build_ble_cross_run_correlation([first, second])
        reverse = build_ble_cross_run_correlation([second, first])
        self.assertEqual(forward, reverse)

    def test_invalid_address_becomes_integrity_warning(self):
        first = source(
            "run-a",
            observation("observation:a", address="invalid"),
            digest=DIGEST_A,
        )
        second = source(
            "run-b",
            observation("observation:b"),
            digest=DIGEST_B,
        )
        result = build_ble_cross_run_correlation([first, second])
        self.assertEqual(result["identity_candidates"], [])
        self.assertEqual(result["integrity"]["warning_count"], 1)
        warning = result["integrity"]["warnings"][0]
        self.assertEqual(warning["code"], "invalid_ble_address")
        self.assertEqual(warning["path"], "/advertisers/0/address")

    def test_duplicate_assessment_id_is_rejected(self):
        first = source(
            "same-run",
            observation("observation:a"),
            digest=DIGEST_A,
        )
        second = source(
            "same-run",
            observation("observation:b"),
            digest=DIGEST_B,
        )
        with self.assertRaisesRegex(ValueError, "Duplicate assessment_id"):
            build_ble_cross_run_correlation([first, second])

    def test_load_assessment_source_hashes_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment.json"
            payload = {
                "schema_version": "0.9.0",
                "assessment_id": "run-a",
                "evidence_contract_version": "0.12.0",
                "observations": [],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_assessment_source(path)
            self.assertEqual(loaded["assessment_id"], "run-a")
            self.assertTrue(loaded["assessment_source_id"].startswith("sha256:"))
            self.assertEqual(len(loaded["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()

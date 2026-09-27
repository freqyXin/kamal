"""Tests for the v0.12 shared evidence contracts."""

import json
import tempfile
import unittest
from pathlib import Path

from kamal.evidence_contracts import (
    EVIDENCE_CONTRACT_VERSION,
    atomic_create_json,
    build_observation_record,
    build_source_record,
)


class EvidenceContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.digest = "a" * 64
        self.source = {
            "source_id": f"sha256:{self.digest}",
            "path": "/evidence/active.json",
            "sha256": self.digest,
            "evidence_type": "active_gatt",
            "schema_version": "0.7.0",
            "report": {
                "schema_version": "0.7.0",
                "evidence_type": "active_gatt",
            },
        }

    def test_build_source_record_preserves_provenance(self):
        record = build_source_record(self.source)
        self.assertEqual(record["record_type"], "evidence_source")
        self.assertEqual(record["contract_version"], EVIDENCE_CONTRACT_VERSION)
        self.assertEqual(record["source_id"], self.source["source_id"])
        self.assertEqual(record["sha256"], self.digest)
        self.assertEqual(record["collection_mode"], "active")

    def test_passive_source_is_classified_passive(self):
        source = dict(self.source)
        source["evidence_type"] = "passive_ble"
        record = build_source_record(source)
        self.assertEqual(record["collection_mode"], "passive")

    def test_source_id_must_match_digest(self):
        source = dict(self.source)
        source["source_id"] = f"sha256:{'b' * 64}"
        with self.assertRaisesRegex(ValueError, "must match"):
            build_source_record(source)

    def test_digest_must_be_sha256_hex(self):
        source = dict(self.source)
        source["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
            build_source_record(source)

    def test_observation_does_not_infer_identity(self):
        observation = build_observation_record(self.source)
        self.assertEqual(observation["record_type"], "observation")
        self.assertEqual(observation["protocol"], "ble")
        self.assertEqual(observation["collection_mode"], "active")
        self.assertIsNone(observation["authorization_ref"])
        self.assertNotIn("device_id", observation)
        self.assertNotIn("asset_id", observation)

    def test_observation_can_carry_authorization_reference(self):
        observation = build_observation_record(
            self.source,
            authorization_ref="authorization:lab-001",
        )
        self.assertEqual(
            observation["authorization_ref"],
            "authorization:lab-001",
        )

    def test_atomic_create_json_creates_complete_document(self):
        destination = self.root / "assessment.json"
        payload = {"schema_version": "0.9.0", "value": [1, 2, 3]}
        atomic_create_json(destination, payload)
        self.assertEqual(
            json.loads(destination.read_text(encoding="utf-8")),
            payload,
        )
        self.assertEqual(list(self.root.glob(".assessment.json.*.tmp")), [])

    def test_atomic_create_json_refuses_overwrite(self):
        destination = self.root / "assessment.json"
        original = b'{"original": true}\n'
        destination.write_bytes(original)
        with self.assertRaises(FileExistsError):
            atomic_create_json(destination, {"replacement": True})
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(list(self.root.glob(".assessment.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()

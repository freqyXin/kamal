"""Tests for read-only BlueZ protected key-evidence analysis."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from kamal.bluez_key_evidence import (
    MAX_BLUEZ_SECRET_SOURCE_BYTES,
    BlueZKeyEvidenceError,
    analyze_bluez_keys,
)

ADAPTER = "AA:BB:CC:DD:EE:01"
TARGET = "AA:BB:CC:DD:EE:FF"
NOW = "2026-09-26T08:30:00Z"
LTK = "00112233445566778899AABBCCDDEEFF"
IRK = "FFEEDDCCBBAA99887766554433221100"


def bonded_info(*, ltk=LTK, irk=IRK):
    return (
        "[General]\n"
        "Name=go dawgs\n"
        "AddressType=public\n"
        "Trusted=true\n"
        "\n"
        "[LongTermKey]\n"
        f"Key={ltk}\n"
        "Authenticated=0\n"
        "EncSize=16\n"
        "EDiv=123\n"
        "Rand=456\n"
        "\n"
        "[IdentityResolvingKey]\n"
        f"Key={irk}\n"
    )


class BlueZKeyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "bluetooth"
        self.adapter = self.root / ADAPTER
        self.device = self.adapter / TARGET
        self.device.mkdir(parents=True)
        for path in (self.root, self.adapter, self.device):
            os.chmod(path, 0o700)

    def write_info(self, text):
        path = self.device / "info"
        path.write_text(text, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def analyze(self, *, pairing_session_ref="pairing:test-001"):
        return analyze_bluez_keys(
            self.root,
            adapter_address=ADAPTER.lower(),
            target_address=TARGET.lower(),
            engagement_id="engagement:test",
            authorization_ref="auth:test-security",
            pairing_session_ref=pairing_session_ref,
            observed_at_utc=NOW,
        )

    def test_analyzes_ltk_and_irk_without_emitting_raw_keys(self):
        info = self.write_info(bonded_info())
        before = info.read_bytes()
        report = self.analyze()
        after = info.read_bytes()
        self.assertEqual(before, after)

        self.assertEqual(report["record_type"], "bluez_key_analysis_report")
        self.assertEqual(report["summary"]["key_count"], 2)
        self.assertEqual(report["summary"]["key_classes"], ["irk", "ltk"])
        self.assertEqual(report["target"]["address"], TARGET)
        self.assertEqual(report["target"]["address_type"], "public")

        execution = report["execution"]
        self.assertFalse(execution["rf_performed"])
        self.assertFalse(execution["network_performed"])
        self.assertFalse(execution["mutated_bluez_state"])
        self.assertTrue(execution["raw_secret_values_read"])
        self.assertFalse(execution["raw_secret_values_persisted_by_command"])
        self.assertFalse(execution["raw_secret_values_printed"])

        secret = report["secret_artifact"]
        self.assertEqual(secret["path"], str(info.absolute()))
        self.assertEqual(secret["storage_state"], "os_protected_source")
        self.assertEqual(secret["secret_classes"], ["irk", "ltk"])
        self.assertTrue(secret["contains_secret_material"])
        self.assertFalse(secret["raw_secret_embedded_in_metadata"])

        ltk = next(item for item in report["key_evidence"] if item["key_class"] == "ltk")
        irk = next(item for item in report["key_evidence"] if item["key_class"] == "irk")
        self.assertEqual(
            ltk["key_fingerprint_sha256"],
            hashlib.sha256(bytes.fromhex(LTK)).hexdigest(),
        )
        self.assertEqual(
            irk["key_fingerprint_sha256"],
            hashlib.sha256(bytes.fromhex(IRK)).hexdigest(),
        )
        self.assertFalse(ltk["authenticated"])
        self.assertEqual(ltk["encryption_size"], 16)
        self.assertIsNone(ltk["secure_connections"])
        self.assertIsNone(ltk["debug_key"])
        self.assertEqual(ltk["source"]["section"], "LongTermKey")
        self.assertEqual(irk["source"]["section"], "IdentityResolvingKey")

        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(LTK, serialized)
        self.assertNotIn(IRK, serialized)
        self.assertNotIn('"raw_key":', serialized)
        self.assertNotIn('"raw_key_hex":', serialized)
        self.assertNotIn('"key_hex":', serialized)

    def test_source_artifact_hash_is_exact(self):
        info = self.write_info(bonded_info())
        raw = info.read_bytes()
        report = self.analyze()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(report["source_artifact"]["sha256"], digest)
        self.assertEqual(report["secret_artifact"]["sha256"], digest)
        for item in report["key_evidence"]:
            self.assertEqual(item["source"]["artifact_ref"], "sha256:" + digest)

    def test_pairing_session_reference_is_optional_for_existing_store(self):
        self.write_info(bonded_info())
        report = self.analyze(pairing_session_ref=None)
        self.assertIsNone(report["pairing_session_ref"])
        for item in report["key_evidence"]:
            self.assertIsNone(item["pairing_session_ref"])
            self.assertTrue(
                any("pairing session" in text.lower() for text in item["limitations"])
            )

    def test_obvious_pattern_flags_are_analytical_only(self):
        self.write_info(bonded_info(ltk="00" * 16))
        report = self.analyze()
        ltk_analysis = next(item for item in report["analysis"] if item["key_class"] == "ltk")
        self.assertIn("all_zero", ltk_analysis["pattern_flags"])
        self.assertIn("single_repeated_byte", ltk_analysis["pattern_flags"])
        self.assertNotIn("vulnerability", json.dumps(report).lower())

    def test_duplicate_fingerprint_within_source_is_observation(self):
        self.write_info(bonded_info(irk=LTK))
        report = self.analyze()
        self.assertEqual(
            report["summary"]["duplicate_fingerprint_groups_within_source"], 1
        )
        self.assertTrue(
            all(item["duplicate_fingerprint_within_source"] for item in report["analysis"])
        )

    def test_unrecognized_key_section_is_not_fingerprinted(self):
        future = "1234567890ABCDEF1234567890ABCDEF"
        self.write_info(
            bonded_info()
            + "\n[FutureSecurityThing]\n"
            + f"Key={future}\n"
            + "Mode=7\n"
        )
        report = self.analyze()
        self.assertIn("FutureSecurityThing", report["summary"]["unrecognized_key_sections"])
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(future, serialized)
        self.assertNotIn(hashlib.sha256(bytes.fromhex(future)).hexdigest(), serialized)

    def test_malformed_recognized_key_fails_without_echoing_value(self):
        bad = "THIS-IS-NOT-A-KEY"
        self.write_info(
            "[General]\nAddressType=public\n"
            "[LongTermKey]\n"
            f"Key={bad}\n"
        )
        with self.assertRaises(BlueZKeyEvidenceError) as caught:
            self.analyze()
        self.assertNotIn(bad, str(caught.exception))
        self.assertIn("malformed 128-bit Key material", str(caught.exception))

    def test_info_without_recognized_keys_is_rejected(self):
        self.write_info("[General]\nName=go dawgs\nAddressType=public\n")
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "no recognized"):
            self.analyze()

    def test_missing_persistent_info_is_rejected(self):
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "does not exist"):
            self.analyze()

    def test_symlink_info_is_rejected(self):
        outside = self.root / "outside-info"
        outside.write_text(bonded_info(), encoding="utf-8")
        (self.device / "info").symlink_to(outside)
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "symbolic-link"):
            self.analyze()

    def test_symlink_device_directory_is_rejected(self):
        self.device.rmdir()
        real_device = self.root / "real-device"
        real_device.mkdir()
        (real_device / "info").write_text(bonded_info(), encoding="utf-8")
        self.device.symlink_to(real_device, target_is_directory=True)
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "symbolic-link"):
            self.analyze()

    def test_oversized_source_is_rejected(self):
        info = self.device / "info"
        info.write_bytes(b"A" * (MAX_BLUEZ_SECRET_SOURCE_BYTES + 1))
        os.chmod(info, 0o600)
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "exceeds"):
            self.analyze()

    def test_group_readable_secret_source_is_rejected(self):
        info = self.write_info(bonded_info())
        os.chmod(info, 0o640)
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "access-restricted"):
            self.analyze()

    def test_group_accessible_device_directory_is_rejected(self):
        self.write_info(bonded_info())
        os.chmod(self.device, 0o750)
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "access-restricted"):
            self.analyze()

    def test_invalid_timestamp_is_rejected(self):
        self.write_info(bonded_info())
        with self.assertRaisesRegex(BlueZKeyEvidenceError, "must use UTC"):
            analyze_bluez_keys(
                self.root,
                adapter_address=ADAPTER,
                target_address=TARGET,
                engagement_id="engagement:test",
                authorization_ref="auth:test-security",
                observed_at_utc="2026-09-26T08:30:00-07:00",
            )


if __name__ == "__main__":
    unittest.main()

"""Tests for read-only BlueZ persistent security-state inspection."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from kamal.bluez_security_state import (
    MAX_BLUEZ_METADATA_BYTES,
    BlueZSecurityStateError,
    inspect_bluez_target,
)

ADAPTER = "88:A2:9E:C6:E9:09"
TARGET = "00:1C:4D:45:DE:3F"
NOW = "2026-09-26T07:00:00Z"
LTK = "00112233445566778899AABBCCDDEEFF"
IRK = "FFEEDDCCBBAA99887766554433221100"


def _cache_text(address_type="public"):
    return (
        "[General]\n"
        "Name=go dawgs\n"
        f"AddressType={address_type}\n"
        "Appearance=0x0000\n"
        "\n"
        "[AdvertisingData]\n"
        "0x01=06\n"
    )


def _bonded_info_text():
    return (
        "[General]\n"
        "Name=go dawgs\n"
        "AddressType=public\n"
        "Trusted=true\n"
        "Blocked=false\n"
        "\n"
        "[LongTermKey]\n"
        f"Key={LTK}\n"
        "Authenticated=0\n"
        "EncSize=16\n"
        "EDiv=123\n"
        "Rand=456\n"
        "\n"
        "[IdentityResolvingKey]\n"
        f"Key={IRK}\n"
        "\n"
        "[DeviceID]\n"
        "Source=2\n"
    )


class BlueZSecurityStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "bluetooth"
        self.adapter = self.root / ADAPTER
        self.cache = self.adapter / "cache"
        self.cache.mkdir(parents=True)
        os.chmod(self.root, 0o700)
        os.chmod(self.adapter, 0o700)
        os.chmod(self.cache, 0o700)

    def write_cache(self, text=None):
        path = self.cache / TARGET
        path.write_text(text or _cache_text(), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def write_info(self, text):
        device = self.adapter / TARGET
        device.mkdir(exist_ok=True)
        os.chmod(device, 0o700)
        path = device / "info"
        path.write_text(text, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def inspect(self):
        return inspect_bluez_target(
            self.root,
            adapter_address=ADAPTER.lower(),
            target_address=TARGET.lower(),
            engagement_id="engagement:test",
            authorization_ref="auth:test-security",
            observed_at_utc=NOW,
        )

    def test_cache_only_preserves_unknown_bond_state(self):
        self.write_cache()
        report = self.inspect()
        self.assertTrue(report["records"]["cache"]["present"])
        self.assertFalse(report["records"]["persistent"]["present"])
        self.assertIsNone(report["security_state"]["state"]["bonded"])
        self.assertEqual(report["target"]["address"], TARGET)
        self.assertEqual(report["target"]["address_type"], "public")
        self.assertFalse(report["execution"]["rf_performed"])
        self.assertFalse(report["execution"]["network_performed"])
        self.assertFalse(report["execution"]["mutated_bluez_state"])
        self.assertTrue(
            any("absence of stored state" in item for item in report["limitations"])
        )

    def test_bonded_store_reports_metadata_without_raw_keys(self):
        self.write_cache()
        info = self.write_info(_bonded_info_text())
        before = info.read_bytes()
        report = self.inspect()
        after = info.read_bytes()
        self.assertEqual(before, after)

        persistent = report["persistent_security"]
        self.assertTrue(persistent["persistent_record_present"])
        self.assertEqual(
            persistent["recognized_key_sections_present"],
            ["IdentityResolvingKey", "LongTermKey"],
        )
        self.assertEqual(
            persistent["key_classes_with_material_present"], ["irk", "ltk"]
        )
        self.assertEqual(persistent["key_material_field_count"], 2)
        self.assertTrue(persistent["le_ltk_present"])
        self.assertTrue(persistent["irk_present"])
        self.assertFalse(persistent["br_edr_link_key_present"])
        self.assertFalse(persistent["signing_key_present"])
        self.assertTrue(report["security_state"]["state"]["bonded"])
        self.assertTrue(report["security_state"]["state"]["trusted"])
        self.assertIsNone(report["security_state"]["state"]["paired"])
        self.assertIsNone(report["security_state"]["state"]["connected"])
        self.assertIsNone(report["security_state"]["state"]["encrypted"])

        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(LTK, serialized)
        self.assertNotIn(IRK, serialized)
        self.assertEqual(
            report["records"]["persistent"]["redacted_secret_value_fields"], 2
        )
        long_term = next(
            item
            for item in report["records"]["persistent"]["key_sections"]
            if item["section"] == "LongTermKey"
        )
        self.assertTrue(long_term["key_field_present"])
        self.assertEqual(long_term["metadata"]["encryption_size"], "16")
        self.assertEqual(long_term["metadata"]["authenticated"], "0")

    def test_info_without_key_sections_records_no_persisted_bond(self):
        self.write_cache()
        self.write_info(
            "[General]\nName=go dawgs\nAddressType=public\nTrusted=false\n"
        )
        report = self.inspect()
        self.assertFalse(report["security_state"]["state"]["bonded"])
        self.assertFalse(report["security_state"]["state"]["trusted"])
        self.assertEqual(
            report["persistent_security"]["key_classes_with_material_present"], []
        )

    def test_security_section_without_key_does_not_claim_bond(self):
        self.write_cache()
        self.write_info(
            "[General]\nAddressType=public\nTrusted=false\n"
            "[LongTermKey]\nAuthenticated=0\nEncSize=16\n"
        )
        report = self.inspect()
        self.assertIsNone(report["security_state"]["state"]["bonded"])
        self.assertTrue(
            any("without a Key field" in item for item in report["limitations"])
        )

    def test_static_bluez_address_type_normalizes_to_random(self):
        self.write_cache(_cache_text(address_type="static"))
        report = self.inspect()
        self.assertEqual(report["target"]["address_type"], "random")
        self.assertEqual(
            report["records"]["cache"]["general"]["address_type_raw"], "static"
        )

    def test_source_file_hash_is_exact(self):
        cache = self.write_cache()
        raw = cache.read_bytes()
        report = self.inspect()
        self.assertEqual(
            report["records"]["cache"]["artifact"]["sha256"],
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(
            report["security_state"]["source"]["artifact_ref"],
            "sha256:" + hashlib.sha256(raw).hexdigest(),
        )

    def test_unrecognized_section_key_value_is_still_redacted(self):
        self.write_cache(
            "[General]\nAddressType=public\n"
            "[FutureSecurityThing]\nKey=SUPERSECRET\nOther=metadata\n"
        )
        report = self.inspect()
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("SUPERSECRET", serialized)
        self.assertEqual(
            report["records"]["cache"]["redacted_secret_value_fields"], 1
        )
        self.assertIn(
            "FutureSecurityThing", report["records"]["cache"]["unrecognized_sections"]
        )

    def test_target_absent_is_rejected(self):
        with self.assertRaisesRegex(BlueZSecurityStateError, "not present"):
            self.inspect()

    def test_symlink_info_record_is_rejected(self):
        self.write_cache()
        device = self.adapter / TARGET
        device.mkdir()
        real = self.root / "outside-info"
        real.write_text(_bonded_info_text(), encoding="utf-8")
        (device / "info").symlink_to(real)
        with self.assertRaisesRegex(BlueZSecurityStateError, "symbolic-link"):
            self.inspect()

    def test_symlink_device_directory_is_rejected(self):
        self.write_cache()
        real_device = self.root / "real-device"
        real_device.mkdir()
        (real_device / "info").write_text(_bonded_info_text(), encoding="utf-8")
        (self.adapter / TARGET).symlink_to(real_device, target_is_directory=True)
        with self.assertRaisesRegex(BlueZSecurityStateError, "symbolic-link directory"):
            self.inspect()

    def test_oversized_record_is_rejected(self):
        path = self.cache / TARGET
        path.write_bytes(b"A" * (MAX_BLUEZ_METADATA_BYTES + 1))
        with self.assertRaisesRegex(BlueZSecurityStateError, "exceeds"):
            self.inspect()

    def test_duplicate_section_is_rejected(self):
        self.write_cache("[General]\nAddressType=public\n[General]\nName=x\n")
        with self.assertRaisesRegex(BlueZSecurityStateError, "duplicate section"):
            self.inspect()

    def test_invalid_timestamp_is_rejected(self):
        self.write_cache()
        with self.assertRaisesRegex(BlueZSecurityStateError, "must use UTC"):
            inspect_bluez_target(
                self.root,
                adapter_address=ADAPTER,
                target_address=TARGET,
                engagement_id="engagement:test",
                authorization_ref="auth:test-security",
                observed_at_utc="2026-09-26T07:00:00-07:00",
            )


if __name__ == "__main__":
    unittest.main()

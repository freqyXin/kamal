"""Tests for BLE security-state and key-aware evidence contracts."""

import copy
import unittest

from kamal.active_contracts import (
    ContractValidationError,
    build_gatt_operation_plan,
)
from kamal.bluetooth_security import (
    BLUETOOTH_SECURITY_OPERATION_CLASSES,
    BluetoothSecurityContractError,
    operation_policy,
    validate_bluetooth_key_evidence,
    validate_bluetooth_security_state,
    validate_decryption_derivation,
    validate_packet_observation,
    validate_pairing_session,
    validate_secret_evidence_artifact,
)


DIGEST = "a" * 64
REQUEST_DIGEST = "b" * 64
NOW = "2026-09-25T05:00:00Z"


def target():
    return {
        "address": "aa:bb:cc:dd:ee:ff",
        "address_type": "public",
    }


def pairing_session():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_pairing_session",
        "pairing_session_id": "pairing:test-001",
        "engagement_id": "engagement:test",
        "authorization_ref": "auth:test-security",
        "target": target(),
        "started_at_utc": "2026-09-25T05:00:00Z",
        "completed_at_utc": "2026-09-25T05:00:05Z",
        "status": "completed",
        "requested": {"pair": True, "bond": True},
        "observed": {
            "paired_before": False,
            "bonded_before": False,
            "trusted_before": False,
            "paired_after": True,
            "bonded_after": True,
            "trusted_after": False,
            "connected_after": True,
            "encrypted_after": True,
        },
        "security": {
            "authenticated": False,
            "secure_connections": True,
            "encryption_size": 16,
            "association_model": "just_works",
        },
        "evidence": ["artifact:bluez-mgmt", "artifact:pairing-pcap"],
        "limitations": ["application authorization not assessed"],
    }


def security_state():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_security_state",
        "security_state_id": "security-state:test-001",
        "engagement_id": "engagement:test",
        "authorization_ref": "auth:test-security",
        "target": target(),
        "observed_at_utc": "2026-09-25T05:00:06Z",
        "source": {
            "kind": "bluez_store",
            "artifact_ref": "artifact:bluez-store-snapshot",
        },
        "state": {
            "paired": True,
            "bonded": True,
            "trusted": False,
            "connected": False,
            "encrypted": None,
        },
        "key_evidence_refs": ["key-evidence:ltk-001", "key-evidence:irk-001"],
        "limitations": ["encrypted is unknown while disconnected"],
    }


def key_evidence():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_key_evidence",
        "key_evidence_id": "key-evidence:ltk-001",
        "engagement_id": "engagement:test",
        "authorization_ref": "auth:test-security",
        "target": target(),
        "pairing_session_ref": "pairing:test-001",
        "key_class": "ltk",
        "key_bytes": 16,
        "key_fingerprint_sha256": "c" * 64,
        "authenticated": False,
        "secure_connections": True,
        "encryption_size": 16,
        "debug_key": False,
        "source": {
            "kind": "bluez_mgmt",
            "artifact_ref": "artifact:mgmt-key-event",
        },
        "secret_artifact_ref": "secret-artifact:bond-001",
        "raw_key_embedded": False,
        "limitations": [],
    }


def secret_artifact():
    return {
        "schema_version": "0.12.0",
        "record_type": "secret_evidence_artifact",
        "artifact_id": "secret-artifact:bond-001",
        "engagement_id": "engagement:test",
        "path": "/restricted/engagement-test/bond-001.bin",
        "sha256": "d" * 64,
        "byte_size": 128,
        "sensitivity": "highly_restricted",
        "secret_classes": ["ltk", "irk"],
        "storage_state": "encrypted_at_rest",
        "contains_secret_material": True,
        "raw_secret_embedded_in_metadata": False,
        "limitations": [],
    }


def packet_observation():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_packet_observation",
        "packet_observation_id": "packet:1844",
        "source_capture_sha256": "e" * 64,
        "frame_number": 1844,
        "protocol": "att",
        "direction": "responder_to_initiator",
        "decrypted": True,
        "decryption_derivation_ref": "derivation:test-001",
        "directly_observed": True,
        "opcode": "Error Response",
        "error_code": "0x08",
        "summary": "ATT Error Response: Insufficient Authorization",
    }


def derivation():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_decryption_derivation",
        "derivation_id": "derivation:test-001",
        "engagement_id": "engagement:test",
        "authorization_ref": "auth:test-security",
        "created_at_utc": "2026-09-25T05:01:00Z",
        "source_capture": {
            "artifact_ref": "artifact:pairing-pcap",
            "sha256": "e" * 64,
        },
        "key_evidence": [
            {
                "key_evidence_ref": "key-evidence:ltk-001",
                "key_fingerprint_sha256": "c" * 64,
            }
        ],
        "decoder": {"tool": "tshark", "version": "4.4.0"},
        "result": {
            "attempted": True,
            "succeeded": True,
            "frames_decrypted": 12,
            "error": None,
        },
        "packet_observation_refs": ["packet:1844"],
        "execution": {
            "status": "offline_derivation",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [],
    }


def active_authorization():
    return {
        "schema_version": "0.12.0",
        "record_type": "authorization_scope",
        "authorization_id": "auth:test-001",
        "engagement_id": "engagement:test",
        "owner": "Example Device Owner",
        "operator": "freqy",
        "location": "authorized lab",
        "issued_at_utc": "2026-09-25T03:00:00Z",
        "not_before_utc": "2026-09-25T04:00:00Z",
        "expires_at_utc": "2026-09-25T06:00:00Z",
        "targets": [
            {
                "protocol": "ble",
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "public",
                "label": "owned test device",
            }
        ],
        "allowed_operations": ["read_characteristic"],
        "constraints": {
            "max_operations": 1,
            "max_payload_bytes": 1,
            "max_timeout_seconds": 8,
            "max_subscription_seconds": 1,
            "allow_writes": False,
            "allow_write_without_response": False,
        },
        "approval": {
            "approver": "Example Device Owner",
            "approved_at_utc": "2026-09-25T03:30:00Z",
            "basis": "lab authorization ticket TEST-001",
        },
    }


class BluetoothSecurityContractTests(unittest.TestCase):
    def test_operation_taxonomy_is_non_executing_metadata(self):
        self.assertIn("pair_target", BLUETOOTH_SECURITY_OPERATION_CLASSES)
        policy = operation_policy("pair_target")
        self.assertEqual(policy["execution_domain"], "active_rf")
        self.assertTrue(policy["transmit_capable"])
        self.assertTrue(policy["mutates_security_state"])
        self.assertFalse(policy["requires_secret_access"])

    def test_pair_target_is_not_silently_added_to_gatt_planner(self):
        request = {
            "schema_version": "0.12.0",
            "record_type": "gatt_operation_request",
            "plan_id": "plan:test",
            "operations": [
                {
                    "operation_id": "op:pair",
                    "operation_type": "pair_target",
                    "target": target(),
                    "selector": {"service_uuid": "1800", "characteristic_uuid": "2a00"},
                    "timeout_seconds": 5,
                }
            ],
        }
        with self.assertRaisesRegex(ContractValidationError, "Unsupported active operation"):
            build_gatt_operation_plan(
                active_authorization(),
                request,
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )

    def test_pairing_session_normalizes_without_mutating_input(self):
        value = pairing_session()
        before = copy.deepcopy(value)
        normalized = validate_pairing_session(value)
        self.assertEqual(value, before)
        self.assertEqual(normalized["target"]["address"], "AA:BB:CC:DD:EE:FF")
        self.assertTrue(normalized["observed"]["bonded_after"])
        self.assertEqual(normalized["security"]["encryption_size"], 16)

    def test_bond_requires_pair(self):
        value = pairing_session()
        value["requested"] = {"pair": False, "bond": True}
        with self.assertRaisesRegex(BluetoothSecurityContractError, "requires requested.pair"):
            validate_pairing_session(value)

    def test_terminal_pairing_status_requires_completion_time(self):
        value = pairing_session()
        value["completed_at_utc"] = None
        with self.assertRaisesRegex(BluetoothSecurityContractError, "completed_at_utc is required"):
            validate_pairing_session(value)

    def test_nonterminal_pairing_status_rejects_completion_time(self):
        value = pairing_session()
        value["status"] = "attempted"
        with self.assertRaisesRegex(BluetoothSecurityContractError, "must be null"):
            validate_pairing_session(value)

    def test_supported_bluetooth_keys_are_128_bit_material(self):
        value = key_evidence()
        value["key_bytes"] = 15
        with self.assertRaisesRegex(BluetoothSecurityContractError, "between 16 and 16"):
            validate_bluetooth_key_evidence(value)

    def test_security_state_distinguishes_unknown_from_false(self):
        normalized = validate_bluetooth_security_state(security_state())
        self.assertIsNone(normalized["state"]["encrypted"])
        self.assertFalse(normalized["state"]["trusted"])

    def test_key_evidence_contains_fingerprint_not_raw_secret(self):
        normalized = validate_bluetooth_key_evidence(key_evidence())
        self.assertEqual(normalized["key_class"], "ltk")
        self.assertEqual(normalized["key_bytes"], 16)
        self.assertEqual(normalized["key_fingerprint_sha256"], "c" * 64)
        self.assertFalse(normalized["raw_key_embedded"])

    def test_key_evidence_rejects_raw_key_hex(self):
        value = key_evidence()
        value["raw_key_hex"] = "00" * 16
        with self.assertRaisesRegex(BluetoothSecurityContractError, "raw secret"):
            validate_bluetooth_key_evidence(value)

    def test_non_ltk_cannot_claim_encryption_size(self):
        value = key_evidence()
        value["key_class"] = "irk"
        with self.assertRaisesRegex(BluetoothSecurityContractError, "only valid for ltk"):
            validate_bluetooth_key_evidence(value)

    def test_secret_artifact_is_highly_restricted_metadata(self):
        normalized = validate_secret_evidence_artifact(secret_artifact())
        self.assertEqual(normalized["sensitivity"], "highly_restricted")
        self.assertTrue(normalized["contains_secret_material"])
        self.assertFalse(normalized["raw_secret_embedded_in_metadata"])

    def test_secret_artifact_rejects_duplicate_secret_classes(self):
        value = secret_artifact()
        value["secret_classes"] = ["ltk", "ltk"]
        with self.assertRaisesRegex(BluetoothSecurityContractError, "must be unique"):
            validate_secret_evidence_artifact(value)

    def test_packet_observation_requires_actual_capture_observation(self):
        value = packet_observation()
        value["directly_observed"] = False
        with self.assertRaisesRegex(BluetoothSecurityContractError, "must be directly observed"):
            validate_packet_observation(value)

    def test_decrypted_packet_requires_derivation_reference(self):
        value = packet_observation()
        value["decryption_derivation_ref"] = None
        with self.assertRaises(BluetoothSecurityContractError):
            validate_packet_observation(value)

    def test_decryption_derivation_is_offline_and_hash_bound(self):
        normalized = validate_decryption_derivation(derivation())
        self.assertEqual(normalized["source_capture"]["sha256"], "e" * 64)
        self.assertEqual(
            normalized["key_evidence"][0]["key_fingerprint_sha256"], "c" * 64
        )
        self.assertFalse(normalized["execution"]["rf_performed"])
        self.assertFalse(normalized["execution"]["network_performed"])

    def test_decryption_derivation_rejects_secret_bytes(self):
        value = derivation()
        value["decoder"]["secret_bytes"] = "do-not-log"
        with self.assertRaisesRegex(BluetoothSecurityContractError, "raw secret"):
            validate_decryption_derivation(value)

    def test_failed_decryption_cannot_claim_decrypted_frames(self):
        value = derivation()
        value["result"] = {
            "attempted": True,
            "succeeded": False,
            "frames_decrypted": 1,
            "error": "MIC verification failed",
        }
        with self.assertRaisesRegex(BluetoothSecurityContractError, "must be zero"):
            validate_decryption_derivation(value)


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest
from copy import deepcopy

from kamal.pairing_contracts import (
    PairingContractError,
    build_pairing_plan,
    validate_pairing_authorization,
    validate_pairing_plan,
)


TARGET = "AA:BB:CC:DD:EE:FF"


def auth():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_pairing_authorization",
        "authorization_id": "pair-auth-1",
        "engagement_id": "eng-1",
        "owner": "Lab",
        "operator": "Tester",
        "location": "Controlled lab",
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "not_before_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "2099-01-01T00:00:00Z",
        "target": {
            "protocol": "ble",
            "address": TARGET,
            "address_type": "public",
            "label": "target",
        },
        "allowed_operations": ["pair_target", "establish_bond"],
        "constraints": {
            "max_attempts": 1,
            "max_discovery_seconds": 20,
            "max_pairing_seconds": 90,
            "max_disconnect_seconds": 10,
            "require_disconnect_after": True,
            "require_unpaired_before": True,
            "require_unbonded_before": True,
            "allowed_agent_modes": ["external_default", "no_input_no_output"],
        },
        "approval": {
            "approver": "Owner",
            "approved_at_utc": "2026-01-01T00:00:00Z",
            "basis": "owned lab target",
        },
    }


def request(*, bond=True, agent="no_input_no_output"):
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_pairing_request",
        "plan_id": "pair-plan-1",
        "pairing_session_id": "pair-session-1",
        "target": {"address": TARGET, "address_type": "public"},
        "request_bond": bond,
        "agent_mode": agent,
        "timeouts": {
            "discovery_seconds": 10,
            "pairing_seconds": 60,
            "disconnect_seconds": 5,
        },
    }


def build(a=None, r=None):
    return build_pairing_plan(
        a or auth(),
        r or request(),
        authorization_sha256=hashlib.sha256(b"auth").hexdigest(),
        request_sha256=hashlib.sha256(b"request").hexdigest(),
        created_at_utc="2026-09-26T12:00:00Z",
    )


class PairingContractTests(unittest.TestCase):
    def test_valid_authorization_is_detached(self):
        raw = auth()
        original = deepcopy(raw)
        normalized = validate_pairing_authorization(
            raw, at_utc="2026-09-26T12:00:00Z"
        )
        self.assertEqual(raw, original)
        self.assertEqual(normalized["target"]["address"], TARGET)
        self.assertEqual(normalized["constraints"]["max_attempts"], 1)

    def test_pair_target_must_be_explicitly_authorized(self):
        a = auth()
        a["allowed_operations"] = ["establish_bond"]
        with self.assertRaises(PairingContractError):
            validate_pairing_authorization(a, at_utc="2026-09-26T12:00:00Z")

    def test_gatt_operation_is_rejected(self):
        a = auth()
        a["allowed_operations"].append("write_characteristic")
        with self.assertRaises(PairingContractError):
            validate_pairing_authorization(a, at_utc="2026-09-26T12:00:00Z")

    def test_unknown_address_type_is_rejected(self):
        a = auth()
        a["target"]["address_type"] = "unknown"
        with self.assertRaises(PairingContractError):
            validate_pairing_authorization(a, at_utc="2026-09-26T12:00:00Z")

    def test_more_than_one_attempt_is_rejected(self):
        a = auth()
        a["constraints"]["max_attempts"] = 2
        with self.assertRaises(PairingContractError):
            validate_pairing_authorization(a, at_utc="2026-09-26T12:00:00Z")

    def test_disconnect_after_is_mandatory(self):
        a = auth()
        a["constraints"]["require_disconnect_after"] = False
        with self.assertRaises(PairingContractError):
            validate_pairing_authorization(a, at_utc="2026-09-26T12:00:00Z")

    def test_expired_authorization_is_rejected(self):
        a = auth()
        a["expires_at_utc"] = "2026-01-02T00:00:00Z"
        with self.assertRaises(PairingContractError):
            validate_pairing_authorization(a, at_utc="2026-09-26T12:00:00Z")

    def test_bond_request_requires_separate_operation(self):
        a = auth()
        a["allowed_operations"] = ["pair_target"]
        with self.assertRaises(PairingContractError):
            build(a=a)

    def test_pair_only_request_does_not_require_bond_operation(self):
        a = auth()
        a["allowed_operations"] = ["pair_target"]
        plan = build(a=a, r=request(bond=False))
        self.assertEqual(plan["requested"], {"pair": True, "bond": False})

    def test_target_must_match_exact_authorization(self):
        r = request()
        r["target"]["address"] = "11:22:33:44:55:66"
        with self.assertRaises(PairingContractError):
            build(r=r)

    def test_agent_mode_must_be_authorized(self):
        a = auth()
        a["constraints"]["allowed_agent_modes"] = ["external_default"]
        with self.assertRaises(PairingContractError):
            build(a=a)

    def test_timeouts_are_bounded_by_authorization(self):
        r = request()
        r["timeouts"]["pairing_seconds"] = 91
        with self.assertRaises(PairingContractError):
            build(r=r)

    def test_plan_is_explicitly_state_mutating_active_rf(self):
        plan = build()
        self.assertEqual(
            plan["execution"],
            {
                "execution_domain": "active_rf",
                "transmit_capable": True,
                "mutates_security_state": True,
            },
        )
        self.assertTrue(plan["cleanup"]["disconnect_after"])

    def test_plan_hash_binding_is_verified(self):
        a = auth()
        plan = build(a=a)
        with self.assertRaises(PairingContractError):
            validate_pairing_plan(
                plan,
                a,
                authorization_sha256="f" * 64,
                at_utc="2026-09-26T12:00:00Z",
            )

    def test_plan_does_not_mutate_inputs(self):
        a = auth()
        r = request()
        a0 = deepcopy(a)
        r0 = deepcopy(r)
        build(a=a, r=r)
        self.assertEqual(a, a0)
        self.assertEqual(r, r0)


if __name__ == "__main__":
    unittest.main()

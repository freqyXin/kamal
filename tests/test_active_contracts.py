"""Tests for active BLE authorization and typed GATT operation contracts."""

import unittest
from copy import deepcopy

from kamal.active_contracts import (
    ContractValidationError,
    build_gatt_operation_plan,
    validate_authorization_scope,
    validate_gatt_survey_authorization,
)


NOW = "2026-09-25T05:00:00Z"
DIGEST = "a" * 64
REQUEST_DIGEST = "b" * 64


def authorization():
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
                "address": "aa:bb:cc:dd:ee:ff",
                "address_type": "public",
                "label": "owned test device",
            }
        ],
        "allowed_operations": [
            "read_characteristic",
            "read_descriptor",
            "subscribe_notifications",
        ],
        "constraints": {
            "max_operations": 4,
            "max_payload_bytes": 32,
            "max_timeout_seconds": 8,
            "max_subscription_seconds": 30,
            "allow_writes": False,
            "allow_write_without_response": False,
        },
        "approval": {
            "approver": "Example Device Owner",
            "approved_at_utc": "2026-09-25T03:30:00Z",
            "basis": "lab authorization ticket TEST-001",
        },
    }


def all_discovered_authorization():
    auth = authorization()
    auth["targets"][0]["address_type"] = "unknown"
    auth["allowed_operations"] = ["enumerate_gatt_metadata"]
    auth["constraints"]["allow_writes"] = False
    auth["constraints"]["allow_write_without_response"] = False
    auth["survey_scope"] = {
        "mode": "all_discovered",
        "scope_acknowledged": True,
    }
    return auth


def request(*operations):
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_operation_request",
        "plan_id": "plan:test-001",
        "operations": list(operations),
    }


def read_characteristic(operation_id="op:read"):
    return {
        "operation_id": operation_id,
        "operation_type": "read_characteristic",
        "target": {
            "address": "AA:BB:CC:DD:EE:FF",
            "address_type": "public",
        },
        "selector": {
            "service_uuid": "180f",
            "characteristic_uuid": "2a19",
        },
        "timeout_seconds": 5,
    }


class ActiveContractTests(unittest.TestCase):
    def test_valid_read_plan_is_contract_only(self):
        plan = build_gatt_operation_plan(
            authorization(),
            request(read_characteristic()),
            authorization_sha256=DIGEST,
            request_sha256=REQUEST_DIGEST,
            created_at_utc=NOW,
        )
        self.assertEqual(plan["record_type"], "gatt_operation_plan")
        self.assertEqual(plan["authorization_ref"], "auth:test-001")
        self.assertEqual(plan["authorization_provenance"]["sha256"], DIGEST)
        self.assertEqual(plan["request_provenance"]["sha256"], REQUEST_DIGEST)
        self.assertEqual(plan["operations"][0]["selector"]["service_uuid"], "180f")
        self.assertFalse(plan["execution"]["rf_performed"])
        self.assertEqual(plan["execution"]["status"], "contract_only")

    def test_address_is_normalized_but_not_identity(self):
        normalized = validate_authorization_scope(authorization(), at_utc=NOW)
        self.assertEqual(normalized["targets"][0]["address"], "AA:BB:CC:DD:EE:FF")
        self.assertNotIn("asset_id", normalized["targets"][0])
        self.assertNotIn("stable_identity", normalized["targets"][0])

    def test_expired_authorization_fails_closed(self):
        with self.assertRaisesRegex(ContractValidationError, "expired"):
            validate_authorization_scope(
                authorization(), at_utc="2026-09-25T06:00:00Z"
            )

    def test_not_yet_valid_authorization_fails_closed(self):
        with self.assertRaisesRegex(ContractValidationError, "not yet valid"):
            validate_authorization_scope(
                authorization(), at_utc="2026-09-25T03:59:59Z"
            )

    def test_target_outside_scope_is_rejected(self):
        operation = read_characteristic()
        operation["target"]["address"] = "00:11:22:33:44:55"
        with self.assertRaisesRegex(ContractValidationError, "outside authorization scope"):
            build_gatt_operation_plan(
                authorization(),
                request(operation),
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )

    def test_unlisted_operation_class_is_rejected(self):
        operation = read_characteristic()
        operation["operation_type"] = "fuzz_characteristic"
        with self.assertRaisesRegex(ContractValidationError, "Unsupported active operation"):
            build_gatt_operation_plan(
                authorization(),
                request(operation),
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )


    def test_metadata_enumeration_can_be_authorized_without_becoming_plan_operation(self):
        auth = authorization()
        auth["allowed_operations"].append("enumerate_gatt_metadata")
        auth["targets"][0]["address_type"] = "unknown"

        normalized = validate_gatt_survey_authorization(
            auth,
            target_addresses=["aa:bb:cc:dd:ee:ff"],
            timeout_seconds=5,
            max_targets=1,
            at_utc=NOW,
        )
        self.assertIn(
            "enumerate_gatt_metadata",
            normalized["allowed_operations"],
        )

        operation = read_characteristic()
        operation["operation_type"] = "enumerate_gatt_metadata"
        operation["target"]["address_type"] = "unknown"
        with self.assertRaisesRegex(
            ContractValidationError,
            "Unsupported active operation class",
        ):
            build_gatt_operation_plan(
                auth,
                request(operation),
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )

    def test_metadata_survey_requires_explicit_operation_permission(self):
        auth = authorization()
        auth["targets"][0]["address_type"] = "unknown"

        with self.assertRaisesRegex(
            ContractValidationError,
            "enumerate_gatt_metadata is not authorized",
        ):
            validate_gatt_survey_authorization(
                auth,
                target_addresses=["AA:BB:CC:DD:EE:FF"],
                timeout_seconds=5,
                max_targets=1,
                at_utc=NOW,
            )

    def test_metadata_survey_requires_unknown_address_type(self):
        auth = authorization()
        auth["allowed_operations"].append("enumerate_gatt_metadata")

        with self.assertRaisesRegex(
            ContractValidationError,
            "address_type=unknown",
        ):
            validate_gatt_survey_authorization(
                auth,
                target_addresses=["AA:BB:CC:DD:EE:FF"],
                timeout_seconds=5,
                max_targets=1,
                at_utc=NOW,
            )

    def test_metadata_survey_enforces_target_count_and_timeout(self):
        auth = authorization()
        auth["allowed_operations"].append("enumerate_gatt_metadata")
        auth["targets"][0]["address_type"] = "unknown"
        auth["constraints"]["max_operations"] = 1
        auth["constraints"]["max_timeout_seconds"] = 4

        with self.assertRaisesRegex(ContractValidationError, "target limit"):
            validate_gatt_survey_authorization(
                auth,
                timeout_seconds=4,
                max_targets=2,
                at_utc=NOW,
            )

        with self.assertRaisesRegex(ContractValidationError, "timeout"):
            validate_gatt_survey_authorization(
                auth,
                timeout_seconds=5,
                max_targets=1,
                at_utc=NOW,
            )

    def test_all_discovered_metadata_scope_accepts_rotated_runtime_address(self):
        auth = all_discovered_authorization()

        normalized = validate_gatt_survey_authorization(
            auth,
            target_addresses=["11:22:33:44:55:66"],
            timeout_seconds=5,
            max_targets=1,
            policy_mode="all_discovered",
            scope_acknowledged=True,
            at_utc=NOW,
        )

        self.assertEqual(
            normalized["survey_scope"],
            {
                "mode": "all_discovered",
                "scope_acknowledged": True,
            },
        )

    def test_all_discovered_metadata_scope_requires_matching_policy(self):
        auth = all_discovered_authorization()

        with self.assertRaisesRegex(
            ContractValidationError,
            "requires acknowledged all-discovered survey policy",
        ):
            validate_gatt_survey_authorization(
                auth,
                target_addresses=["11:22:33:44:55:66"],
                timeout_seconds=5,
                max_targets=1,
                policy_mode="allowlist",
                scope_acknowledged=False,
                at_utc=NOW,
            )

    def test_all_discovered_scope_cannot_authorize_typed_operations(self):
        auth = all_discovered_authorization()
        auth["allowed_operations"].append("read_characteristic")

        with self.assertRaisesRegex(
            ContractValidationError,
            "only valid for enumerate_gatt_metadata",
        ):
            validate_authorization_scope(auth, at_utc=NOW)

    def test_all_discovered_scope_requires_unknown_recorded_target_type(self):
        auth = all_discovered_authorization()
        auth["targets"][0]["address_type"] = "public"

        with self.assertRaisesRegex(
            ContractValidationError,
            "requires address_type=unknown",
        ):
            validate_authorization_scope(auth, at_utc=NOW)

    def test_exact_scope_still_rejects_rotated_runtime_address(self):
        auth = authorization()
        auth["targets"][0]["address_type"] = "unknown"
        auth["allowed_operations"].append("enumerate_gatt_metadata")

        with self.assertRaisesRegex(
            ContractValidationError,
            "outside authorization scope",
        ):
            validate_gatt_survey_authorization(
                auth,
                target_addresses=["11:22:33:44:55:66"],
                timeout_seconds=5,
                max_targets=1,
                policy_mode="all_discovered",
                scope_acknowledged=True,
                at_utc=NOW,
            )

    def test_write_requires_layered_opt_in(self):
        auth = authorization()
        auth["allowed_operations"].append("write_characteristic")
        with self.assertRaisesRegex(ContractValidationError, "allow_writes=true"):
            validate_authorization_scope(auth, at_utc=NOW)

    def test_authorized_write_payload_is_bounded(self):
        auth = authorization()
        auth["allowed_operations"].append("write_characteristic")
        auth["constraints"]["allow_writes"] = True
        operation = {
            "operation_id": "op:write",
            "operation_type": "write_characteristic",
            "target": {
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "public",
            },
            "selector": {"handle": 42},
            "timeout_seconds": 4,
            "payload_hex": "A1b2",
            "write_mode": "request",
        }
        plan = build_gatt_operation_plan(
            auth,
            request(operation),
            authorization_sha256=DIGEST,
            request_sha256=REQUEST_DIGEST,
            created_at_utc=NOW,
        )
        self.assertEqual(plan["operations"][0]["payload_hex"], "a1b2")
        self.assertEqual(plan["operations"][0]["payload_bytes"], 2)
        self.assertEqual(plan["integrity"]["write_operation_count"], 1)

    def test_oversized_write_payload_is_rejected(self):
        auth = authorization()
        auth["allowed_operations"].append("write_characteristic")
        auth["constraints"]["allow_writes"] = True
        auth["constraints"]["max_payload_bytes"] = 1
        operation = {
            "operation_id": "op:write",
            "operation_type": "write_characteristic",
            "target": {
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "public",
            },
            "selector": {"handle": 42},
            "timeout_seconds": 4,
            "payload_hex": "0102",
            "write_mode": "request",
        }
        with self.assertRaisesRegex(ContractValidationError, "payload limit"):
            build_gatt_operation_plan(
                auth,
                request(operation),
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )

    def test_write_without_response_requires_separate_permission(self):
        auth = authorization()
        auth["allowed_operations"].append("write_characteristic")
        auth["constraints"]["allow_writes"] = True
        operation = {
            "operation_id": "op:write",
            "operation_type": "write_characteristic",
            "target": {
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "public",
            },
            "selector": {"handle": 42},
            "timeout_seconds": 4,
            "payload_hex": "01",
            "write_mode": "command",
        }
        with self.assertRaisesRegex(ContractValidationError, "without-response"):
            build_gatt_operation_plan(
                auth,
                request(operation),
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )

    def test_subscription_carries_cleanup_contract(self):
        operation = {
            "operation_id": "op:notify",
            "operation_type": "subscribe_notifications",
            "target": {
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "public",
            },
            "selector": {
                "service_uuid": "180f",
                "characteristic_uuid": "2a19",
            },
            "timeout_seconds": 5,
            "duration_seconds": 15,
        }
        plan = build_gatt_operation_plan(
            authorization(),
            request(operation),
            authorization_sha256=DIGEST,
            request_sha256=REQUEST_DIGEST,
            created_at_utc=NOW,
        )
        self.assertTrue(
            plan["operations"][0]["cleanup"]["unsubscribe_required"]
        )

    def test_operation_count_is_bounded(self):
        auth = authorization()
        auth["constraints"]["max_operations"] = 1
        with self.assertRaisesRegex(ContractValidationError, "operation count"):
            build_gatt_operation_plan(
                auth,
                request(read_characteristic("op:1"), read_characteristic("op:2")),
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )

    def test_unknown_authorization_field_is_rejected(self):
        auth = authorization()
        auth["allow_everything"] = True
        with self.assertRaisesRegex(ContractValidationError, "unsupported field"):
            validate_authorization_scope(auth, at_utc=NOW)

    def test_duplicate_operation_ids_are_rejected(self):
        with self.assertRaisesRegex(ContractValidationError, "duplicate operation_id"):
            build_gatt_operation_plan(
                authorization(),
                request(read_characteristic("same"), read_characteristic("same")),
                authorization_sha256=DIGEST,
                request_sha256=REQUEST_DIGEST,
                created_at_utc=NOW,
            )

    def test_operation_order_is_preserved(self):
        first = read_characteristic("op:z-first")
        second = read_characteristic("op:a-second")
        plan = build_gatt_operation_plan(
            authorization(),
            request(first, second),
            authorization_sha256=DIGEST,
            request_sha256=REQUEST_DIGEST,
            created_at_utc=NOW,
        )
        self.assertEqual(
            [item["operation_id"] for item in plan["operations"]],
            ["op:z-first", "op:a-second"],
        )

    def test_input_objects_are_not_mutated(self):
        auth = authorization()
        req = request(read_characteristic())
        auth_before = deepcopy(auth)
        req_before = deepcopy(req)
        build_gatt_operation_plan(
            auth,
            req,
            authorization_sha256=DIGEST,
            request_sha256=REQUEST_DIGEST,
            created_at_utc=NOW,
        )
        self.assertEqual(auth, auth_before)
        self.assertEqual(req, req_before)


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import unittest

from kamal.result_semantics import (
    ResultSemanticsError,
    build_effect_review,
    build_initial_effect_semantics,
    mark_executor_failure,
    mark_executor_success,
    validate_effect_semantics,
    validate_operation_result,
)


def operation_result(semantics=None):
    if semantics is None:
        semantics = mark_executor_success(
            build_initial_effect_semantics("write_characteristic", write_mode="request"),
            "write_characteristic",
            write_mode="request",
        )
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_operation_result",
        "plan_id": "plan-1",
        "operation_id": "op-1",
        "operation_type": "write_characteristic",
        "target": {"address": "AA:BB:CC:DD:EE:FF", "address_type": "public"},
        "transport_success": semantics["transport"]["state"] == "succeeded",
        "application_effect": "not_assessed",
        "effect_semantics": semantics,
        "error": None,
    }


def review(stages=None):
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_effect_review_request",
        "review_id": "review-1",
        "reviewer": "analyst-1",
        "basis": "authorized lab validation",
        "stages": stages or {
            "state_change": {
                "state": "observed",
                "basis": "external indicator changed",
                "evidence": ["video:evidence-1"],
            }
        },
    }


class ResultSemanticsTests(unittest.TestCase):
    def test_initial_semantics_do_not_claim_application_effect(self):
        value = build_initial_effect_semantics("write_characteristic", write_mode="request")
        self.assertEqual(value["transport"]["state"], "not_attempted")
        self.assertEqual(value["application_acknowledgment"]["state"], "not_assessed")
        self.assertEqual(value["state_change"]["state"], "not_assessed")
        self.assertEqual(value["security_effect"]["state"], "not_assessed")

    def test_write_request_success_is_not_application_ack(self):
        value = mark_executor_success(
            build_initial_effect_semantics("write_characteristic", write_mode="request"),
            "write_characteristic",
            write_mode="request",
        )
        self.assertEqual(value["protocol"]["state"], "write_request_completed")
        self.assertTrue(value["protocol"]["response_expected"])
        self.assertFalse(value["protocol"]["att_pdu_directly_observed"])
        self.assertEqual(value["application_acknowledgment"]["state"], "not_assessed")

    def test_write_command_does_not_claim_remote_receipt(self):
        value = mark_executor_success(
            build_initial_effect_semantics("write_characteristic", write_mode="command"),
            "write_characteristic",
            write_mode="command",
        )
        self.assertEqual(value["protocol"]["state"], "write_command_submitted")
        self.assertFalse(value["protocol"]["response_expected"])
        self.assertEqual(value["state_change"]["state"], "not_assessed")

    def test_read_success_records_value_received(self):
        value = mark_executor_success(
            build_initial_effect_semantics("read_characteristic"),
            "read_characteristic",
        )
        self.assertEqual(value["protocol"]["state"], "value_received")
        self.assertEqual(value["security_effect"]["state"], "not_assessed")

    def test_notification_success_distinguishes_no_event(self):
        value = mark_executor_success(
            build_initial_effect_semantics("subscribe_notifications"),
            "subscribe_notifications",
            notification_count=0,
        )
        self.assertEqual(value["protocol"]["state"], "subscription_completed")

    def test_notification_success_records_observed_event(self):
        value = mark_executor_success(
            build_initial_effect_semantics("subscribe_notifications"),
            "subscribe_notifications",
            notification_count=1,
        )
        self.assertEqual(value["protocol"]["state"], "notification_received")

    def test_failure_does_not_infer_security_effect(self):
        value = mark_executor_failure(
            build_initial_effect_semantics("read_characteristic"),
            "TimeoutError: timed out",
        )
        self.assertEqual(value["transport"]["state"], "failed")
        self.assertEqual(value["protocol"]["state"], "failed")
        self.assertEqual(value["security_effect"]["state"], "not_assessed")

    def test_not_assessed_stage_rejects_evidence(self):
        value = build_initial_effect_semantics("read_characteristic")
        value["state_change"]["evidence"] = ["note:x"]
        with self.assertRaises(ResultSemanticsError):
            validate_effect_semantics(value)

    def test_operation_result_rejects_legacy_mismatch(self):
        value = operation_result()
        value["transport_success"] = False
        with self.assertRaisesRegex(ResultSemanticsError, "disagrees"):
            validate_operation_result(value)

    def test_review_is_hash_bound_and_offline(self):
        artifact = build_effect_review(
            operation_result(),
            review(),
            operation_sha256="a" * 64,
            review_sha256="b" * 64,
            reviewed_at_utc="2026-09-25T12:00:00Z",
        )
        self.assertEqual(artifact["operation_provenance"]["sha256"], "a" * 64)
        self.assertEqual(artifact["review_provenance"]["sha256"], "b" * 64)
        self.assertFalse(artifact["execution"]["rf_performed"])
        self.assertFalse(artifact["execution"]["network_performed"])

    def test_review_can_mark_validated_security_effect_only_explicitly(self):
        artifact = build_effect_review(
            operation_result(),
            review({
                "security_effect": {
                    "state": "validated",
                    "basis": "reviewer confirmed authorized security impact",
                    "evidence": ["artifact:validation-1"],
                }
            }),
            operation_sha256="a" * 64,
            review_sha256="b" * 64,
            reviewed_at_utc="2026-09-25T12:00:00Z",
        )
        self.assertEqual(artifact["effect_semantics"]["security_effect"]["state"], "validated")
        self.assertEqual(artifact["effect_semantics"]["state_change"]["state"], "not_assessed")

    def test_review_requires_evidence_for_non_default_stage(self):
        with self.assertRaisesRegex(ResultSemanticsError, "must not be empty"):
            build_effect_review(
                operation_result(),
                review({
                    "application_acknowledgment": {
                        "state": "observed",
                        "basis": "application returned explicit ack",
                        "evidence": [],
                    }
                }),
                operation_sha256="a" * 64,
                review_sha256="b" * 64,
            )

    def test_inputs_are_not_mutated(self):
        op = operation_result()
        req = review()
        before_op = copy.deepcopy(op)
        before_req = copy.deepcopy(req)
        build_effect_review(
            op,
            req,
            operation_sha256="a" * 64,
            review_sha256="b" * 64,
            reviewed_at_utc="2026-09-25T12:00:00Z",
        )
        self.assertEqual(op, before_op)
        self.assertEqual(req, before_req)


if __name__ == "__main__":
    unittest.main()

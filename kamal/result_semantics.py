"""Explicit result/effect semantics for active BLE GATT operations.

The executor can establish transport- and API-visible protocol outcomes. It does
not infer application acknowledgement, device state change, or security impact.
Those higher-level conclusions require a separate, hash-bound analyst review.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from kamal.evidence_contracts import atomic_create_json


RESULT_SEMANTICS_VERSION = "0.12.0"

TRANSPORT_STATES = frozenset({"not_attempted", "succeeded", "failed"})
PROTOCOL_STATES = frozenset(
    {
        "not_observed",
        "value_received",
        "write_request_completed",
        "write_command_submitted",
        "subscription_completed",
        "notification_received",
        "failed",
    }
)
ASSESSMENT_STATES = frozenset({"not_assessed", "observed", "not_observed"})
SECURITY_EFFECT_STATES = frozenset(
    {"not_assessed", "candidate", "validated", "refuted"}
)
REVIEWABLE_STAGES = frozenset(
    {"application_acknowledgment", "state_change", "security_effect"}
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ResultSemanticsError(ValueError):
    """Raised when result/effect semantics or a review artifact is invalid."""


def _utc_text(value, field):
    if value is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        if not value.endswith("Z"):
            raise ResultSemanticsError(f"{field} must use UTC and end with Z")
        try:
            dt = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise ResultSemanticsError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    else:
        raise ResultSemanticsError(f"{field} must be a UTC timestamp")
    if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise ResultSemanticsError(f"{field} must use UTC")
    return dt.isoformat().replace("+00:00", "Z")


def _nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ResultSemanticsError(f"{field} must be a non-empty string")
    return value.strip()


def _sha256(value, field):
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ResultSemanticsError(f"{field} must be a SHA-256 hexadecimal digest")
    return value.lower()


def build_initial_effect_semantics(operation_type, *, write_mode=None):
    """Return the conservative semantics baseline for one planned operation."""
    operation_type = _nonempty(operation_type, "operation_type")
    if operation_type == "write_characteristic":
        if write_mode not in {"request", "command"}:
            raise ResultSemanticsError("write_mode must be request or command")
    elif write_mode is not None:
        raise ResultSemanticsError("write_mode is only valid for write_characteristic")

    return {
        "schema_version": RESULT_SEMANTICS_VERSION,
        "transport": {
            "state": "not_attempted",
            "basis": "executor_not_started",
        },
        "protocol": {
            "state": "not_observed",
            "basis": "no_client_api_outcome_available",
            "att_pdu_directly_observed": False,
            "response_expected": (
                write_mode == "request" if operation_type == "write_characteristic" else None
            ),
        },
        "application_acknowledgment": {
            "state": "not_assessed",
            "basis": None,
            "evidence": [],
        },
        "state_change": {
            "state": "not_assessed",
            "basis": None,
            "evidence": [],
        },
        "security_effect": {
            "state": "not_assessed",
            "basis": None,
            "evidence": [],
        },
    }


def mark_executor_success(semantics, operation_type, *, write_mode=None, notification_count=None):
    """Record only what a successful client-library operation establishes."""
    result = deepcopy(semantics)
    validate_effect_semantics(result)
    result["transport"] = {
        "state": "succeeded",
        "basis": "bleak_client_api_completed_without_exception",
    }

    if operation_type in {"read_characteristic", "read_descriptor"}:
        protocol_state = "value_received"
        basis = "bleak_client_api_returned_gatt_value"
        response_expected = True
    elif operation_type == "write_characteristic" and write_mode == "request":
        protocol_state = "write_request_completed"
        basis = "bleak_write_gatt_char_completed_with_response_true"
        response_expected = True
    elif operation_type == "write_characteristic" and write_mode == "command":
        protocol_state = "write_command_submitted"
        basis = "bleak_write_gatt_char_completed_with_response_false"
        response_expected = False
    elif operation_type == "subscribe_notifications":
        if isinstance(notification_count, bool) or not isinstance(notification_count, int) or notification_count < 0:
            raise ResultSemanticsError("notification_count must be a non-negative integer")
        if notification_count:
            protocol_state = "notification_received"
            basis = "one_or_more_notification_values_delivered_by_client_api"
        else:
            protocol_state = "subscription_completed"
            basis = "subscription_window_completed_without_notification_value"
        response_expected = None
    else:
        raise ResultSemanticsError(f"unsupported operation_type for result semantics: {operation_type}")

    result["protocol"] = {
        "state": protocol_state,
        "basis": basis,
        "att_pdu_directly_observed": False,
        "response_expected": response_expected,
    }
    # Higher semantic layers remain explicitly untouched.
    return validate_effect_semantics(result)


def mark_executor_failure(semantics, error_text):
    """Record an executor/API failure without inventing protocol or application meaning."""
    result = deepcopy(semantics)
    validate_effect_semantics(result)
    error_text = _nonempty(error_text, "error_text")
    result["transport"] = {
        "state": "failed",
        "basis": error_text,
    }
    result["protocol"] = {
        "state": "failed",
        "basis": "executor_or_client_api_raised_before_successful_outcome",
        "att_pdu_directly_observed": False,
        "response_expected": result["protocol"].get("response_expected"),
    }
    return validate_effect_semantics(result)


def validate_effect_semantics(value):
    """Validate and return a detached effect-semantics object."""
    if not isinstance(value, dict):
        raise ResultSemanticsError("effect_semantics must be an object")
    allowed_top = {
        "schema_version", "transport", "protocol", "application_acknowledgment",
        "state_change", "security_effect",
    }
    unknown = sorted(set(value) - allowed_top)
    if unknown:
        raise ResultSemanticsError("effect_semantics contains unsupported fields: " + ", ".join(unknown))
    if value.get("schema_version") != RESULT_SEMANTICS_VERSION:
        raise ResultSemanticsError("unsupported effect semantics schema_version")

    transport = value.get("transport")
    if not isinstance(transport, dict) or set(transport) != {"state", "basis"}:
        raise ResultSemanticsError("transport semantics are malformed")
    if transport.get("state") not in TRANSPORT_STATES:
        raise ResultSemanticsError("invalid transport state")
    _nonempty(transport.get("basis"), "transport.basis")

    protocol = value.get("protocol")
    if not isinstance(protocol, dict) or set(protocol) != {
        "state", "basis", "att_pdu_directly_observed", "response_expected"
    }:
        raise ResultSemanticsError("protocol semantics are malformed")
    if protocol.get("state") not in PROTOCOL_STATES:
        raise ResultSemanticsError("invalid protocol state")
    _nonempty(protocol.get("basis"), "protocol.basis")
    if not isinstance(protocol.get("att_pdu_directly_observed"), bool):
        raise ResultSemanticsError("protocol.att_pdu_directly_observed must be boolean")
    if protocol.get("response_expected") not in {True, False, None}:
        raise ResultSemanticsError("protocol.response_expected must be boolean or null")

    for stage in ("application_acknowledgment", "state_change"):
        item = value.get(stage)
        if not isinstance(item, dict) or set(item) != {"state", "basis", "evidence"}:
            raise ResultSemanticsError(f"{stage} semantics are malformed")
        if item.get("state") not in ASSESSMENT_STATES:
            raise ResultSemanticsError(f"invalid {stage} state")
        _validate_reviewable_stage(item, stage)

    security = value.get("security_effect")
    if not isinstance(security, dict) or set(security) != {"state", "basis", "evidence"}:
        raise ResultSemanticsError("security_effect semantics are malformed")
    if security.get("state") not in SECURITY_EFFECT_STATES:
        raise ResultSemanticsError("invalid security_effect state")
    _validate_reviewable_stage(security, "security_effect")
    return deepcopy(value)


def _validate_reviewable_stage(item, stage):
    state = item.get("state")
    basis = item.get("basis")
    evidence = item.get("evidence")
    if not isinstance(evidence, list) or any(
        not isinstance(entry, str) or not entry.strip() for entry in evidence
    ):
        raise ResultSemanticsError(f"{stage}.evidence must be an array of non-empty strings")
    if state == "not_assessed":
        if basis is not None or evidence:
            raise ResultSemanticsError(f"{stage} not_assessed must not carry basis/evidence")
    else:
        _nonempty(basis, f"{stage}.basis")
        if not evidence:
            raise ResultSemanticsError(f"{stage} {state} requires evidence")


def validate_operation_result(result):
    if not isinstance(result, dict):
        raise ResultSemanticsError("operation result must be an object")
    if result.get("record_type") != "gatt_operation_result":
        raise ResultSemanticsError("operation result has unsupported record_type")
    _nonempty(result.get("plan_id"), "operation result plan_id")
    _nonempty(result.get("operation_id"), "operation result operation_id")
    semantics = validate_effect_semantics(result.get("effect_semantics"))
    transport_success = result.get("transport_success")
    if not isinstance(transport_success, bool):
        raise ResultSemanticsError("operation result transport_success must be boolean")
    expected = semantics["transport"]["state"] == "succeeded"
    if transport_success != expected:
        raise ResultSemanticsError("legacy transport_success disagrees with effect_semantics")
    if result.get("application_effect") != "not_assessed":
        raise ResultSemanticsError("legacy application_effect must remain not_assessed")
    return semantics


def _normalize_review_stage(stage_name, value):
    if not isinstance(value, dict):
        raise ResultSemanticsError(f"review.stages.{stage_name} must be an object")
    if set(value) != {"state", "basis", "evidence"}:
        raise ResultSemanticsError(f"review.stages.{stage_name} fields are invalid")
    if stage_name == "security_effect":
        allowed = SECURITY_EFFECT_STATES - {"not_assessed"}
    else:
        allowed = ASSESSMENT_STATES - {"not_assessed"}
    if value.get("state") not in allowed:
        raise ResultSemanticsError(f"invalid review state for {stage_name}")
    normalized = {
        "state": value["state"],
        "basis": _nonempty(value.get("basis"), f"review.stages.{stage_name}.basis"),
        "evidence": [],
    }
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ResultSemanticsError(f"review.stages.{stage_name}.evidence must not be empty")
    for entry in evidence:
        normalized["evidence"].append(_nonempty(entry, f"review.stages.{stage_name}.evidence"))
    return normalized


def build_effect_review(
    operation_result,
    review,
    *,
    operation_sha256,
    review_sha256,
    reviewed_at_utc=None,
):
    """Build an immutable, hash-bound offline analyst review of one operation result."""
    base = validate_operation_result(operation_result)
    operation_sha256 = _sha256(operation_sha256, "operation_sha256")
    review_sha256 = _sha256(review_sha256, "review_sha256")
    if not isinstance(review, dict):
        raise ResultSemanticsError("review must be an object")
    allowed = {"schema_version", "record_type", "review_id", "reviewer", "basis", "stages"}
    unknown = sorted(set(review) - allowed)
    if unknown:
        raise ResultSemanticsError("review contains unsupported fields: " + ", ".join(unknown))
    if review.get("schema_version") != RESULT_SEMANTICS_VERSION:
        raise ResultSemanticsError("review schema_version is unsupported")
    if review.get("record_type") != "gatt_effect_review_request":
        raise ResultSemanticsError("review record_type must be gatt_effect_review_request")
    stages = review.get("stages")
    if not isinstance(stages, dict) or not stages:
        raise ResultSemanticsError("review.stages must contain at least one stage")
    unknown_stages = sorted(set(stages) - REVIEWABLE_STAGES)
    if unknown_stages:
        raise ResultSemanticsError("review contains unsupported stage(s): " + ", ".join(unknown_stages))

    merged = deepcopy(base)
    normalized_stages = {}
    for stage_name in sorted(stages):
        normalized = _normalize_review_stage(stage_name, stages[stage_name])
        merged[stage_name] = normalized
        normalized_stages[stage_name] = normalized
    validate_effect_semantics(merged)

    return {
        "schema_version": RESULT_SEMANTICS_VERSION,
        "record_type": "gatt_effect_review",
        "review_id": _nonempty(review.get("review_id"), "review.review_id"),
        "reviewed_at_utc": _utc_text(reviewed_at_utc, "reviewed_at_utc"),
        "reviewer": _nonempty(review.get("reviewer"), "review.reviewer"),
        "basis": _nonempty(review.get("basis"), "review.basis"),
        "operation_provenance": {
            "sha256": operation_sha256,
            "plan_id": operation_result["plan_id"],
            "operation_id": operation_result["operation_id"],
        },
        "review_provenance": {"sha256": review_sha256},
        "reviewed_stages": normalized_stages,
        "effect_semantics": merged,
        "execution": {
            "status": "offline_review",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [
            "Analyst review does not alter the original executor artifact.",
            "A validated security effect is an explicit reviewer conclusion, not an inference from transport or protocol success.",
        ],
    }


def load_json_with_sha256(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ResultSemanticsError(f"Invalid JSON in {path}: {exc}") from exc
    return payload, hashlib.sha256(raw).hexdigest(), path


def write_effect_review(operation_path, review_path, output_path):
    operation, operation_sha256, operation_path = load_json_with_sha256(operation_path)
    review, review_sha256, review_path = load_json_with_sha256(review_path)
    output_path = Path(output_path).resolve()
    if output_path in {operation_path, review_path}:
        raise ResultSemanticsError("output path must differ from input paths")
    artifact = build_effect_review(
        operation,
        review,
        operation_sha256=operation_sha256,
        review_sha256=review_sha256,
    )
    atomic_create_json(output_path, artifact)
    return artifact

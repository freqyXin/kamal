"""Offline v0.12 integration and acceptance harness.

The harness deliberately injects a synthetic BLE backend. It exercises the
active authorization/plan/executor path without opening a real adapter, then
feeds synthetic K'amal evidence through assessment, device intelligence, and
BSAM mapping. Negative gates verify fail-closed behavior before release/hardware
acceptance.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from kamal.active_contracts import (
    ACTIVE_CONTRACT_VERSION,
    ContractValidationError,
    build_gatt_operation_plan,
    validate_authorization_scope,
)
from kamal.assessment import build_assessment
from kamal.bsam_mapping import BSAM_PROFILE_VERSION, build_bsam_mapping
from kamal.device_intelligence import (
    build_ble_intelligence_enrichment,
    load_intelligence_catalog,
)
from kamal.evidence_contracts import EVIDENCE_CONTRACT_VERSION, atomic_create_json
from kamal.gatt_executor import (
    EXECUTOR_VERSION,
    ConnectionLostError,
    ExecutionError,
    UnsafeStopError,
    execute_plan,
)
from kamal.gatt_report import new_report
from kamal.gatt_safety import (
    SAFETY_STATE_VERSION,
    SafetyInterlockError,
    acquire_active_run,
    latch_unsafe_stop,
)
from kamal.report_validation import validate_report
from kamal.result_semantics import (
    RESULT_SEMANTICS_VERSION,
    build_effect_review,
    validate_operation_result,
)

ACCEPTANCE_VERSION = "0.12.0"
FIXED_UTC = "2026-09-25T20:00:00Z"
TARGET = "AA:BB:CC:DD:EE:FF"

_BANNED_OFFLINE_IMPORT_PREFIXES = (
    "bleak",
    "socket",
    "requests",
    "urllib",
    "httpx",
    "aiohttp",
)
_OFFLINE_MODULES = (
    "assessment.py",
    "ble_intelligence.py",
    "bsam_mapping.py",
    "catalog_provenance.py",
    "device_intelligence.py",
    "active_contracts.py",
    "ble_correlation.py",
    "evidence_contracts.py",
    "result_semantics.py",
)


class AcceptanceError(RuntimeError):
    """Raised when a v0.12 acceptance gate does not hold."""


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _artifact_ref(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _write_json(path, value):
    atomic_create_json(path, value)
    return _artifact_ref(path)


def _authorization(*, expires="2099-01-01T00:00:00Z"):
    return {
        "schema_version": ACTIVE_CONTRACT_VERSION,
        "record_type": "authorization_scope",
        "authorization_id": "acceptance:auth:v0.12",
        "engagement_id": "acceptance:v0.12",
        "owner": "K'amal synthetic acceptance fixture",
        "operator": "kamal-v012-acceptance",
        "location": "synthetic offline backend",
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "not_before_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": expires,
        "targets": [
            {
                "protocol": "ble",
                "address": TARGET,
                "address_type": "public",
                "label": "synthetic acceptance target",
            }
        ],
        "allowed_operations": [
            "read_characteristic",
            "write_characteristic",
        ],
        "constraints": {
            "max_operations": 4,
            "max_payload_bytes": 16,
            "max_timeout_seconds": 3,
            "max_subscription_seconds": 5,
            "allow_writes": True,
            "allow_write_without_response": False,
        },
        "approval": {
            "approver": "K'amal synthetic acceptance fixture",
            "approved_at_utc": "2026-01-01T00:00:00Z",
            "basis": "offline synthetic acceptance only",
        },
    }


def _operation(operation_id, operation_type="read_characteristic"):
    value = {
        "operation_id": operation_id,
        "operation_type": operation_type,
        "target": {"address": TARGET, "address_type": "public"},
        "selector": {"handle": 3},
        "timeout_seconds": 1,
    }
    if operation_type == "write_characteristic":
        value.update(payload_hex="0102", write_mode="request")
    return value


def _request(operations=None):
    return {
        "schema_version": ACTIVE_CONTRACT_VERSION,
        "record_type": "gatt_operation_request",
        "plan_id": "acceptance:plan:v0.12",
        "operations": operations
        or [_operation("acceptance:read"), _operation("acceptance:write", "write_characteristic")],
    }


class _SyntheticCharacteristic:
    handle = 3
    uuid = "2a19"
    properties = ["read", "write", "write-without-response"]
    descriptors = []


class _SyntheticService:
    handle = 1
    uuid = "180f"
    characteristics = [_SyntheticCharacteristic()]


class _SyntheticClient:
    def __init__(self, *, read_error=None, disconnect_stuck=False, disconnect_after_read=False):
        self.is_connected = False
        self.services = [_SyntheticService()]
        self.read_error = read_error
        self.disconnect_stuck = disconnect_stuck
        self.disconnect_after_read = disconnect_after_read
        self.writes = []

    async def connect(self):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = self.disconnect_stuck

    async def read_gatt_char(self, _selected):
        if self.read_error is not None:
            raise self.read_error
        if self.disconnect_after_read:
            self.is_connected = False
        return b"acceptance"

    async def read_gatt_descriptor(self, _handle):
        return b"descriptor"

    async def write_gatt_char(self, _selected, payload, response=True):
        self.writes.append((bytes(payload), bool(response)))

    async def start_notify(self, _selected, _callback):
        raise AcceptanceError("synthetic acceptance happy path does not subscribe")

    async def stop_notify(self, _selected):
        return None


class _SyntheticBackend:
    """Injected backend that never imports or invokes Bleak."""

    def __init__(self, client=None):
        self.client_instance = client or _SyntheticClient()
        self.discover_calls = 0

    async def discover(self, address, adapter, timeout):
        self.discover_calls += 1
        return SimpleNamespace(address=address, adapter=adapter, timeout=timeout), SimpleNamespace()

    def client(self, _device, _timeout):
        return self.client_instance


def _assert_offline_module_boundaries(repo_root):
    kamal_dir = Path(repo_root).resolve() / "kamal"
    checked = []
    for filename in _OFFLINE_MODULES:
        path = kamal_dir / filename
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        violations = []
        for prefix in _BANNED_OFFLINE_IMPORT_PREFIXES:
            if f"import {prefix}" in lowered or f"from {prefix}" in lowered:
                violations.append(prefix)
        if violations:
            raise AcceptanceError(
                f"offline module {filename} imports active/network dependency: "
                + ", ".join(sorted(set(violations)))
            )
        checked.append(filename)
    return checked


def _synthetic_active_report():
    report = new_report(TARGET, "synthetic0")
    report["timestamp_utc"] = FIXED_UTC
    report["connection"] = {"attempted": True, "connected": True, "error": None}
    report["gatt"] = {
        "enumeration_attempted": True,
        "enumerated": True,
        "error": None,
        "services": [
            {
                "handle": 1,
                "uuid": "180f",
                "characteristics": [
                    {
                        "handle": 3,
                        "uuid": "2a19",
                        "properties": ["read", "write", "write-without-response"],
                        "descriptors": [],
                    }
                ],
            }
        ],
    }
    report["disconnect"] = {"attempted": True, "completed": True, "error": None}
    report["operations"] = {
        "characteristic_reads": True,
        "characteristic_writes": True,
        "notifications": False,
        "pairing_requested": False,
    }
    validate_report(report, "active_gatt")
    return report


def _catalog_payload():
    return {
        "schema_version": EVIDENCE_CONTRACT_VERSION,
        "catalog_id": "acceptance-device-context",
        "catalog_revision": "acceptance-r1",
        "records": [
            {
                "record_id": "battery-level-purpose",
                "match": {
                    "kind": "gatt_uuid",
                    "attribute_type": "characteristic",
                    "uuid": "2a19",
                },
                "claim": {
                    "category": "gatt_characteristic_purpose",
                    "value": "Synthetic Battery Level characteristic",
                },
                "state": "documented",
                "confidence": "high",
                "source": {
                    "source_type": "acceptance_fixture",
                    "title": "K'amal v0.12 synthetic acceptance fixture",
                    "locator": "synthetic://v0.12/device-context",
                },
                "limitations": ["Synthetic acceptance context only."],
            }
        ],
    }


async def _execute(plan, authorization, *, authorization_sha, plan_sha, output_dir, safety_dir, client=None):
    backend = _SyntheticBackend(client)
    try:
        final = await execute_plan(
            plan,
            authorization,
            authorization_sha256=authorization_sha,
            plan_sha256=plan_sha,
            output_dir=output_dir,
            safety_state_dir=safety_dir,
            adapter="synthetic0",
            backend=backend,
        )
        return final, backend, None
    except BaseException as exc:  # acceptance records the expected failure type
        return None, backend, exc


def _negative_gates(root, plan, authorization, authorization_sha, plan_sha):
    gates = {}

    expired = _authorization(expires="2026-09-25T19:59:59Z")
    try:
        validate_authorization_scope(expired, at_utc=FIXED_UTC)
    except ContractValidationError:
        gates["expired_authorization_fails_closed"] = True
    else:
        raise AcceptanceError("expired authorization unexpectedly validated")

    bad_request = _request([_operation("outside")])
    bad_request["operations"][0]["target"]["address"] = "00:11:22:33:44:55"
    try:
        build_gatt_operation_plan(
            authorization,
            bad_request,
            authorization_sha256=authorization_sha,
            request_sha256="f" * 64,
            created_at_utc=FIXED_UTC,
        )
    except ContractValidationError:
        gates["target_mismatch_fails_closed"] = True
    else:
        raise AcceptanceError("out-of-scope target unexpectedly produced a plan")

    corrupt = deepcopy(plan)
    corrupt["operations"][0]["operation_type"] = "fuzz_characteristic"
    final, backend, exc = asyncio.run(_execute(
        corrupt,
        authorization,
        authorization_sha=authorization_sha,
        plan_sha=plan_sha,
        output_dir=root / "corrupt-plan-output",
        safety_dir=root / "corrupt-plan-safety",
    ))
    if final is not None or not isinstance(exc, ExecutionError) or backend.discover_calls:
        raise AcceptanceError("corrupt plan was not rejected before synthetic discovery")
    gates["corrupt_plan_fails_before_rf_boundary"] = True

    latch_dir = root / "latched-safety"
    acquire_active_run(
        latch_dir,
        plan_id=plan["plan_id"],
        plan_sha256=plan_sha,
        authorization_sha256=authorization_sha,
        output_dir=root / "latched-origin",
        targets=[plan["operations"][0]["target"]],
    )
    latch_unsafe_stop(
        latch_dir,
        plan_id=plan["plan_id"],
        reason="synthetic acceptance unsafe latch",
        cleanup={"disconnect_confirmed": False},
        output_dir=root / "latched-origin",
        current_target=plan["operations"][0]["target"],
    )
    final, backend, exc = asyncio.run(_execute(
        plan,
        authorization,
        authorization_sha=authorization_sha,
        plan_sha=plan_sha,
        output_dir=root / "latched-followup",
        safety_dir=latch_dir,
    ))
    if final is not None or not isinstance(exc, SafetyInterlockError) or backend.discover_calls:
        raise AcceptanceError("unsafe latch did not block execution before discovery")
    gates["unsafe_latch_blocks_followup_before_rf_boundary"] = True

    orphan_dir = root / "orphaned-active-run"
    acquire_active_run(
        orphan_dir,
        plan_id=plan["plan_id"],
        plan_sha256=plan_sha,
        authorization_sha256=authorization_sha,
        output_dir=root / "orphan-origin",
        targets=[plan["operations"][0]["target"]],
    )
    final, backend, exc = asyncio.run(_execute(
        plan,
        authorization,
        authorization_sha=authorization_sha,
        plan_sha=plan_sha,
        output_dir=root / "orphan-followup",
        safety_dir=orphan_dir,
    ))
    if final is not None or not isinstance(exc, SafetyInterlockError) or backend.discover_calls:
        raise AcceptanceError("orphaned active-run lease did not block before discovery")
    gates["orphaned_active_run_blocks_followup_before_rf_boundary"] = True

    one_read = build_gatt_operation_plan(
        authorization,
        _request([_operation("failure-read")]),
        authorization_sha256=authorization_sha,
        request_sha256="e" * 64,
        created_at_utc=FIXED_UTC,
    )
    failure_root = root / "operation-failure"
    final, _, exc = asyncio.run(_execute(
        one_read,
        authorization,
        authorization_sha=authorization_sha,
        plan_sha="d" * 64,
        output_dir=failure_root / "out",
        safety_dir=failure_root / "safety",
        client=_SyntheticClient(read_error=RuntimeError("synthetic read failure")),
    ))
    if final is not None or not isinstance(exc, ExecutionError):
        raise AcceptanceError("synthetic operation failure did not stop execution")
    if not (failure_root / "out" / "operation-001.json").exists():
        raise AcceptanceError("partial operation evidence was not preserved")
    if (failure_root / "safety" / "unsafe-stop.json").exists():
        raise AcceptanceError("safe operation failure incorrectly latched unsafe state")
    gates["safe_failure_preserves_partial_evidence"] = True

    disconnect_root = root / "uncertain-disconnect"
    final, _, exc = asyncio.run(_execute(
        one_read,
        authorization,
        authorization_sha=authorization_sha,
        plan_sha="c" * 64,
        output_dir=disconnect_root / "out",
        safety_dir=disconnect_root / "safety",
        client=_SyntheticClient(disconnect_stuck=True),
    ))
    if final is not None or not isinstance(exc, UnsafeStopError):
        raise AcceptanceError("uncertain disconnect did not cause unsafe stop")
    if not (disconnect_root / "safety" / "unsafe-stop.json").exists():
        raise AcceptanceError("uncertain disconnect did not persist unsafe latch")
    gates["uncertain_disconnect_requires_recovery"] = True

    loss_plan = build_gatt_operation_plan(
        authorization,
        _request([_operation("loss-1"), _operation("loss-2")]),
        authorization_sha256=authorization_sha,
        request_sha256="b" * 64,
        created_at_utc=FIXED_UTC,
    )
    loss_root = root / "connection-loss"
    final, _, exc = asyncio.run(_execute(
        loss_plan,
        authorization,
        authorization_sha=authorization_sha,
        plan_sha="a" * 64,
        output_dir=loss_root / "out",
        safety_dir=loss_root / "safety",
        client=_SyntheticClient(disconnect_after_read=True),
    ))
    if final is not None or not isinstance(exc, (ConnectionLostError, ExecutionError)):
        raise AcceptanceError("connection loss did not stop the plan")
    run_final = json.loads((loss_root / "out" / "run-final.json").read_text())
    if run_final["unattempted_operations"] != 1 or (loss_root / "out" / "operation-002.json").exists():
        raise AcceptanceError("connection loss did not leave later operation unattempted")
    gates["connection_loss_stops_remaining_operations"] = True

    immutability_path = root / "immutability.json"
    atomic_create_json(immutability_path, {"first": True})
    try:
        atomic_create_json(immutability_path, {"second": True})
    except OSError:
        gates["artifact_no_overwrite"] = True
    else:
        raise AcceptanceError("immutable persistence unexpectedly overwrote artifact")

    return gates


def run_v012_acceptance(work_dir, *, repo_root=None):
    """Run the offline synthetic v0.12 release acceptance workflow."""
    root = Path(work_dir).expanduser().resolve()
    if root.exists():
        raise AcceptanceError(f"acceptance work directory already exists: {root}")
    root.mkdir(parents=True)
    repo_root = Path(repo_root or Path(__file__).resolve().parents[1]).resolve()

    checked_modules = _assert_offline_module_boundaries(repo_root)
    artifacts = {}

    authorization = _authorization()
    request = _request()
    artifacts["authorization"] = _write_json(root / "authorization.json", authorization)
    artifacts["request"] = _write_json(root / "operations.json", request)
    authorization_sha = artifacts["authorization"]["sha256"]
    request_sha = artifacts["request"]["sha256"]

    plan = build_gatt_operation_plan(
        authorization,
        request,
        authorization_sha256=authorization_sha,
        request_sha256=request_sha,
        created_at_utc=FIXED_UTC,
    )
    artifacts["plan"] = _write_json(root / "plan.json", plan)

    final, backend, exc = asyncio.run(_execute(
        plan,
        authorization,
        authorization_sha=authorization_sha,
        plan_sha=artifacts["plan"]["sha256"],
        output_dir=root / "execution",
        safety_dir=root / "safety",
    ))
    if exc is not None:
        raise AcceptanceError(f"synthetic happy-path execution failed: {exc}") from exc
    if backend.discover_calls != 1 or not final.get("complete"):
        raise AcceptanceError("synthetic happy-path execution did not complete")
    artifacts["run_start"] = _artifact_ref(root / "execution" / "run-start.json")
    artifacts["read_result"] = _artifact_ref(root / "execution" / "operation-001.json")
    artifacts["write_result"] = _artifact_ref(root / "execution" / "operation-002.json")
    artifacts["run_final"] = _artifact_ref(root / "execution" / "run-final.json")

    write_result = json.loads((root / "execution" / "operation-002.json").read_text())
    semantics = validate_operation_result(write_result)
    if semantics["protocol"]["state"] != "write_request_completed":
        raise AcceptanceError("synthetic write did not reach expected protocol-visible state")
    for stage in ("application_acknowledgment", "state_change", "security_effect"):
        if semantics[stage]["state"] != "not_assessed":
            raise AcceptanceError(f"executor overclaimed {stage}")

    review_request = {
        "schema_version": RESULT_SEMANTICS_VERSION,
        "record_type": "gatt_effect_review_request",
        "review_id": "acceptance:review:v0.12",
        "reviewer": "kamal-v012-acceptance",
        "basis": "synthetic backend intentionally exposes no application acknowledgement channel",
        "stages": {
            "application_acknowledgment": {
                "state": "not_observed",
                "basis": "synthetic backend produced no application-level acknowledgement evidence",
                "evidence": ["synthetic://v0.12/no-application-ack"],
            }
        },
    }
    artifacts["review_request"] = _write_json(root / "review-request.json", review_request)
    review = build_effect_review(
        write_result,
        review_request,
        operation_sha256=artifacts["write_result"]["sha256"],
        review_sha256=artifacts["review_request"]["sha256"],
        reviewed_at_utc=FIXED_UTC,
    )
    artifacts["effect_review"] = _write_json(root / "effect-review.json", review)

    active_report = _synthetic_active_report()
    artifacts["active_report"] = _write_json(root / "active-report.json", active_report)
    source = {
        "source_id": "sha256:" + artifacts["active_report"]["sha256"],
        "path": artifacts["active_report"]["path"],
        "sha256": artifacts["active_report"]["sha256"],
        "evidence_type": "active_gatt",
        "schema_version": "0.7.0",
        "report": active_report,
    }
    assessment = build_assessment(
        [source],
        assessment_id="acceptance:v0.12",
        created_at_utc=FIXED_UTC,
    )
    artifacts["assessment"] = _write_json(root / "assessment.json", assessment)
    assessment_source = {
        "assessment_source_id": "sha256:" + artifacts["assessment"]["sha256"],
        "path": artifacts["assessment"]["path"],
        "sha256": artifacts["assessment"]["sha256"],
        "assessment_id": assessment["assessment_id"],
        "assessment": assessment,
    }

    artifacts["device_catalog"] = _write_json(root / "device-catalog.json", _catalog_payload())
    catalog_source = load_intelligence_catalog(root / "device-catalog.json")
    enrichment = build_ble_intelligence_enrichment(assessment_source, catalog_source)
    artifacts["enrichment"] = _write_json(root / "enrichment.json", enrichment)
    enrichment_source = {
        "enrichment_source_id": "sha256:" + artifacts["enrichment"]["sha256"],
        "path": artifacts["enrichment"]["path"],
        "sha256": artifacts["enrichment"]["sha256"],
        "enrichment": enrichment,
    }

    bsam = build_bsam_mapping(
        assessment_source,
        enrichment_source=enrichment_source,
        created_at_utc=FIXED_UTC,
    )
    artifacts["bsam_mapping"] = _write_json(root / "bsam-mapping.json", bsam)
    if bsam["summary"]["pass_fail_determinations_made"]:
        raise AcceptanceError("BSAM mapping unexpectedly made pass/fail determinations")
    if bsam["summary"]["candidate_concern_count"] < 1:
        raise AcceptanceError("synthetic GATT review finding did not reach BSAM candidate concern")

    gates = _negative_gates(
        root / "negative-gates",
        plan,
        authorization,
        authorization_sha,
        artifacts["plan"]["sha256"],
    )

    checks = {
        "offline_module_boundaries": True,
        "authorization_to_plan_hash_bound": plan["authorization_provenance"]["sha256"] == authorization_sha,
        "request_to_plan_hash_bound": plan["request_provenance"]["sha256"] == request_sha,
        "synthetic_executor_completed": bool(final["complete"]),
        "executor_did_not_claim_application_effect": True,
        "review_hash_bound_to_operation": review["operation_provenance"]["sha256"] == artifacts["write_result"]["sha256"],
        "assessment_preserved_source_hash": assessment["sources"][0]["sha256"] == artifacts["active_report"]["sha256"],
        "enrichment_hash_bound_to_assessment": enrichment["assessment_source"]["sha256"] == artifacts["assessment"]["sha256"],
        "bsam_no_pass_fail_inference": not bsam["summary"]["pass_fail_determinations_made"],
        "safety_interlock_clear_after_happy_path": not (root / "safety" / "active-run.json").exists() and not (root / "safety" / "unsafe-stop.json").exists(),
        **gates,
    }
    if not all(checks.values()):
        failed = sorted(name for name, passed in checks.items() if not passed)
        raise AcceptanceError("acceptance check(s) failed: " + ", ".join(failed))

    return {
        "schema_version": ACCEPTANCE_VERSION,
        "record_type": "kamal_v012_acceptance_report",
        "acceptance_version": ACCEPTANCE_VERSION,
        "execution": {
            "status": "offline_synthetic_acceptance",
            "real_rf_performed": False,
            "network_performed": False,
            "synthetic_backend": True,
        },
        "component_versions": {
            "evidence_contract": EVIDENCE_CONTRACT_VERSION,
            "active_contract": ACTIVE_CONTRACT_VERSION,
            "executor": EXECUTOR_VERSION,
            "result_semantics": RESULT_SEMANTICS_VERSION,
            "safety_state": SAFETY_STATE_VERSION,
            "bsam_profile": BSAM_PROFILE_VERSION,
        },
        "offline_modules_checked": checked_modules,
        "checks": checks,
        "summary": {
            "check_count": len(checks),
            "passed_count": sum(bool(value) for value in checks.values()),
            "failed_count": sum(not bool(value) for value in checks.values()),
            "ready_for_controlled_hardware_read_acceptance": True,
            "hardware_write_acceptance_performed": False,
        },
        "artifacts": artifacts,
        "limitations": [
            "This acceptance run uses a synthetic injected backend and performs no real BLE RF activity.",
            "It does not validate BlueZ, adapter, kernel, RF environment, target-device behavior, or hardware cleanup behavior.",
            "Current assessment ingestion consumes active-GATT enumeration reports; executor operation-result/review artifacts remain separately hash-bound and are not silently converted into assessment observations.",
            "Hardware acceptance must begin with an owned or expressly authorized read-only target before any write test.",
        ],
    }

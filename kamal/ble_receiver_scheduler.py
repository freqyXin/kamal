"""Offline receiver-scheduler contract for evidenced BLE connection context.

This module performs no RF, receiver-control, or network operations. It consumes
only accepted connection-context extraction records and records deterministic
scheduling decisions. The current contract intentionally does not derive a BLE
data-channel schedule from CONNECT_IND alone because the implemented context
does not establish an actual data-channel anchor, connection event counter, or
channel-selection algorithm, and K'amal does not yet have a verified arbitrary
data-channel receiver-control path.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Mapping

from kamal.ble_connection_context import (
    BLE_CONNECTION_CONTEXT_CONTRACT_VERSION,
    PRIMARY_ADVERTISING_CHANNELS,
)
from kamal.ble_connection_extractor import BLE_CONNECTION_EXTRACTION_VERSION


BLE_RECEIVER_SCHEDULER_CONTRACT_VERSION = "0.12.0"

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_REQUIRED_LINK_LAYER_FIELDS = (
    "access_address",
    "crc_init",
    "window_size",
    "window_offset",
    "interval",
    "latency",
    "timeout",
    "channel_map_hex",
    "hop_increment",
    "sleep_clock_accuracy_code",
)

_CURRENT_BLOCKERS = (
    "missing_verified_data_channel_control",
    "missing_data_channel_anchor",
    "missing_connection_event_counter",
    "missing_channel_selection_algorithm",
)


class BLEReceiverSchedulerContractError(ValueError):
    """Raised when scheduler input cannot satisfy the offline contract."""


def _mapping(value, field):
    if not isinstance(value, Mapping):
        raise BLEReceiverSchedulerContractError(f"{field} must be an object")
    return value


def _list(value, field):
    if not isinstance(value, list):
        raise BLEReceiverSchedulerContractError(f"{field} must be an array")
    return value


def _nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise BLEReceiverSchedulerContractError(
            f"{field} must be a non-empty string"
        )
    return value.strip()


def _sha256(value, field):
    value = _nonempty(value, field)
    if not _SHA256_RE.fullmatch(value):
        raise BLEReceiverSchedulerContractError(
            f"{field} must be a SHA-256 hexadecimal digest"
        )
    return value.lower()


def _bounded_int(value, field, *, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise BLEReceiverSchedulerContractError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise BLEReceiverSchedulerContractError(
            f"{field} must be in the range {minimum}..{maximum}"
        )
    return value


def _channel_map(value):
    value = _nonempty(value, "observation.link_layer.channel_map_hex").lower()
    if len(value) != 10 or not _HEX_RE.fullmatch(value):
        raise BLEReceiverSchedulerContractError(
            "observation.link_layer.channel_map_hex must be five bytes of hexadecimal"
        )
    bits = int.from_bytes(bytes.fromhex(value), "little")
    if bits >> 37:
        raise BLEReceiverSchedulerContractError(
            "observation.link_layer.channel_map_hex has nonzero reserved bits"
        )
    if (bits & ((1 << 37) - 1)).bit_count() < 2:
        raise BLEReceiverSchedulerContractError(
            "observation.link_layer.channel_map_hex must enable at least two data channels"
        )
    return value


def _validate_context(context, *, report_source_sha256):
    context = _mapping(context, "connection_context")

    if context.get("schema_version") != BLE_CONNECTION_CONTEXT_CONTRACT_VERSION:
        raise BLEReceiverSchedulerContractError(
            "connection_context has unsupported schema_version"
        )
    if context.get("record_type") != "ble_legacy_connect_ind":
        raise BLEReceiverSchedulerContractError(
            "connection_context must be a ble_legacy_connect_ind record"
        )

    context_id = _nonempty(
        context.get("connection_context_id"),
        "connection_context.connection_context_id",
    )
    source = _mapping(
        context.get("source_capture"),
        "connection_context.source_capture",
    )
    source_sha = _sha256(
        source.get("sha256"),
        "connection_context.source_capture.sha256",
    )
    if source_sha != report_source_sha256:
        raise BLEReceiverSchedulerContractError(
            "connection_context source capture SHA-256 does not match extraction report"
        )

    frame_number = _bounded_int(
        source.get("frame_number"),
        "connection_context.source_capture.frame_number",
        minimum=1,
        maximum=2**31 - 1,
    )
    expected_id = (
        f"ble-legacy-connect-ind:sha256:{source_sha}:frame:{frame_number}"
    )
    if context_id != expected_id:
        raise BLEReceiverSchedulerContractError(
            "connection_context_id does not match source capture/frame provenance"
        )

    observation = _mapping(
        context.get("observation"),
        "connection_context.observation",
    )
    if observation.get("directly_observed") is not True:
        raise BLEReceiverSchedulerContractError(
            "connection_context must be directly observed"
        )
    if observation.get("crc_valid") is not True:
        raise BLEReceiverSchedulerContractError(
            "connection_context must be CRC-valid"
        )
    if observation.get("pdu_type") != "CONNECT_IND":
        raise BLEReceiverSchedulerContractError(
            "connection_context must represent CONNECT_IND"
        )
    advertising_channel = _bounded_int(
        observation.get("advertising_channel"),
        "connection_context.observation.advertising_channel",
        minimum=0,
        maximum=255,
    )
    if advertising_channel not in PRIMARY_ADVERTISING_CHANNELS:
        raise BLEReceiverSchedulerContractError(
            "connection_context must come from advertising channel 37, 38, or 39"
        )

    link_layer = _mapping(
        observation.get("link_layer"),
        "connection_context.observation.link_layer",
    )
    missing = [
        field for field in _REQUIRED_LINK_LAYER_FIELDS
        if field not in link_layer
    ]
    if missing:
        raise BLEReceiverSchedulerContractError(
            "connection_context is missing required link-layer fields: "
            + ", ".join(missing)
        )

    access_address = _nonempty(
        link_layer.get("access_address"),
        "connection_context.observation.link_layer.access_address",
    ).lower()
    crc_init = _nonempty(
        link_layer.get("crc_init"),
        "connection_context.observation.link_layer.crc_init",
    ).lower()
    if not re.fullmatch(r"0x[0-9a-f]{8}", access_address):
        raise BLEReceiverSchedulerContractError(
            "connection_context access_address must be 0x plus eight hexadecimal digits"
        )
    if not re.fullmatch(r"0x[0-9a-f]{6}", crc_init):
        raise BLEReceiverSchedulerContractError(
            "connection_context crc_init must be 0x plus six hexadecimal digits"
        )

    evidenced_inputs = {
        "access_address": access_address,
        "crc_init": crc_init,
        "window_size": _bounded_int(
            link_layer.get("window_size"),
            "connection_context.observation.link_layer.window_size",
            minimum=1,
            maximum=8,
        ),
        "window_offset": _bounded_int(
            link_layer.get("window_offset"),
            "connection_context.observation.link_layer.window_offset",
            minimum=0,
            maximum=65535,
        ),
        "interval": _bounded_int(
            link_layer.get("interval"),
            "connection_context.observation.link_layer.interval",
            minimum=6,
            maximum=3200,
        ),
        "latency": _bounded_int(
            link_layer.get("latency"),
            "connection_context.observation.link_layer.latency",
            minimum=0,
            maximum=499,
        ),
        "timeout": _bounded_int(
            link_layer.get("timeout"),
            "connection_context.observation.link_layer.timeout",
            minimum=10,
            maximum=3200,
        ),
        "channel_map_hex": _channel_map(link_layer.get("channel_map_hex")),
        "hop_increment": _bounded_int(
            link_layer.get("hop_increment"),
            "connection_context.observation.link_layer.hop_increment",
            minimum=5,
            maximum=16,
        ),
        "sleep_clock_accuracy_code": _bounded_int(
            link_layer.get("sleep_clock_accuracy_code"),
            "connection_context.observation.link_layer.sleep_clock_accuracy_code",
            minimum=0,
            maximum=7,
        ),
    }

    return {
        "connection_context_id": context_id,
        "source_capture_sha256": source_sha,
        "source_frame_number": frame_number,
        "advertising_channel": advertising_channel,
        "evidenced_inputs": evidenced_inputs,
    }


def build_receiver_scheduler_plan(extraction_report):
    """Build an offline, fail-closed scheduler decision record.

    This function records whether accepted connection context is available and
    why the current K'amal implementation cannot yet assign dynamic receivers.
    It never derives channel/event timing, never consumes rejected candidates,
    and never performs RF or receiver control.
    """

    if not isinstance(extraction_report, Mapping):
        raise BLEReceiverSchedulerContractError(
            "extraction_report must be an object"
        )

    original = deepcopy(dict(extraction_report))

    if extraction_report.get("schema_version") != BLE_CONNECTION_EXTRACTION_VERSION:
        raise BLEReceiverSchedulerContractError(
            "extraction_report has unsupported schema_version"
        )
    if extraction_report.get("record_type") != "ble_connection_context_extraction":
        raise BLEReceiverSchedulerContractError(
            "extraction_report must be a ble_connection_context_extraction record"
        )

    source = _mapping(
        extraction_report.get("source_capture"),
        "extraction_report.source_capture",
    )
    source_sha = _sha256(
        source.get("sha256"),
        "extraction_report.source_capture.sha256",
    )

    summary = _mapping(
        extraction_report.get("summary"),
        "extraction_report.summary",
    )
    contexts = _list(
        extraction_report.get("connection_contexts"),
        "extraction_report.connection_contexts",
    )
    rejected = _list(
        extraction_report.get("rejected_candidates"),
        "extraction_report.rejected_candidates",
    )

    accepted_count = _bounded_int(
        summary.get("accepted_count"),
        "extraction_report.summary.accepted_count",
        minimum=0,
        maximum=2**31 - 1,
    )
    rejected_count = _bounded_int(
        summary.get("rejected_count"),
        "extraction_report.summary.rejected_count",
        minimum=0,
        maximum=2**31 - 1,
    )
    candidate_count = _bounded_int(
        summary.get("candidate_count"),
        "extraction_report.summary.candidate_count",
        minimum=0,
        maximum=2**31 - 1,
    )

    if accepted_count != len(contexts):
        raise BLEReceiverSchedulerContractError(
            "accepted_count does not match connection_contexts length"
        )
    if rejected_count != len(rejected):
        raise BLEReceiverSchedulerContractError(
            "rejected_count does not match rejected_candidates length"
        )
    if candidate_count != accepted_count + rejected_count:
        raise BLEReceiverSchedulerContractError(
            "candidate_count does not equal accepted_count + rejected_count"
        )

    normalized = []
    seen_ids = set()
    for context in contexts:
        item = _validate_context(
            context,
            report_source_sha256=source_sha,
        )
        context_id = item["connection_context_id"]
        if context_id in seen_ids:
            raise BLEReceiverSchedulerContractError(
                f"duplicate connection_context_id: {context_id}"
            )
        seen_ids.add(context_id)
        normalized.append(item)

    normalized.sort(
        key=lambda item: (
            item["source_frame_number"],
            item["connection_context_id"],
        )
    )

    assignment_decisions = []
    for item in normalized:
        assignment_decisions.append(
            {
                "connection_context_id": item["connection_context_id"],
                "decision": "not_assigned",
                "receiver_id": None,
                "data_channel": None,
                "blockers": list(_CURRENT_BLOCKERS),
                "evidenced_inputs": item["evidenced_inputs"],
            }
        )

    if normalized:
        status = "blocked"
        blockers = list(_CURRENT_BLOCKERS)
    else:
        status = "no_context"
        blockers = ["no_accepted_connection_context"]

    result = {
        "schema_version": BLE_RECEIVER_SCHEDULER_CONTRACT_VERSION,
        "record_type": "ble_receiver_scheduler_plan",
        "source_extraction": {
            "source_capture_sha256": source_sha,
            "accepted_context_count": len(normalized),
            "rejected_candidate_count": rejected_count,
            "connection_context_ids": [
                item["connection_context_id"] for item in normalized
            ],
        },
        "scheduler": {
            "status": status,
            "receiver_assignments_performed": False,
            "blockers": blockers,
        },
        "assignment_decisions": assignment_decisions,
        "execution": {
            "status": "offline_contract_evaluation",
            "rf_performed": False,
            "receiver_control_performed": False,
            "network_performed": False,
        },
        "limitations": [
            "rejected CONNECT_IND candidates are diagnostic only and are never scheduler inputs",
            "legacy CONNECT_IND context does not establish an actual data-channel anchor",
            "connection event counter is not inferred",
            "channel-selection algorithm is not inferred",
            "arbitrary BLE data-channel receiver control is not yet verified",
            "no receiver or data-channel assignment is emitted while these blockers remain",
        ],
    }

    if dict(extraction_report) != original:
        raise AssertionError("extraction_report was unexpectedly mutated")

    return result

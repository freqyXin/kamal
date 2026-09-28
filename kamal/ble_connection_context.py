"""Offline BLE legacy CONNECT_IND evidence normalization.

This module performs no RF operations and does not schedule receivers. It accepts
already-decoded packet fields, validates that they represent a CRC-valid legacy
CONNECT_IND observed on a primary advertising channel, and returns a deterministic
record bound to the immutable source capture hash and frame number.
"""

from __future__ import annotations

import re
from copy import deepcopy
from decimal import Decimal, InvalidOperation
from typing import Mapping


BLE_CONNECTION_CONTEXT_CONTRACT_VERSION = "0.12.0"
LEGACY_CONNECT_IND_PDU_TYPE = 5
PRIMARY_ADVERTISING_CHANNELS = frozenset({37, 38, 39})

CONNECT_IND_TSHARK_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "nordic_ble.channel",
    "nordic_ble.crcok",
    "btle.advertising_header.pdu_type",
    "btle.advertising_header.randomized_tx",
    "btle.advertising_header.randomized_rx",
    "btle.advertising_header.ch_sel",
    "btle.initiator_address",
    "btle.advertising_address",
    "btle.link_layer_data.access_address",
    "btle.link_layer_data.crc_init",
    "btle.link_layer_data.window_size",
    "btle.link_layer_data.window_offset",
    "btle.link_layer_data.interval",
    "btle.link_layer_data.latency",
    "btle.link_layer_data.timeout",
    "btle.link_layer_data.channel_map",
    "btle.link_layer_data.hop",
    "btle.link_layer_data.sleep_clock_accuracy",
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class BLEConnectionContextError(ValueError):
    """Raised when decoded packet evidence cannot satisfy the contract."""


def _nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise BLEConnectionContextError(f"{field} must be a non-empty string")
    return value.strip()


def _sha256(value, field):
    value = _nonempty(value, field)
    if not _SHA256_RE.fullmatch(value):
        raise BLEConnectionContextError(
            f"{field} must be a SHA-256 hexadecimal digest"
        )
    return value.lower()


def _uint(value, field, *, bits):
    if isinstance(value, bool):
        raise BLEConnectionContextError(f"{field} must be an unsigned integer")

    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise BLEConnectionContextError(
                f"{field} must be an unsigned integer"
            )
        try:
            if raw.lower().startswith("0x"):
                parsed = int(raw, 16)
            elif raw.isdigit():
                parsed = int(raw, 10)
            elif _HEX_RE.fullmatch(raw):
                parsed = int(raw, 16)
            else:
                raise ValueError
        except ValueError as exc:
            raise BLEConnectionContextError(
                f"{field} must be an unsigned integer"
            ) from exc
    else:
        raise BLEConnectionContextError(f"{field} must be an unsigned integer")

    if parsed < 0 or parsed > (2**bits - 1):
        raise BLEConnectionContextError(
            f"{field} must fit in {bits} unsigned bits"
        )
    return parsed


def _bounded_uint(value, field, *, bits, minimum, maximum):
    parsed = _uint(value, field, bits=bits)
    if parsed < minimum or parsed > maximum:
        raise BLEConnectionContextError(
            f"{field} must be in the range {minimum}..{maximum}"
        )
    return parsed


def _timestamp_epoch(value):
    field = "frame.time_epoch"
    raw = _nonempty(value, field)
    try:
        parsed = Decimal(raw)
    except InvalidOperation as exc:
        raise BLEConnectionContextError(
            f"{field} must be a decimal epoch timestamp"
        ) from exc
    if not parsed.is_finite():
        raise BLEConnectionContextError(
            f"{field} must be a finite decimal epoch timestamp"
        )
    return raw


def _bool(value, field):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true"}:
            return True
        if normalized in {"0", "false"}:
            return False
    raise BLEConnectionContextError(f"{field} must be boolean")


def _optional_bool(value, field):
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return _bool(value, field)


def _address(value, field):
    value = _nonempty(value, field)
    if not _ADDRESS_RE.fullmatch(value):
        raise BLEConnectionContextError(
            f"{field} must be a six-octet Bluetooth address"
        )
    return value.upper()


def _channel_map(value):
    field = "btle.link_layer_data.channel_map"
    if isinstance(value, bytes):
        raw = value.hex()
    elif isinstance(value, str):
        raw = value.strip().lower().replace(":", "").replace("-", "")
        if raw.startswith("0x"):
            raw = raw[2:]
    else:
        raise BLEConnectionContextError(
            f"{field} must be a five-byte hexadecimal value"
        )

    if len(raw) != 10 or not _HEX_RE.fullmatch(raw):
        raise BLEConnectionContextError(
            f"{field} must be a five-byte hexadecimal value"
        )

    normalized = raw.lower()
    channel_bits = int.from_bytes(bytes.fromhex(normalized), "little")
    if channel_bits >> 37:
        raise BLEConnectionContextError(
            f"{field} has nonzero reserved bits 37..39"
        )
    if (channel_bits & ((1 << 37) - 1)).bit_count() < 2:
        raise BLEConnectionContextError(
            f"{field} must mark at least two data channels as used"
        )
    return normalized


def _required(fields, name):
    try:
        value = fields[name]
    except KeyError as exc:
        raise BLEConnectionContextError(
            f"missing required decoded field: {name}"
        ) from exc

    if value is None or (isinstance(value, str) and not value.strip()):
        raise BLEConnectionContextError(
            f"missing required decoded field: {name}"
        )
    return value


def parse_legacy_connect_ind(
    fields: Mapping[str, object],
    *,
    source_capture_path: str,
    source_capture_sha256: str,
):
    """Normalize one decoded CRC-valid legacy CONNECT_IND packet.

    ``fields`` is a mapping keyed by Wireshark/TShark display-filter field name.
    The function performs no capture, subprocess, network, or RF operation.

    The result contains directly observed packet evidence only. In particular, it
    does not infer an actual data-channel anchor, connection event counter, or
    channel-selection algorithm.
    """

    if not isinstance(fields, Mapping):
        raise BLEConnectionContextError("fields must be a mapping")

    original = deepcopy(dict(fields))

    source_path = _nonempty(source_capture_path, "source_capture_path")
    source_sha = _sha256(source_capture_sha256, "source_capture_sha256")
    packet_time_epoch = _timestamp_epoch(
        _required(fields, "frame.time_epoch")
    )

    frame_number = _uint(
        _required(fields, "frame.number"),
        "frame.number",
        bits=31,
    )
    if frame_number < 1:
        raise BLEConnectionContextError("frame.number must be at least 1")

    advertising_channel = _uint(
        _required(fields, "nordic_ble.channel"),
        "nordic_ble.channel",
        bits=8,
    )
    if advertising_channel not in PRIMARY_ADVERTISING_CHANNELS:
        raise BLEConnectionContextError(
            "legacy CONNECT_IND evidence must be observed on advertising "
            "channel 37, 38, or 39"
        )

    crc_valid = _bool(
        _required(fields, "nordic_ble.crcok"),
        "nordic_ble.crcok",
    )
    if not crc_valid:
        raise BLEConnectionContextError(
            "legacy CONNECT_IND evidence requires nordic_ble.crcok=true"
        )

    pdu_type = _uint(
        _required(fields, "btle.advertising_header.pdu_type"),
        "btle.advertising_header.pdu_type",
        bits=8,
    )
    if pdu_type != LEGACY_CONNECT_IND_PDU_TYPE:
        raise BLEConnectionContextError(
            "decoded packet is not a legacy CONNECT_IND PDU"
        )

    randomized_tx = _bool(
        _required(fields, "btle.advertising_header.randomized_tx"),
        "btle.advertising_header.randomized_tx",
    )
    randomized_rx = _bool(
        _required(fields, "btle.advertising_header.randomized_rx"),
        "btle.advertising_header.randomized_rx",
    )
    connect_ind_chsel = _optional_bool(
        fields.get("btle.advertising_header.ch_sel"),
        "btle.advertising_header.ch_sel",
    )

    initiator = _address(
        _required(fields, "btle.initiator_address"),
        "btle.initiator_address",
    )
    advertiser = _address(
        _required(fields, "btle.advertising_address"),
        "btle.advertising_address",
    )

    access_address = _uint(
        _required(fields, "btle.link_layer_data.access_address"),
        "btle.link_layer_data.access_address",
        bits=32,
    )
    crc_init = _uint(
        _required(fields, "btle.link_layer_data.crc_init"),
        "btle.link_layer_data.crc_init",
        bits=24,
    )
    window_size = _bounded_uint(
        _required(fields, "btle.link_layer_data.window_size"),
        "btle.link_layer_data.window_size",
        bits=8,
        minimum=1,
        maximum=8,
    )
    window_offset = _uint(
        _required(fields, "btle.link_layer_data.window_offset"),
        "btle.link_layer_data.window_offset",
        bits=16,
    )
    interval = _bounded_uint(
        _required(fields, "btle.link_layer_data.interval"),
        "btle.link_layer_data.interval",
        bits=16,
        minimum=6,
        maximum=3200,
    )
    latency = _bounded_uint(
        _required(fields, "btle.link_layer_data.latency"),
        "btle.link_layer_data.latency",
        bits=16,
        minimum=0,
        maximum=499,
    )
    timeout = _bounded_uint(
        _required(fields, "btle.link_layer_data.timeout"),
        "btle.link_layer_data.timeout",
        bits=16,
        minimum=10,
        maximum=3200,
    )
    if window_offset > interval:
        raise BLEConnectionContextError(
            "btle.link_layer_data.window_offset must not exceed interval"
        )
    if window_size > min(8, interval - 1):
        raise BLEConnectionContextError(
            "btle.link_layer_data.window_size exceeds the CONNECT_IND transmit-window limit"
        )
    if timeout * 4 <= (latency + 1) * interval:
        raise BLEConnectionContextError(
            "CONNECT_IND supervision timeout must exceed twice the latency-adjusted connection interval"
        )

    channel_map = _channel_map(
        _required(fields, "btle.link_layer_data.channel_map")
    )
    hop = _bounded_uint(
        _required(fields, "btle.link_layer_data.hop"),
        "btle.link_layer_data.hop",
        bits=8,
        minimum=5,
        maximum=16,
    )
    sleep_clock_accuracy = _bounded_uint(
        _required(fields, "btle.link_layer_data.sleep_clock_accuracy"),
        "btle.link_layer_data.sleep_clock_accuracy",
        bits=8,
        minimum=0,
        maximum=7,
    )

    record = {
        "schema_version": BLE_CONNECTION_CONTEXT_CONTRACT_VERSION,
        "record_type": "ble_legacy_connect_ind",
        "connection_context_id": (
            f"ble-legacy-connect-ind:sha256:{source_sha}:frame:{frame_number}"
        ),
        "source_capture": {
            "path": source_path,
            "sha256": source_sha,
            "frame_number": frame_number,
        },
        "observation": {
            "directly_observed": True,
            "pdu_type": "CONNECT_IND",
            "pdu_type_code": LEGACY_CONNECT_IND_PDU_TYPE,
            "crc_valid": True,
            "advertising_channel": advertising_channel,
            "packet_time_epoch": packet_time_epoch,
            "connect_ind_chsel": connect_ind_chsel,
            "initiator": {
                "address": initiator,
                "address_type": "random" if randomized_tx else "public",
            },
            "advertiser": {
                "address": advertiser,
                "address_type": "random" if randomized_rx else "public",
            },
            "link_layer": {
                "access_address": f"0x{access_address:08x}",
                "crc_init": f"0x{crc_init:06x}",
                "window_size": window_size,
                "window_offset": window_offset,
                "interval": interval,
                "latency": latency,
                "timeout": timeout,
                "channel_map_hex": channel_map,
                "hop_increment": hop,
                "sleep_clock_accuracy_code": sleep_clock_accuracy,
            },
        },
        "execution": {
            "status": "offline_normalization",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [
            "legacy CONNECT_IND only; extended connection establishment is not represented",
            "actual data-channel connection anchor is not established by CONNECT_IND alone",
            "connection event counter is not inferred from this record",
            "channel selection algorithm is not inferred from CONNECT_IND alone",
        ],
    }

    if dict(fields) != original:
        raise AssertionError("input fields were unexpectedly mutated")

    return record

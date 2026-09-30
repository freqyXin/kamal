"""Nordic-native CONNECT_REQ sidecar reconciliation for BLE evidence.

This module performs no RF or network operations. It parses retained nRF Util
extcap control-log records that contain Nordic's native CONNECT_REQ decode and
can reconcile only the CONNECT_IND fields known to disagree with the serialized
PCAP representation. Matching is fail-closed and requires the shared connection
identity/timing fields to agree.
"""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping


NORDIC_CONNECT_REQ_SIDECAR_VERSION = "0.12.0"
DEFAULT_MATCH_WINDOW_SECONDS = Decimal("2.0")

_ADDRESS_OCTET_RE = re.compile(r"^[0-9A-Fa-f]{1,2}$")
_CONNECT_REQ_RE = re.compile(
    r"ADV_TYPE_CONNECT_REQ.*?"
    r"initiator_address: BleAddress\((?P<initiator>[0-9A-Fa-f:]+) "
    r"(?P<initiator_type>public|random)\).*?"
    r"advertising_address: BleAddress\((?P<advertiser>[0-9A-Fa-f:]+) "
    r"(?P<advertiser_type>public|random)\).*?"
    r"access_address: (?P<access_address>\d+), "
    r"crc_init: (?P<crc_init>\d+), "
    r"win_size: (?P<window_size>\d+), "
    r"win_offset: (?P<window_offset>\d+), "
    r"interval: (?P<interval>\d+), "
    r"latency: (?P<latency>\d+), "
    r"timeout: (?P<timeout>\d+), "
    r"channel_map: (?P<channel_map>\d+), "
    r"hop_length: (?P<hop>\d+), "
    r"sca: (?P<sca>\d+)"
)


class BLENordicSidecarError(ValueError):
    """Raised when Nordic-native supplemental evidence cannot be trusted."""


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_int(value, field, *, minimum, maximum):
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError) as exc:
        raise BLENordicSidecarError(f"{field} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise BLENordicSidecarError(
            f"{field} must be in the range {minimum}..{maximum}"
        )
    return parsed


def _field_uint(value, field, *, bits):
    if isinstance(value, bool):
        raise BLENordicSidecarError(f"{field} must be an unsigned integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise BLENordicSidecarError(f"{field} must be an unsigned integer")
        try:
            parsed = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
        except ValueError as exc:
            raise BLENordicSidecarError(
                f"{field} must be an unsigned integer"
            ) from exc
    else:
        raise BLENordicSidecarError(f"{field} must be an unsigned integer")
    if parsed < 0 or parsed > (2**bits - 1):
        raise BLENordicSidecarError(f"{field} must fit in {bits} unsigned bits")
    return parsed


def _field_bool(value, field):
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
    raise BLENordicSidecarError(f"{field} must be boolean")


def _address(value, field):
    if not isinstance(value, str):
        raise BLENordicSidecarError(
            f"{field} must be a six-octet Bluetooth address"
        )
    parts = value.strip().split(":")
    if len(parts) != 6 or any(
        not _ADDRESS_OCTET_RE.fullmatch(part) for part in parts
    ):
        raise BLENordicSidecarError(
            f"{field} must be a six-octet Bluetooth address"
        )
    return ":".join(f"{int(part, 16):02X}" for part in parts)


def _decimal_epoch(value, field):
    if not isinstance(value, str) or not value.strip():
        raise BLENordicSidecarError(f"{field} must be a decimal epoch timestamp")
    try:
        parsed = Decimal(value.strip())
    except InvalidOperation as exc:
        raise BLENordicSidecarError(
            f"{field} must be a decimal epoch timestamp"
        ) from exc
    if not parsed.is_finite():
        raise BLENordicSidecarError(
            f"{field} must be a finite decimal epoch timestamp"
        )
    return parsed


def load_nordic_connect_req_sidecar(path):
    """Load and hash a retained extcap control log containing native CONNECT_REQs."""

    try:
        source = Path(path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BLENordicSidecarError(
            f"Nordic control log is unavailable: {path}"
        ) from exc
    if not source.is_file():
        raise BLENordicSidecarError(
            f"Nordic control log is not a regular file: {source}"
        )

    size_before = source.stat().st_size
    if size_before <= 0:
        raise BLENordicSidecarError(f"Nordic control log is empty: {source}")
    sha_before = _sha256_file(source)

    records = []
    seen = set()
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            if "ADV_TYPE_CONNECT_REQ" not in line:
                continue
            prefix = line.split("\t", 1)[0].strip()
            timestamp = _decimal_epoch(prefix, "Nordic control-log timestamp")
            match = _CONNECT_REQ_RE.search(line)
            if match is None:
                continue
            values = match.groupdict()

            initiator = _address(values["initiator"], "native initiator")
            advertiser = _address(values["advertiser"], "native advertiser")
            access_address = _bounded_int(
                values["access_address"],
                "native access_address",
                minimum=0,
                maximum=2**32 - 1,
            )
            crc_init = _bounded_int(
                values["crc_init"],
                "native crc_init",
                minimum=0,
                maximum=2**24 - 1,
            )
            window_size = _bounded_int(
                values["window_size"],
                "native window_size",
                minimum=1,
                maximum=8,
            )
            window_offset = _bounded_int(
                values["window_offset"],
                "native window_offset",
                minimum=0,
                maximum=2**16 - 1,
            )
            interval = _bounded_int(
                values["interval"],
                "native interval",
                minimum=6,
                maximum=3200,
            )
            latency = _bounded_int(
                values["latency"],
                "native latency",
                minimum=0,
                maximum=499,
            )
            timeout = _bounded_int(
                values["timeout"],
                "native timeout",
                minimum=10,
                maximum=3200,
            )
            channel_map = _bounded_int(
                values["channel_map"],
                "native channel_map",
                minimum=0,
                maximum=2**40 - 1,
            )
            channel_map_hex = f"{channel_map:010x}"
            channel_bits = int.from_bytes(bytes.fromhex(channel_map_hex), "little")
            if channel_bits >> 37:
                raise BLENordicSidecarError(
                    "native channel_map has nonzero reserved bits 37..39"
                )
            if (channel_bits & ((1 << 37) - 1)).bit_count() < 2:
                raise BLENordicSidecarError(
                    "native channel_map must enable at least two data channels"
                )
            hop = _bounded_int(
                values["hop"],
                "native hop",
                minimum=5,
                maximum=16,
            )
            sca = _bounded_int(
                values["sca"],
                "native sca",
                minimum=0,
                maximum=7,
            )

            record = {
                "timestamp_epoch": format(timestamp, "f"),
                "line_number": line_number,
                "initiator": initiator,
                "initiator_type": values["initiator_type"],
                "advertiser": advertiser,
                "advertiser_type": values["advertiser_type"],
                "access_address": access_address,
                "crc_init": crc_init,
                "window_size": window_size,
                "window_offset": window_offset,
                "interval": interval,
                "latency": latency,
                "timeout": timeout,
                "channel_map_hex": channel_map_hex,
                "hop_increment": hop,
                "sleep_clock_accuracy_code": sca,
            }
            identity = tuple(record.items())
            if identity not in seen:
                seen.add(identity)
                records.append(record)

    size_after = source.stat().st_size
    sha_after = _sha256_file(source)
    if size_after != size_before or sha_after != sha_before:
        raise BLENordicSidecarError(
            "Nordic control log changed while being loaded"
        )

    return {
        "source": {
            "path": str(source),
            "sha256": sha_before,
            "size_bytes": size_before,
            "format": "kamal_extcap_control_log",
        },
        "records": records,
    }


def verify_nordic_connect_req_sidecar_unchanged(sidecar):
    """Verify a previously loaded sidecar source still matches its bound hash."""

    if not isinstance(sidecar, Mapping):
        raise BLENordicSidecarError("sidecar must be an object")
    source = sidecar.get("source")
    if not isinstance(source, Mapping):
        raise BLENordicSidecarError("sidecar.source must be an object")
    try:
        path = Path(source["path"]).resolve(strict=True)
        expected_sha = source["sha256"]
        expected_size = source["size_bytes"]
    except (KeyError, OSError, RuntimeError) as exc:
        raise BLENordicSidecarError("sidecar source metadata is incomplete") from exc
    if path.stat().st_size != expected_size or _sha256_file(path) != expected_sha:
        raise BLENordicSidecarError(
            "Nordic control log changed during CONNECT_IND extraction"
        )


def reconcile_connect_ind_fields(
    fields,
    records,
    *,
    max_time_delta=DEFAULT_MATCH_WINDOW_SECONDS,
):
    """Return a copy with only channel map, Hop, and SCA supplemented.

    Matching requires address/type, access address, CRCInit, transmit-window,
    interval, latency, and timeout agreement. Among exact matches, the nearest
    native timestamp inside ``max_time_delta`` is selected; a tied nearest match
    fails closed.
    """

    if not isinstance(fields, Mapping):
        raise BLENordicSidecarError("fields must be an object")
    if not isinstance(records, list):
        raise BLENordicSidecarError("records must be an array")
    if not isinstance(max_time_delta, Decimal):
        max_time_delta = Decimal(str(max_time_delta))
    if max_time_delta <= 0:
        raise BLENordicSidecarError("max_time_delta must be greater than zero")

    timestamp = _decimal_epoch(fields.get("frame.time_epoch"), "frame.time_epoch")
    initiator = _address(fields.get("btle.initiator_address"), "initiator")
    advertiser = _address(fields.get("btle.advertising_address"), "advertiser")
    initiator_type = (
        "random"
        if _field_bool(
            fields.get("btle.advertising_header.randomized_tx"),
            "btle.advertising_header.randomized_tx",
        )
        else "public"
    )
    advertiser_type = (
        "random"
        if _field_bool(
            fields.get("btle.advertising_header.randomized_rx"),
            "btle.advertising_header.randomized_rx",
        )
        else "public"
    )

    shared = {
        "access_address": _field_uint(
            fields.get("btle.link_layer_data.access_address"),
            "btle.link_layer_data.access_address",
            bits=32,
        ),
        "crc_init": _field_uint(
            fields.get("btle.link_layer_data.crc_init"),
            "btle.link_layer_data.crc_init",
            bits=24,
        ),
        "window_size": _field_uint(
            fields.get("btle.link_layer_data.window_size"),
            "btle.link_layer_data.window_size",
            bits=8,
        ),
        "window_offset": _field_uint(
            fields.get("btle.link_layer_data.window_offset"),
            "btle.link_layer_data.window_offset",
            bits=16,
        ),
        "interval": _field_uint(
            fields.get("btle.link_layer_data.interval"),
            "btle.link_layer_data.interval",
            bits=16,
        ),
        "latency": _field_uint(
            fields.get("btle.link_layer_data.latency"),
            "btle.link_layer_data.latency",
            bits=16,
        ),
        "timeout": _field_uint(
            fields.get("btle.link_layer_data.timeout"),
            "btle.link_layer_data.timeout",
            bits=16,
        ),
    }

    matches = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if record.get("initiator") != initiator:
            continue
        if record.get("advertiser") != advertiser:
            continue
        if record.get("initiator_type") != initiator_type:
            continue
        if record.get("advertiser_type") != advertiser_type:
            continue
        if any(record.get(name) != value for name, value in shared.items()):
            continue
        record_time = _decimal_epoch(
            record.get("timestamp_epoch"),
            "native timestamp_epoch",
        )
        delta = abs(record_time - timestamp)
        if delta <= max_time_delta:
            matches.append((delta, record))

    if not matches:
        raise BLENordicSidecarError(
            "no Nordic native CONNECT_REQ matches the PCAP candidate"
        )

    matches.sort(key=lambda item: item[0])
    if len(matches) > 1 and matches[0][0] == matches[1][0]:
        raise BLENordicSidecarError(
            "Nordic native CONNECT_REQ match is timestamp-ambiguous"
        )

    delta, selected = matches[0]
    reconciled = dict(fields)
    supplemented = {
        "btle.link_layer_data.channel_map": selected["channel_map_hex"],
        "btle.link_layer_data.hop": str(selected["hop_increment"]),
        "btle.link_layer_data.sleep_clock_accuracy": str(
            selected["sleep_clock_accuracy_code"]
        ),
    }
    original = {name: fields.get(name) for name in supplemented}
    reconciled.update(supplemented)

    return reconciled, {
        "status": "nordic_native_sidecar_reconciliation",
        "source_record": {
            "line_number": selected["line_number"],
            "timestamp_epoch": selected["timestamp_epoch"],
            "match_time_delta_seconds": format(delta, "f"),
        },
        "matched_fields": [
            "initiator_address",
            "initiator_address_type",
            "advertiser_address",
            "advertiser_address_type",
            "access_address",
            "crc_init",
            "window_size",
            "window_offset",
            "interval",
            "latency",
            "timeout",
        ],
        "supplemented_fields": {
            name: {
                "pcap_decoded": original[name],
                "nordic_native": value,
            }
            for name, value in supplemented.items()
        },
        "policy": (
            "only channel_map, hop, and sleep_clock_accuracy may be supplemented; "
            "shared connection identity/timing fields must match"
        ),
    }

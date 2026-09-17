"""Offline Bluetooth assigned-identifier resolution."""

import json
import re
from pathlib import Path


REGISTRY_DIR = Path(__file__).resolve().parent.parent / "data" / "bluetooth"

HEX_ID = re.compile(r"^(?:0x)?[0-9a-fA-F]{1,8}$")


def normalize_identifier(value, bits):
    """Return a canonical hexadecimal identifier or None."""
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not HEX_ID.fullmatch(value):
        return None

    number = int(value, 16)

    if number >= (1 << bits):
        return None

    return f"0x{number:0{bits // 4}x}"


BLUETOOTH_BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def normalize_bluetooth_uuid16(value):
    """Return a 16-bit assigned number from a Bluetooth UUID, or None.

    Accepts ordinary 16-bit hexadecimal identifiers and 128-bit UUIDs using
    the Bluetooth Base UUID. Vendor-specific 128-bit UUIDs are not reduced or
    inferred.
    """
    normalized = normalize_identifier(value, 16)
    if normalized is not None:
        return normalized

    if not isinstance(value, str):
        return None

    uuid = value.strip().lower()
    if (
        len(uuid) == 36
        and uuid.startswith("0000")
        and uuid.endswith(BLUETOOTH_BASE_UUID_SUFFIX)
    ):
        return normalize_identifier(uuid[4:8], 16)

    return None


def resolve_gatt_uuid(value, namespace, registry):
    """Resolve a GATT UUID in one explicitly selected assigned namespace."""
    normalized = normalize_bluetooth_uuid16(value)

    if normalized is None:
        return {
            "id": value,
            "name": None,
            "status": "unknown",
            "namespace": namespace,
            "identity_inference": False,
        }

    name = registry["identifiers"].get(normalized)

    return {
        "id": normalized,
        "name": name,
        "status": "assigned" if name is not None else "unknown",
        "namespace": namespace,
        "identity_inference": False,
    }


def load_registry(filename):
    """Load a versioned local identifier registry."""
    path = REGISTRY_DIR / filename

    with path.open(encoding="utf-8") as stream:
        registry = json.load(stream)

    if not isinstance(registry, dict):
        raise ValueError(f"Invalid registry: {path}")

    if not isinstance(registry.get("identifiers"), dict):
        raise ValueError(f"Missing identifiers: {path}")

    return registry


def resolve_identifier(value, bits, registry):
    """Resolve an assigned identifier without inferring device identity."""
    normalized = normalize_identifier(value, bits)

    if normalized is None:
        return {
            "id": value,
            "name": None,
            "status": "invalid",
            "identity_inference": False,
        }

    name = registry["identifiers"].get(normalized)

    return {
        "id": normalized,
        "name": name,
        "status": "assigned" if name is not None else "unknown",
        "identity_inference": False,
    }


def resolve_uuid16(value, service_registry, member_registry):
    """Resolve a 16-bit UUID against Bluetooth SIG UUID namespaces.

    Standard service UUIDs are checked first, followed by member-assigned
    UUIDs. The result describes the assigned-number namespace only; it does
    not infer physical device identity or GATT enumeration.
    """
    normalized = normalize_identifier(value, 16)

    if normalized is None:
        return {
            "id": value,
            "name": None,
            "status": "invalid",
            "namespace": None,
            "identity_inference": False,
            "gatt_enumerated": False,
        }

    name = service_registry["identifiers"].get(normalized)
    if name is not None:
        return {
            "id": normalized,
            "name": name,
            "status": "assigned",
            "namespace": "service",
            "identity_inference": False,
            "gatt_enumerated": False,
        }

    name = member_registry["identifiers"].get(normalized)
    if name is not None:
        return {
            "id": normalized,
            "name": name,
            "status": "assigned",
            "namespace": "member",
            "identity_inference": False,
            "gatt_enumerated": False,
        }

    return {
        "id": normalized,
        "name": None,
        "status": "unknown",
        "namespace": None,
        "identity_inference": False,
        "gatt_enumerated": False,
    }

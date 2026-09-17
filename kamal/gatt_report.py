"""Structured evidence for active BLE GATT enumeration."""

from datetime import datetime, timezone


SCHEMA_VERSION = "0.6.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def new_report(target, adapter):
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_type": "active_gatt",
        "timestamp_utc": utc_now(),
        "target": target,
        "adapter": adapter,
        "connection": {
            "attempted": False,
            "connected": False,
            "error": None,
        },
        "gatt": {
            "enumeration_attempted": False,
            "enumerated": False,
            "error": None,
            "services": [],
        },
        "disconnect": {
            "attempted": False,
            "completed": False,
            "error": None,
        },
        "operations": {
            "characteristic_reads": False,
            "characteristic_writes": False,
            "notifications": False,
            "pairing_requested": False,
        },
    }


def serialize_services(services):
    """Serialize GATT metadata without reading characteristic values."""
    result = []

    for service in sorted(services, key=lambda item: item.handle):
        characteristics = []

        for characteristic in sorted(service.characteristics, key=lambda item: item.handle):
            descriptors = [
                {
                    "handle": descriptor.handle,
                    "uuid": descriptor.uuid,
                }
                for descriptor in sorted(characteristic.descriptors, key=lambda item: item.handle)
            ]

            characteristics.append({
                "handle": characteristic.handle,
                "uuid": characteristic.uuid,
                "properties": list(characteristic.properties),
                "descriptors": descriptors,
            })

        result.append({
            "handle": service.handle,
            "uuid": service.uuid,
            "characteristics": characteristics,
        })

    return result

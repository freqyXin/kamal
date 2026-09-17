"""Structured evidence for active BLE GATT enumeration."""

from datetime import datetime, timezone

from kamal.identifiers import resolve_gatt_uuid


SCHEMA_VERSION = "0.7.0"


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


def serialize_services(services, registries=None):
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

            if registries is not None:
                for item in descriptors:
                    item["resolution"] = resolve_gatt_uuid(
                        item["uuid"],
                        "descriptor",
                        registries["descriptor"],
                    )

            characteristic_record = {
                "handle": characteristic.handle,
                "uuid": characteristic.uuid,
                "properties": list(characteristic.properties),
                "descriptors": descriptors,
            }

            if registries is not None:
                characteristic_record["resolution"] = resolve_gatt_uuid(
                    characteristic.uuid,
                    "characteristic",
                    registries["characteristic"],
                )

            characteristics.append(characteristic_record)

        service_record = {
            "handle": service.handle,
            "uuid": service.uuid,
            "characteristics": characteristics,
        }

        if registries is not None:
            service_record["resolution"] = resolve_gatt_uuid(
                service.uuid,
                "service",
                registries["service"],
            )

        result.append(service_record)

    return result

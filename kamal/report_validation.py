"""Structural validation of supported K'amal source reports."""


def require_object(value, path):
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def require_field(obj, name, expected, path):
    if name not in obj:
        raise ValueError(f"{path}.{name} is required")

    value = obj[name]

    # bool is a subclass of int in Python; reject it for integer fields.
    if expected is int:
        valid = type(value) is int
    else:
        valid = isinstance(value, expected)

    if not valid:
        raise ValueError(f"{path}.{name} has an invalid type")

    return value


def require_nullable_string(obj, name, path):
    if name not in obj:
        raise ValueError(f"{path}.{name} is required")

    value = obj[name]
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{path}.{name} must be a string or null")


def require_boolean_fields(obj, names, path):
    for name in names:
        require_field(obj, name, bool, path)


def validate_passive(report):
    path = "passive"

    require_field(report, "source_pcap", str, path)
    require_nullable_string(report, "source_metadata", path)

    advertisers = require_field(report, "advertisers", list, path)
    count = require_field(report, "advertiser_count", int, path)

    if count < 0 or count != len(advertisers):
        raise ValueError("passive.advertiser_count does not match advertisers")

    skipped = require_field(
        report, "skipped_ambiguous_packets", int, path
    )
    if skipped < 0:
        raise ValueError("passive.skipped_ambiguous_packets must be nonnegative")

    require_field(report, "warnings", list, path)
    require_field(report, "scan_request_targets", list, path)

    integrity = require_field(report, "integrity", dict, path)
    require_field(integrity, "scope", str, "passive.integrity")

    for name in ("valid", "invalid", "unknown"):
        value = require_field(
            integrity, name, int, "passive.integrity"
        )
        if value < 0:
            raise ValueError(
                f"passive.integrity.{name} must be nonnegative"
            )

    registries = require_field(
        report, "identifier_registries", dict, path
    )

    for name in (
        "company_identifiers",
        "service_uuids",
        "member_uuids",
    ):
        registry = require_field(
            registries, name, dict, "passive.identifier_registries"
        )

        for field in (
            "source",
            "source_commit",
            "source_file",
            "generated_at_utc",
        ):
            require_nullable_string(
                registry,
                field,
                f"passive.identifier_registries.{name}",
            )

    for index, advertiser in enumerate(advertisers):
        require_object(advertiser, f"passive.advertisers[{index}]")

    for index, target in enumerate(report["scan_request_targets"]):
        require_object(target, f"passive.scan_request_targets[{index}]")

    for index, warning in enumerate(report["warnings"]):
        if not isinstance(warning, str):
            raise ValueError(f"passive.warnings[{index}] must be a string")


def validate_active(report):
    path = "active"

    require_field(report, "timestamp_utc", str, path)
    require_field(report, "target", str, path)
    require_field(report, "adapter", str, path)

    connection = require_field(report, "connection", dict, path)
    require_boolean_fields(
        connection,
        ("attempted", "connected"),
        "active.connection",
    )
    require_nullable_string(connection, "error", "active.connection")

    gatt = require_field(report, "gatt", dict, path)
    require_boolean_fields(
        gatt,
        ("enumeration_attempted", "enumerated"),
        "active.gatt",
    )
    require_nullable_string(gatt, "error", "active.gatt")
    services = require_field(gatt, "services", list, "active.gatt")

    disconnect = require_field(report, "disconnect", dict, path)
    require_boolean_fields(
        disconnect,
        ("attempted", "completed"),
        "active.disconnect",
    )
    require_nullable_string(disconnect, "error", "active.disconnect")

    operations = require_field(report, "operations", dict, path)
    require_boolean_fields(
        operations,
        (
            "characteristic_reads",
            "characteristic_writes",
            "notifications",
            "pairing_requested",
        ),
        "active.operations",
    )

    if "authorization" in report:
        authorization = require_field(report, "authorization", dict, path)
        authorization_id = require_field(
            authorization, "authorization_id", str, "active.authorization"
        )
        sha256 = require_field(
            authorization, "sha256", str, "active.authorization"
        )
        operation_class = require_field(
            authorization, "operation_class", str, "active.authorization"
        )
        if not authorization_id.strip():
            raise ValueError("active.authorization.authorization_id must not be empty")
        if len(sha256) != 64:
            raise ValueError("active.authorization.sha256 must be a SHA-256 digest")
        try:
            int(sha256, 16)
        except ValueError as exc:
            raise ValueError(
                "active.authorization.sha256 must be a SHA-256 digest"
            ) from exc
        if operation_class != "enumerate_gatt_metadata":
            raise ValueError(
                "active.authorization.operation_class must be enumerate_gatt_metadata"
            )

    for index, service in enumerate(services):
        service_path = f"active.gatt.services[{index}]"
        require_object(service, service_path)
        require_field(service, "handle", int, service_path)
        require_field(service, "uuid", str, service_path)

        characteristics = require_field(
            service, "characteristics", list, service_path
        )

        for char_index, characteristic in enumerate(characteristics):
            char_path = (
                f"{service_path}.characteristics[{char_index}]"
            )
            require_object(characteristic, char_path)
            require_field(characteristic, "handle", int, char_path)
            require_field(characteristic, "uuid", str, char_path)
            require_field(characteristic, "properties", list, char_path)

            for property_index, prop in enumerate(
                characteristic["properties"]
            ):
                if not isinstance(prop, str):
                    raise ValueError(
                        f"{char_path}.properties[{property_index}] "
                        "must be a string"
                    )

            descriptors = require_field(
                characteristic, "descriptors", list, char_path
            )

            for desc_index, descriptor in enumerate(descriptors):
                desc_path = f"{char_path}.descriptors[{desc_index}]"
                require_object(descriptor, desc_path)
                require_field(descriptor, "handle", int, desc_path)
                require_field(descriptor, "uuid", str, desc_path)

    # Failure is valid evidence. Check only impossible state combinations.
    if connection["connected"] and not connection["attempted"]:
        raise ValueError("active.connection.connected requires attempted")

    if gatt["enumeration_attempted"] and not connection["connected"]:
        raise ValueError(
            "active.gatt.enumeration_attempted requires connected"
        )

    if gatt["enumerated"] and not gatt["enumeration_attempted"]:
        raise ValueError(
            "active.gatt.enumerated requires enumeration_attempted"
        )

    if disconnect["completed"] and not disconnect["attempted"]:
        raise ValueError("active.disconnect.completed requires attempted")


def validate_report(report, evidence_type):
    require_object(report, "report")

    if evidence_type == "passive_ble":
        if report.get("schema_version") != "0.6.0":
            raise ValueError("Unsupported passive report schema")
        validate_passive(report)
    elif evidence_type == "active_gatt":
        if (
            report.get("schema_version") != "0.7.0"
            or report.get("evidence_type") != "active_gatt"
        ):
            raise ValueError("Unsupported active report schema")
        validate_active(report)
    else:
        raise ValueError(f"Unsupported evidence type: {evidence_type}")

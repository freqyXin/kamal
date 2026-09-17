import unittest

from kamal.identifiers import (
    normalize_bluetooth_uuid16,
    resolve_gatt_uuid,
)


class GattIdentifierTests(unittest.TestCase):
    def test_short_uuid16(self):
        self.assertEqual(
            normalize_bluetooth_uuid16("0x1800"),
            "0x1800",
        )

    def test_bluetooth_base_service_uuid(self):
        self.assertEqual(
            normalize_bluetooth_uuid16(
                "00001800-0000-1000-8000-00805F9B34FB"
            ),
            "0x1800",
        )

    def test_bluetooth_base_characteristic_uuid(self):
        self.assertEqual(
            normalize_bluetooth_uuid16(
                "00002a00-0000-1000-8000-00805f9b34fb"
            ),
            "0x2a00",
        )

    def test_bluetooth_base_descriptor_uuid(self):
        self.assertEqual(
            normalize_bluetooth_uuid16(
                "00002902-0000-1000-8000-00805f9b34fb"
            ),
            "0x2902",
        )

    def test_32bit_bluetooth_uuid_is_not_reduced(self):
        self.assertIsNone(
            normalize_bluetooth_uuid16(
                "12341800-0000-1000-8000-00805f9b34fb"
            )
        )

    def test_vendor_uuid_is_not_reduced(self):
        self.assertIsNone(
            normalize_bluetooth_uuid16(
                "736d6170-0000-0001-8000-00805f9b34fb"
            )
        )

    def test_resolve_gatt_characteristic(self):
        registry = {
            "identifiers": {
                "0x2a00": "Device Name",
            }
        }

        result = resolve_gatt_uuid(
            "00002a00-0000-1000-8000-00805f9b34fb",
            "characteristic",
            registry,
        )

        self.assertEqual(result["id"], "0x2a00")
        self.assertEqual(result["name"], "Device Name")
        self.assertEqual(result["status"], "assigned")
        self.assertEqual(result["namespace"], "characteristic")
        self.assertFalse(result["identity_inference"])

    def test_unknown_assigned_number(self):
        registry = {"identifiers": {}}

        result = resolve_gatt_uuid(
            "00002aff-0000-1000-8000-00805f9b34fb",
            "characteristic",
            registry,
        )

        self.assertEqual(result["id"], "0x2aff")
        self.assertIsNone(result["name"])
        self.assertEqual(result["status"], "unknown")

    def test_vendor_uuid_remains_raw(self):
        registry = {"identifiers": {}}
        uuid = "736d6170-0000-0001-8000-00805f9b34fb"

        result = resolve_gatt_uuid(
            uuid,
            "service",
            registry,
        )

        self.assertEqual(result["id"], uuid)
        self.assertIsNone(result["name"])
        self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()

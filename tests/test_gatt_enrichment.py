import unittest
from types import SimpleNamespace

from kamal.gatt_report import serialize_services


class GattEnrichmentTests(unittest.TestCase):
    def test_service_characteristic_descriptor_resolution(self):
        descriptor = SimpleNamespace(
            handle=4,
            uuid="00002902-0000-1000-8000-00805f9b34fb",
        )

        characteristic = SimpleNamespace(
            handle=3,
            uuid="00002a00-0000-1000-8000-00805f9b34fb",
            properties=["read"],
            descriptors=[descriptor],
        )

        service = SimpleNamespace(
            handle=1,
            uuid="00001800-0000-1000-8000-00805f9b34fb",
            characteristics=[characteristic],
        )

        registries = {
            "service": {
                "identifiers": {"0x1800": "GAP"},
            },
            "characteristic": {
                "identifiers": {"0x2a00": "Device Name"},
            },
            "descriptor": {
                "identifiers": {
                    "0x2902": "Client Characteristic Configuration"
                },
            },
        }

        result = serialize_services([service], registries)

        service_record = result[0]
        characteristic_record = service_record["characteristics"][0]
        descriptor_record = characteristic_record["descriptors"][0]

        self.assertEqual(service_record["resolution"]["name"], "GAP")
        self.assertEqual(
            characteristic_record["resolution"]["name"],
            "Device Name",
        )
        self.assertEqual(
            descriptor_record["resolution"]["name"],
            "Client Characteristic Configuration",
        )

        self.assertEqual(service_record["resolution"]["namespace"], "service")
        self.assertEqual(
            characteristic_record["resolution"]["namespace"],
            "characteristic",
        )
        self.assertEqual(
            descriptor_record["resolution"]["namespace"],
            "descriptor",
        )

        self.assertEqual(service_record["uuid"], service.uuid)
        self.assertEqual(characteristic_record["uuid"], characteristic.uuid)
        self.assertEqual(descriptor_record["uuid"], descriptor.uuid)

    def test_vendor_uuid_remains_unresolved(self):
        uuid = "736d6170-0000-0001-8000-00805f9b34fb"

        service = SimpleNamespace(
            handle=1,
            uuid=uuid,
            characteristics=[],
        )

        registries = {
            "service": {"identifiers": {"0x1800": "GAP"}},
            "characteristic": {"identifiers": {}},
            "descriptor": {"identifiers": {}},
        }

        result = serialize_services([service], registries)

        self.assertEqual(result[0]["uuid"], uuid)
        self.assertIsNone(result[0]["resolution"]["name"])
        self.assertEqual(result[0]["resolution"]["status"], "unknown")

    def test_without_registries_preserves_original_structure(self):
        service = SimpleNamespace(
            handle=1,
            uuid="00001800-0000-1000-8000-00805f9b34fb",
            characteristics=[],
        )

        result = serialize_services([service])

        self.assertEqual(
            result,
            [{
                "handle": 1,
                "uuid": service.uuid,
                "characteristics": [],
            }],
        )


if __name__ == "__main__":
    unittest.main()

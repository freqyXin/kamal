"""Tests for offline Bluetooth identifier resolution."""

import unittest

from kamal.identifiers import normalize_identifier, resolve_identifier, resolve_uuid16


class IdentifierTests(unittest.TestCase):

    def test_normalization(self):
        self.assertEqual(normalize_identifier("0x4c", 16), "0x004c")
        self.assertEqual(normalize_identifier("FE07", 16), "0xfe07")
        self.assertEqual(normalize_identifier("0x180f", 16), "0x180f")

    def test_invalid_identifiers(self):
        self.assertIsNone(normalize_identifier("0x10000", 16))
        self.assertIsNone(normalize_identifier("not-a-uuid", 16))

    def test_assigned_identifier(self):
        registry = {
            "identifiers": {
                "0x004c": "Example Assigned Company"
            }
        }

        result = resolve_identifier("0x4c", 16, registry)

        self.assertEqual(result["status"], "assigned")
        self.assertEqual(result["name"], "Example Assigned Company")
        self.assertFalse(result["identity_inference"])

    def test_unknown_identifier(self):
        registry = {"identifiers": {}}

        result = resolve_identifier("0xfe07", 16, registry)

        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["name"])
        self.assertFalse(result["identity_inference"])


    def test_standard_service_uuid_namespace(self):
        services = {"identifiers": {"0x180f": "Battery"}}
        members = {"identifiers": {}}

        result = resolve_uuid16("0x180f", services, members)

        self.assertEqual(result["name"], "Battery")
        self.assertEqual(result["namespace"], "service")
        self.assertFalse(result["identity_inference"])
        self.assertFalse(result["gatt_enumerated"])

    def test_member_uuid_namespace(self):
        services = {"identifiers": {}}
        members = {"identifiers": {"0xfe07": "Sonos, Inc."}}

        result = resolve_uuid16("FE07", services, members)

        self.assertEqual(result["id"], "0xfe07")
        self.assertEqual(result["name"], "Sonos, Inc.")
        self.assertEqual(result["namespace"], "member")
        self.assertFalse(result["identity_inference"])
        self.assertFalse(result["gatt_enumerated"])

    def test_unknown_uuid_namespace(self):
        services = {"identifiers": {}}
        members = {"identifiers": {}}

        result = resolve_uuid16("0xabcd", services, members)

        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["namespace"])
        self.assertFalse(result["identity_inference"])
        self.assertFalse(result["gatt_enumerated"])


if __name__ == "__main__":
    unittest.main()

import unittest
from types import SimpleNamespace

from kamal.gatt_report import new_report, serialize_services


class GattReportTests(unittest.TestCase):

    def test_initial_report_does_not_claim_connection(self):
        report = new_report("AA:BB:CC:DD:EE:FF", "hci0")

        self.assertEqual(report["evidence_type"], "active_gatt")
        self.assertFalse(report["connection"]["attempted"])
        self.assertFalse(report["connection"]["connected"])
        self.assertFalse(report["gatt"]["enumerated"])
        self.assertEqual(report["gatt"]["services"], [])
        self.assertFalse(report["disconnect"]["attempted"])
        self.assertFalse(report["disconnect"]["completed"])
        self.assertIsNone(report["disconnect"]["error"])

    def test_authorization_provenance_is_optional_and_preserved(self):
        authorization = {
            "authorization_id": "auth:survey-1",
            "sha256": "a" * 64,
            "operation_class": "enumerate_gatt_metadata",
        }
        report = new_report(
            "AA:BB:CC:DD:EE:FF",
            "hci0",
            authorization=authorization,
        )

        self.assertEqual(report["authorization"], authorization)
        authorization["authorization_id"] = "mutated"
        self.assertEqual(
            report["authorization"]["authorization_id"],
            "auth:survey-1",
        )

    def test_operations_default_to_false(self):
        report = new_report("AA:BB:CC:DD:EE:FF", "hci0")

        self.assertTrue(
            all(value is False for value in report["operations"].values())
        )

    def test_service_characteristic_descriptor_serialization(self):
        descriptor = SimpleNamespace(
            handle=3,
            uuid="00002902-0000-1000-8000-00805f9b34fb",
        )

        characteristic = SimpleNamespace(
            handle=2,
            uuid="00002a00-0000-1000-8000-00805f9b34fb",
            properties=["read"],
            descriptors=[descriptor],
        )

        service = SimpleNamespace(
            handle=1,
            uuid="00001800-0000-1000-8000-00805f9b34fb",
            characteristics=[characteristic],
        )

        result = serialize_services([service])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["handle"], 1)
        self.assertEqual(
            result[0]["characteristics"][0]["properties"],
            ["read"],
        )
        self.assertEqual(
            result[0]["characteristics"][0]["descriptors"][0]["handle"],
            3,
        )

    def test_serialization_sorts_all_handles(self):
        def descriptor(handle):
            return SimpleNamespace(handle=handle, uuid=f"descriptor-{handle}")

        def characteristic(handle):
            return SimpleNamespace(
                handle=handle,
                uuid=f"characteristic-{handle}",
                properties=["read"],
                descriptors=[descriptor(9), descriptor(3)],
            )

        def service(handle):
            return SimpleNamespace(
                handle=handle,
                uuid=f"service-{handle}",
                characteristics=[characteristic(8), characteristic(2)],
            )

        result = serialize_services([service(37), service(11)])

        self.assertEqual([s["handle"] for s in result], [11, 37])

        for service_result in result:
            self.assertEqual(
                [c["handle"] for c in service_result["characteristics"]],
                [2, 8],
            )

            for characteristic_result in service_result["characteristics"]:
                self.assertEqual(
                    [d["handle"] for d in characteristic_result["descriptors"]],
                    [3, 9],
                )

    def test_empty_services_remain_empty(self):
        self.assertEqual(serialize_services([]), [])


if __name__ == "__main__":
    unittest.main()

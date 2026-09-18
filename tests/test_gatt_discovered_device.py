import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.test_gatt_lifecycle import module, FakeClient


class DiscoveredDeviceTests(unittest.TestCase):
    def test_inspects_without_rescanning(self):
        device = SimpleNamespace(
            name="Authorized Lab Device",
            address="AA:BB:CC:DD:EE:FF",
        )
        advertisement = SimpleNamespace(
            rssi=-50,
            service_uuids=[],
        )
        client = FakeClient()

        async def unexpected_discovery(*args, **kwargs):
            raise AssertionError("Unexpected second BLE scan")

        with (
            patch.object(module, "find_target", unexpected_discovery),
            patch.object(module, "BleakClient", return_value=client),
        ):
            report, status = asyncio.run(
                module.inspect_discovered_device(
                    device=device,
                    adv=advertisement,
                    adapter="hci0",
                    timeout=3,
                )
            )

        self.assertEqual(status, 0)
        self.assertTrue(report["discovery"]["found"])
        self.assertTrue(report["gatt"]["enumerated"])
        self.assertTrue(report["disconnect"]["completed"])
        self.assertEqual(client.disconnect_calls, 1)


if __name__ == "__main__":
    unittest.main()

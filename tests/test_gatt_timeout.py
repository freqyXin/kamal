import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.test_gatt_lifecycle import module


class HangingClient:
    def __init__(self):
        self.is_connected = False
        self.disconnect_calls = 0

    async def connect(self):
        await asyncio.Event().wait()

    async def disconnect(self):
        self.disconnect_calls += 1
        self.is_connected = False


class GattTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_connection_timeout_attempts_cleanup(self):
        device = SimpleNamespace(
            name="Authorized Lab Device",
            address="AA:BB:CC:DD:EE:FF",
        )
        advertisement = SimpleNamespace(
            rssi=-50,
            service_uuids=[],
        )
        client = HangingClient()

        with patch.object(module, "BleakClient", return_value=client):
            report, status = await asyncio.wait_for(
                module.inspect_discovered_device(
                    device=device,
                    adv=advertisement,
                    adapter="hci0",
                    timeout=0.01,
                ),
                timeout=1,
            )

        self.assertEqual(status, 4)
        self.assertIn("Timeout", report["connection"]["error"])
        self.assertTrue(report["disconnect"]["attempted"])
        self.assertTrue(report["disconnect"]["completed"])
        self.assertEqual(client.disconnect_calls, 1)


if __name__ == "__main__":
    unittest.main()

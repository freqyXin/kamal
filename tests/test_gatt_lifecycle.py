import asyncio
import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "kamal-gatt"

from importlib.machinery import SourceFileLoader

loader = SourceFileLoader("kamal_gatt_cli", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class FakeClient:
    def __init__(
        self,
        *,
        connect_error=None,
        connected_after_connect=True,
        disconnect_error=None,
        remains_connected=False,
        services=None,
    ):
        self.connect_error = connect_error
        self.connected_after_connect = connected_after_connect
        self.disconnect_error = disconnect_error
        self.remains_connected = remains_connected
        self._services = services if services is not None else []
        self.is_connected = False
        self.disconnect_calls = 0

    async def connect(self):
        self.is_connected = self.connected_after_connect
        if self.connect_error:
            raise self.connect_error

    async def disconnect(self):
        self.disconnect_calls += 1
        if self.disconnect_error:
            raise self.disconnect_error
        self.is_connected = self.remains_connected

    @property
    def services(self):
        return self._services


class GattLifecycleTests(unittest.TestCase):
    def inspect(self, client):
        device = SimpleNamespace(
            name="Test Device",
            address="AA:BB:CC:DD:EE:FF",
        )
        adv = SimpleNamespace(
            rssi=-50,
            service_uuids=["00001800-0000-1000-8000-00805f9b34fb"],
        )

        async def fake_find_target(*args):
            return device, adv

        with (
            patch.object(module, "find_target", fake_find_target),
            patch.object(module, "BleakClient", return_value=client),
        ):
            return asyncio.run(
                module.inspect_target(device.address, "hci0", 3)
            )

    def test_success_disconnects(self):
        client = FakeClient()
        report, status = self.inspect(client)

        self.assertEqual(status, 0)
        self.assertTrue(report["connection"]["connected"])
        self.assertTrue(report["gatt"]["enumerated"])
        self.assertTrue(report["disconnect"]["completed"])
        self.assertEqual(client.disconnect_calls, 1)

    def test_partial_connection_failure_attempts_cleanup(self):
        client = FakeClient(
            connect_error=RuntimeError("connection failed"),
        )
        report, status = self.inspect(client)

        self.assertEqual(status, 4)
        self.assertFalse(report["gatt"]["enumeration_attempted"])
        self.assertTrue(report["disconnect"]["attempted"])
        self.assertTrue(report["disconnect"]["completed"])
        self.assertEqual(client.disconnect_calls, 1)

    def test_connect_returns_disconnected(self):
        client = FakeClient(connected_after_connect=False)
        report, status = self.inspect(client)

        self.assertEqual(status, 4)
        self.assertFalse(report["connection"]["connected"])
        self.assertFalse(report["gatt"]["enumerated"])
        self.assertEqual(client.disconnect_calls, 1)

    def test_disconnect_returns_still_connected(self):
        client = FakeClient(remains_connected=True)
        report, status = self.inspect(client)

        self.assertEqual(status, 6)
        self.assertTrue(report["gatt"]["enumerated"])
        self.assertFalse(report["disconnect"]["completed"])
        self.assertIn("still connected", report["disconnect"]["error"])

    def test_disconnect_raises(self):
        client = FakeClient(
            disconnect_error=RuntimeError("disconnect failed")
        )
        report, status = self.inspect(client)

        self.assertEqual(status, 6)
        self.assertTrue(report["gatt"]["enumerated"])
        self.assertFalse(report["disconnect"]["completed"])
        self.assertIn("disconnect failed", report["disconnect"]["error"])

    def test_enumeration_failure_still_disconnects(self):
        client = FakeClient(services=[object()])
        report, status = self.inspect(client)

        self.assertEqual(status, 5)
        self.assertFalse(report["gatt"]["enumerated"])
        self.assertIsNotNone(report["gatt"]["error"])
        self.assertTrue(report["disconnect"]["completed"])

    def test_constructor_failure_is_reported(self):
        device = SimpleNamespace(
            name="Test Device",
            address="AA:BB:CC:DD:EE:FF",
        )
        adv = SimpleNamespace(rssi=-50, service_uuids=[])

        async def fake_find_target(*args):
            return device, adv

        with (
            patch.object(module, "find_target", fake_find_target),
            patch.object(
                module,
                "BleakClient",
                side_effect=RuntimeError("constructor failed"),
            ),
        ):
            report, status = asyncio.run(
                module.inspect_target(device.address, "hci0", 3)
            )

        self.assertEqual(status, 4)
        self.assertIn("constructor failed", report["connection"]["error"])
        self.assertFalse(report["disconnect"]["attempted"])


if __name__ == "__main__":
    unittest.main()

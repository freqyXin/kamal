import asyncio
import unittest
from unittest.mock import patch

from tests.test_gatt_lifecycle import module


class DiscoveryErrorTests(unittest.TestCase):
    def test_discovery_exception_returns_status_2(self):
        async def failing_discovery(*args):
            raise RuntimeError("scanner unavailable")

        with (
            patch.object(module, "find_target", failing_discovery),
            patch.object(module, "BleakClient") as client,
        ):
            report, status = asyncio.run(
                module.inspect_target("AA:BB:CC:DD:EE:FF", "hci0", 3)
            )

        self.assertEqual(status, 2)
        self.assertFalse(report["discovery"]["found"])
        self.assertIn("scanner unavailable", report["discovery"]["error"])
        client.assert_not_called()

    def test_missing_target_returns_status_3(self):
        async def missing_target(*args):
            return None, None

        with (
            patch.object(module, "find_target", missing_target),
            patch.object(module, "BleakClient") as client,
        ):
            report, status = asyncio.run(
                module.inspect_target("AA:BB:CC:DD:EE:FF", "hci0", 3)
            )

        self.assertEqual(status, 3)
        self.assertFalse(report["discovery"]["found"])
        self.assertIsNone(report["discovery"]["error"])
        client.assert_not_called()


if __name__ == "__main__":
    unittest.main()

import asyncio
import unittest

from kamal.gatt_survey import (
    SurveyTargetPolicy,
    discover_target_queue,
)


class FakeScanner:
    calls = []

    @classmethod
    async def discover(cls, **kwargs):
        cls.calls.append(kwargs)
        return {
            "AA:BB:CC:DD:EE:02": (object(), object()),
            "AA:BB:CC:DD:EE:99": (object(), object()),
            "AA:BB:CC:DD:EE:01": (object(), object()),
        }


class SurveyDiscoveryTests(unittest.TestCase):
    def setUp(self):
        FakeScanner.calls = []
        self.policy = SurveyTargetPolicy(
            mode="allowlist",
            allowlist=frozenset({
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
            }),
        )

    def run_discovery(self, **kwargs):
        return asyncio.run(
            discover_target_queue(
                policy=self.policy,
                adapter="hci0",
                scanner=FakeScanner,
                **kwargs,
            )
        )

    def test_discovers_once_and_filters_scope(self):
        queue = self.run_discovery(
            discover_seconds=5,
            max_devices=10,
        )

        self.assertEqual(
            queue,
            ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )
        self.assertEqual(len(FakeScanner.calls), 1)
        self.assertEqual(
            FakeScanner.calls[0],
            {
                "timeout": 5,
                "return_adv": True,
                "bluez": {"adapter": "hci0"},
            },
        )

    def test_applies_device_cap(self):
        queue = self.run_discovery(max_devices=1)
        self.assertEqual(queue, ["AA:BB:CC:DD:EE:01"])

    def test_rejects_zero_duration_before_scanning(self):
        with self.assertRaisesRegex(ValueError, "discover_seconds"):
            self.run_discovery(discover_seconds=0)

        self.assertEqual(FakeScanner.calls, [])

    def test_rejects_excessive_duration_before_scanning(self):
        with self.assertRaisesRegex(ValueError, "discover_seconds"):
            self.run_discovery(discover_seconds=61)

        self.assertEqual(FakeScanner.calls, [])

    def test_rejects_invalid_cap_before_scanning(self):
        with self.assertRaisesRegex(ValueError, "max_devices"):
            self.run_discovery(max_devices=0)

        self.assertEqual(FakeScanner.calls, [])

    def test_rejects_invalid_policy_before_scanning(self):
        with self.assertRaises(TypeError):
            asyncio.run(
                discover_target_queue(
                    policy=None,
                    adapter="hci0",
                    scanner=FakeScanner,
                )
            )

        self.assertEqual(FakeScanner.calls, [])

    def test_rejects_invalid_adapter_before_scanning(self):
        with self.assertRaisesRegex(ValueError, "adapter"):
            asyncio.run(
                discover_target_queue(
                    policy=self.policy,
                    adapter="",
                    scanner=FakeScanner,
                )
            )

        self.assertEqual(FakeScanner.calls, [])


if __name__ == "__main__":
    unittest.main()

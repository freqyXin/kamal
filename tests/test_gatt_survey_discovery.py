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
            queue["targets"],
            ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )
        self.assertEqual(queue["discovered_count"], 3)
        self.assertEqual(queue["permitted_count"], 2)
        self.assertEqual(queue["target_count"], 2)
        self.assertEqual(queue["omitted_by_cap"], 0)
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
        self.assertEqual(queue["targets"], ["AA:BB:CC:DD:EE:01"])
        self.assertEqual(queue["discovered_count"], 3)
        self.assertEqual(queue["permitted_count"], 2)
        self.assertEqual(queue["target_count"], 1)
        self.assertEqual(queue["omitted_by_cap"], 1)

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

class SurveyRecordTests(unittest.TestCase):
    def test_preserves_selected_device_and_advertisement_objects(self):
        from kamal.gatt_survey import discover_target_records

        policy = SurveyTargetPolicy(
            mode="allowlist",
            allowlist=frozenset({
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
            }),
        )

        summary, records = asyncio.run(
            discover_target_records(
                policy=policy,
                adapter="hci0",
                discover_seconds=5,
                max_devices=1,
                scanner=FakeScanner,
            )
        )

        self.assertEqual(summary["target_count"], 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["address"], "AA:BB:CC:DD:EE:01")
        self.assertIsNotNone(records[0]["device"])
        self.assertIsNotNone(records[0]["advertisement"])


class FakeLiveScanner:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        self.discovered_devices_and_advertisement_data = {
            "AA:BB:CC:DD:EE:02": (object(), object()),
            "AA:BB:CC:DD:EE:01": (object(), object()),
        }
        type(self).instances.append(self)

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True


class BrokenSnapshotScanner(FakeLiveScanner):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        type(self).instances.append(self)

    @property
    def discovered_devices_and_advertisement_data(self):
        raise RuntimeError("snapshot failed")


class LiveSurveyDiscoveryTests(unittest.TestCase):
    def test_keeps_scanner_active_after_snapshot(self):
        from kamal.gatt_survey import start_live_target_record_discovery

        FakeLiveScanner.instances = []
        policy = SurveyTargetPolicy(
            mode="all_discovered",
            acknowledge_scope=True,
        )

        async def no_sleep(_seconds):
            return None

        scanner, summary, records = asyncio.run(
            start_live_target_record_discovery(
                policy=policy,
                adapter="hci0",
                discover_seconds=5,
                max_devices=10,
                scanner_factory=FakeLiveScanner,
                sleep=no_sleep,
            )
        )

        self.assertTrue(scanner.started)
        self.assertFalse(scanner.stopped)
        self.assertEqual(scanner.kwargs, {"bluez": {"adapter": "hci0"}})
        self.assertEqual(summary["target_count"], 2)
        self.assertEqual(
            [record["address"] for record in records],
            ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )

        asyncio.run(scanner.stop())
        self.assertTrue(scanner.stopped)

    def test_stops_scanner_if_snapshot_fails(self):
        from kamal.gatt_survey import start_live_target_record_discovery

        BrokenSnapshotScanner.instances = []
        policy = SurveyTargetPolicy(
            mode="all_discovered",
            acknowledge_scope=True,
        )

        async def no_sleep(_seconds):
            return None

        with self.assertRaisesRegex(RuntimeError, "snapshot failed"):
            asyncio.run(
                start_live_target_record_discovery(
                    policy=policy,
                    adapter="hci0",
                    discover_seconds=5,
                    max_devices=10,
                    scanner_factory=BrokenSnapshotScanner,
                    sleep=no_sleep,
                )
            )

        self.assertEqual(len(BrokenSnapshotScanner.instances), 1)
        self.assertTrue(BrokenSnapshotScanner.instances[0].stopped)

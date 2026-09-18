import unittest

from kamal.gatt_survey import SurveyTargetPolicy, build_target_queue


class SurveyQueueTests(unittest.TestCase):
    def setUp(self):
        self.allowlist = SurveyTargetPolicy(
            mode="allowlist",
            allowlist=frozenset({
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
            }),
        )

    def test_filters_out_of_scope_devices(self):
        queue = build_target_queue(
            [
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:99",
            ],
            self.allowlist,
            max_devices=10,
        )
        self.assertEqual(queue, ["AA:BB:CC:DD:EE:01"])

    def test_deduplicates_case_insensitively(self):
        queue = build_target_queue(
            [
                "aa:bb:cc:dd:ee:01",
                "AA:BB:CC:DD:EE:01",
            ],
            self.allowlist,
            max_devices=10,
        )
        self.assertEqual(queue, ["AA:BB:CC:DD:EE:01"])

    def test_sorts_before_applying_cap(self):
        queue = build_target_queue(
            [
                "AA:BB:CC:DD:EE:02",
                "AA:BB:CC:DD:EE:99",
                "AA:BB:CC:DD:EE:01",
            ],
            self.allowlist,
            max_devices=1,
        )
        self.assertEqual(queue, ["AA:BB:CC:DD:EE:01"])

    def test_empty_discovery_returns_empty_queue(self):
        self.assertEqual(
            build_target_queue([], self.allowlist, max_devices=10),
            [],
        )

    def test_all_discovered_mode(self):
        policy = SurveyTargetPolicy(
            mode="all_discovered",
            acknowledge_scope=True,
        )
        queue = build_target_queue(
            ["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:01"],
            policy,
            max_devices=10,
        )
        self.assertEqual(
            queue,
            ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )

    def test_rejects_zero_cap(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            build_target_queue([], self.allowlist, max_devices=0)

    def test_rejects_boolean_cap(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            build_target_queue([], self.allowlist, max_devices=True)

    def test_rejects_invalid_policy(self):
        with self.assertRaises(TypeError):
            build_target_queue([], None, max_devices=10)


if __name__ == "__main__":
    unittest.main()

import unittest

from kamal.gatt_survey import (
    SurveyTargetPolicy,
    summarize_discovery,
)


class SurveyAccountingTests(unittest.TestCase):
    def test_counts_discovered_permitted_selected_and_omitted(self):
        policy = SurveyTargetPolicy(
            mode="allowlist",
            allowlist=frozenset({
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
                "AA:BB:CC:DD:EE:03",
            }),
        )

        result = summarize_discovery(
            [
                "aa:bb:cc:dd:ee:01",
                "AA:BB:CC:DD:EE:01",
                "AA:BB:CC:DD:EE:02",
                "AA:BB:CC:DD:EE:03",
                "AA:BB:CC:DD:EE:99",
            ],
            policy,
            max_devices=2,
        )

        self.assertEqual(result["discovered_count"], 4)
        self.assertEqual(result["permitted_count"], 3)
        self.assertEqual(result["target_count"], 2)
        self.assertEqual(result["omitted_by_cap"], 1)
        self.assertEqual(
            result["targets"],
            ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )

    def test_empty_discovery(self):
        policy = SurveyTargetPolicy(
            mode="all_discovered",
            acknowledge_scope=True,
        )

        result = summarize_discovery([], policy, max_devices=10)

        self.assertEqual(result["discovered_count"], 0)
        self.assertEqual(result["permitted_count"], 0)
        self.assertEqual(result["target_count"], 0)
        self.assertEqual(result["omitted_by_cap"], 0)
        self.assertEqual(result["targets"], [])


if __name__ == "__main__":
    unittest.main()

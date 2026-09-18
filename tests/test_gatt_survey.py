import unittest

from kamal.gatt_survey import SurveyTargetPolicy


class SurveyTargetPolicyTests(unittest.TestCase):
    def test_allowlist_permits_matching_address_case_insensitively(self):
        policy = SurveyTargetPolicy(
            mode="allowlist",
            allowlist=frozenset({"aa:bb:cc:dd:ee:ff"}),
        )

        self.assertTrue(policy.permits("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(policy.permits("11:22:33:44:55:66"))

    def test_allowlist_requires_at_least_one_target(self):
        with self.assertRaisesRegex(
            ValueError,
            "Allowlist mode requires at least one target",
        ):
            SurveyTargetPolicy(
                mode="allowlist",
                allowlist=frozenset(),
            )

    def test_allowlist_rejects_scope_acknowledgment(self):
        with self.assertRaisesRegex(
            ValueError,
            "Scope acknowledgment is only valid for all-discovered mode",
        ):
            SurveyTargetPolicy(
                mode="allowlist",
                allowlist=frozenset({"AA:BB:CC:DD:EE:FF"}),
                acknowledge_scope=True,
            )

    def test_all_discovered_requires_acknowledgment(self):
        with self.assertRaisesRegex(
            ValueError,
            "All-discovered mode requires scope acknowledgment",
        ):
            SurveyTargetPolicy(
                mode="all_discovered",
            )

    def test_all_discovered_rejects_allowlist(self):
        with self.assertRaisesRegex(
            ValueError,
            "All-discovered mode cannot include an allowlist",
        ):
            SurveyTargetPolicy(
                mode="all_discovered",
                allowlist=frozenset({"AA:BB:CC:DD:EE:FF"}),
                acknowledge_scope=True,
            )

    def test_all_discovered_permits_nonempty_address(self):
        policy = SurveyTargetPolicy(
            mode="all_discovered",
            acknowledge_scope=True,
        )

        self.assertTrue(policy.permits("11:22:33:44:55:66"))

    def test_invalid_address_input_is_not_permitted(self):
        policy = SurveyTargetPolicy(
            mode="all_discovered",
            acknowledge_scope=True,
        )

        self.assertFalse(policy.permits(""))
        self.assertFalse(policy.permits("   "))
        self.assertFalse(policy.permits(None))

    def test_allowlist_rejects_invalid_target(self):
        with self.assertRaisesRegex(
            ValueError,
            "Allowlist contains an invalid target",
        ):
            SurveyTargetPolicy(
                mode="allowlist",
                allowlist=frozenset({""}),
            )

    def test_rejects_unsupported_mode(self):
        with self.assertRaisesRegex(
            ValueError,
            "Unsupported survey mode",
        ):
            SurveyTargetPolicy(
                mode="everything",
            )


if __name__ == "__main__":
    unittest.main()

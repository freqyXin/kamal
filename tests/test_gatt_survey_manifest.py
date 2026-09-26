import unittest

from kamal.gatt_survey import (
    SurveyAbortedError,
    build_execution_manifest,
)

class SurveyManifestTests(unittest.TestCase):
    def test_complete_manifest(self):
        outcomes = [
            {
                "address": "AA:00",
                "status": 0,
                "report": {
                    "connection": {"client_created": True},
                    "disconnect": {"completed": True},
                },
            }
        ]

        execution = build_execution_manifest(1, outcomes)

        self.assertTrue(execution["complete"])
        self.assertFalse(execution["aborted"])
        self.assertIsNone(execution["abort"])
        self.assertEqual(
            execution["results"][0]["report_path"],
            "device-001.json",
        )

    def test_aborted_manifest_preserves_partial_progress(self):
        outcomes = [
            {
                "address": "AA:00",
                "status": 0,
                "report": {
                    "connection": {"client_created": True},
                    "disconnect": {"completed": True},
                },
            }
        ]

        error = SurveyAbortedError(
            "BB:00",
            outcomes,
            RuntimeError("unexpected failure"),
        )

        execution = build_execution_manifest(
            2,
            outcomes,
            abort_error=error,
        )

        self.assertFalse(execution["complete"])
        self.assertTrue(execution["aborted"])
        self.assertEqual(execution["inspected_count"], 1)
        self.assertEqual(execution["not_inspected_count"], 1)
        self.assertEqual(execution["abort"]["address"], "BB:00")
        self.assertFalse(execution["abort"]["cleanup_confirmed"])
        self.assertIn(
            "unexpected failure",
            execution["abort"]["error"],
        )

    def test_aborted_manifest_can_record_confirmed_cleanup(self):
        error = SurveyAbortedError(
            "AA:00",
            [],
            RuntimeError("pre-connection authorization expired"),
        )

        execution = build_execution_manifest(
            1,
            [],
            abort_error=error,
            abort_cleanup_confirmed=True,
        )

        self.assertTrue(execution["abort"]["cleanup_confirmed"])


if __name__ == "__main__":
    unittest.main()

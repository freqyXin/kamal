import unittest

from kamal.gatt_survey import summarize_survey_execution


class SurveyAccountingTests(unittest.TestCase):
    def test_complete_survey_with_recoverable_failure(self):
        outcomes = [
            {
                "status": 0,
                "report": {
                    "connection": {"client_created": True},
                    "disconnect": {"completed": True},
                },
            },
            {
                "status": 4,
                "report": {
                    "connection": {
                        "client_created": False,
                        "error": "BleakClient constructor failed",
                    },
                    "disconnect": {
                        "attempted": False,
                        "completed": False,
                    },
                },
            },
        ]

        summary = summarize_survey_execution(2, outcomes)

        self.assertEqual(summary["inspected_count"], 2)
        self.assertEqual(summary["successful_count"], 1)
        self.assertEqual(summary["failed_count"], 1)
        self.assertEqual(summary["not_inspected_count"], 0)
        self.assertFalse(summary["stopped_unsafe"])
        self.assertTrue(summary["complete"])

    def test_unsafe_disconnect_stops_survey(self):
        outcomes = [
            {
                "status": 6,
                "report": {
                    "connection": {"client_created": True},
                    "disconnect": {"completed": False},
                },
            }
        ]

        summary = summarize_survey_execution(3, outcomes)

        self.assertEqual(summary["inspected_count"], 1)
        self.assertEqual(summary["not_inspected_count"], 2)
        self.assertTrue(summary["stopped_unsafe"])
        self.assertFalse(summary["complete"])


if __name__ == "__main__":
    unittest.main()

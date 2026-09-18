import json
import tempfile
import unittest
from pathlib import Path

from kamal.gatt_survey import persist_survey_reports


class SurveyPersistenceTests(unittest.TestCase):
    def test_writes_individual_reports_and_manifest_entries(self):
        outcomes = [
            {
                "address": "AA:BB:CC:DD:EE:01",
                "status": 0,
                "report": {"target": "AA:BB:CC:DD:EE:01"},
            },
            {
                "address": "AA:BB:CC:DD:EE:02",
                "status": 4,
                "report": {"target": "AA:BB:CC:DD:EE:02"},
            },
        ]

        with tempfile.TemporaryDirectory() as directory:
            entries = persist_survey_reports(outcomes, directory)

            self.assertEqual(len(entries), 2)
            self.assertEqual(
                [entry["report_path"] for entry in entries],
                ["device-001.json", "device-002.json"],
            )

            self.assertEqual(
                json.loads(
                    (Path(directory) / "device-001.json").read_text()
                ),
                outcomes[0]["report"],
            )

            self.assertEqual(
                json.loads(
                    (Path(directory) / "device-002.json").read_text()
                ),
                outcomes[1]["report"],
            )

            self.assertEqual(
                [entry["status"] for entry in entries],
                [0, 4],
            )


if __name__ == "__main__":
    unittest.main()

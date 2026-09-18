import asyncio
import unittest
from types import SimpleNamespace

from kamal.gatt_survey import run_survey_records


class SurveyRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_sequential_execution_and_failure_isolation(self):
        records = [
            {
                "address": address,
                "device": SimpleNamespace(address=address),
                "advertisement": object(),
            }
            for address in ("AA:00", "BB:00", "CC:00")
        ]

        events = []
        statuses = iter((0, 4, 0))

        async def inspect(record):
            events.append(("start", record["address"]))
            await asyncio.sleep(0)
            events.append(("finish", record["address"]))

            status = next(statuses)

            return (
                {
                    "target": record["address"],
                    "connection": {
                        "attempted": True,
                        "client_created": True,
                        "error": "Connection failed" if status else None,
                    },
                    "disconnect": {
                        "attempted": True,
                        "completed": True,
                        "error": None,
                    },
                },
                status,
            )

        outcomes = await run_survey_records(records, inspect)

        self.assertEqual(
            [outcome["status"] for outcome in outcomes],
            [0, 4, 0],
        )

        self.assertEqual(
            events,
            [
                ("start", "AA:00"),
                ("finish", "AA:00"),
                ("start", "BB:00"),
                ("finish", "BB:00"),
                ("start", "CC:00"),
                ("finish", "CC:00"),
            ],
        )

    async def test_stops_after_unconfirmed_disconnect(self):
        records = [
            {
                "address": address,
                "device": SimpleNamespace(address=address),
                "advertisement": object(),
            }
            for address in ("AA:00", "BB:00")
        ]

        visited = []

        async def inspect(record):
            visited.append(record["address"])

            return (
                {
                    "target": record["address"],
                    "connection": {
                        "attempted": True,
                        "client_created": True,
                        "error": None,
                    },
                    "disconnect": {
                        "attempted": True,
                        "completed": False,
                        "error": "Disconnect timed out",
                    },
                },
                6,
            )

        outcomes = await run_survey_records(records, inspect)

        self.assertEqual(visited, ["AA:00"])
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["status"], 6)



    async def test_constructor_failure_can_continue(self):
        records = [
            {
                "address": address,
                "device": SimpleNamespace(address=address),
                "advertisement": object(),
            }
            for address in ("AA:00", "BB:00")
        ]

        visited = []

        async def inspect(record):
            visited.append(record["address"])

            if record["address"] == "AA:00":
                return (
                    {
                        "target": record["address"],
                        "connection": {
                            "attempted": True,
                            "client_created": False,
                            "error": "RuntimeError: constructor failed",
                        },
                        "disconnect": {
                            "attempted": False,
                            "completed": False,
                            "error": None,
                        },
                    },
                    4,
                )

            return (
                {
                    "target": record["address"],
                    "connection": {
                        "attempted": True,
                        "client_created": True,
                        "error": None,
                    },
                    "disconnect": {
                        "attempted": True,
                        "completed": True,
                        "error": None,
                    },
                },
                0,
            )

        outcomes = await run_survey_records(records, inspect)

        self.assertEqual(visited, ["AA:00", "BB:00"])
        self.assertEqual(
            [outcome["status"] for outcome in outcomes],
            [4, 0],
        )

    async def test_unexpected_inspector_exception_aborts(self):
        records = [
            {
                "address": "AA:00",
                "device": SimpleNamespace(address="AA:00"),
                "advertisement": object(),
            }
        ]

        async def inspect(record):
            raise RuntimeError("unexpected inspector failure")

        with self.assertRaisesRegex(
            RuntimeError,
            "unexpected inspector failure",
        ) as caught:
            await run_survey_records(records, inspect)

        self.assertEqual(caught.exception.address, "AA:00")
        self.assertEqual(caught.exception.outcomes, [])
        self.assertIsInstance(caught.exception.cause, RuntimeError)



    async def test_persists_each_report_before_next_inspection(self):
        import json
        import tempfile
        from pathlib import Path

        records = [
            {"address": "AA:00"},
            {"address": "BB:00"},
        ]

        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)

            async def inspect(record):
                if record["address"] == "BB:00":
                    previous = output_dir / "device-001.json"
                    self.assertTrue(previous.exists())
                    self.assertEqual(
                        json.loads(previous.read_text())["target"],
                        "AA:00",
                    )
                    raise RuntimeError("second inspection failed")

                return (
                    {
                        "target": record["address"],
                        "connection": {
                            "attempted": True,
                            "client_created": True,
                            "error": None,
                        },
                        "disconnect": {
                            "attempted": True,
                            "completed": True,
                            "error": None,
                        },
                    },
                    0,
                )

            with self.assertRaisesRegex(
                RuntimeError, "second inspection failed"
            ):
                await run_survey_records(
                    records,
                    inspect,
                    output_dir=output_dir,
                )


    async def test_incremental_reports_do_not_overwrite(self):
        import json
        import tempfile
        from pathlib import Path

        records = [
            {"address": "AA:00"},
            {"address": "BB:00"},
        ]

        async def inspect(record):
            return (
                {
                    "target": record["address"],
                    "connection": {
                        "attempted": True,
                        "client_created": True,
                        "error": None,
                    },
                    "disconnect": {
                        "attempted": True,
                        "completed": True,
                        "error": None,
                    },
                },
                0,
            )

        with tempfile.TemporaryDirectory() as directory:
            outcomes = await run_survey_records(
                records,
                inspect,
                output_dir=directory,
            )

            first = json.loads(
                (Path(directory) / "device-001.json").read_text()
            )
            second = json.loads(
                (Path(directory) / "device-002.json").read_text()
            )

            self.assertEqual(len(outcomes), 2)
            self.assertEqual(first["target"], "AA:00")
            self.assertEqual(second["target"], "BB:00")


    async def test_abort_preserves_completed_inspections(self):
        import tempfile
        from pathlib import Path
        from kamal.gatt_survey import SurveyAbortedError

        records = [
            {"address": "AA:00"},
            {"address": "BB:00"},
        ]

        async def inspect(record):
            if record["address"] == "BB:00":
                raise RuntimeError("second device failed")

            return (
                {
                    "target": record["address"],
                    "connection": {
                        "attempted": True,
                        "client_created": True,
                        "error": None,
                    },
                    "disconnect": {
                        "attempted": True,
                        "completed": True,
                        "error": None,
                    },
                },
                0,
            )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SurveyAbortedError) as caught:
                await run_survey_records(
                    records,
                    inspect,
                    output_dir=directory,
                )

            error = caught.exception

            self.assertEqual(error.address, "BB:00")
            self.assertEqual(len(error.outcomes), 1)
            self.assertEqual(error.outcomes[0]["address"], "AA:00")
            self.assertEqual(error.outcomes[0]["status"], 0)
            self.assertTrue(
                (Path(directory) / "device-001.json").exists()
            )
            self.assertFalse(
                (Path(directory) / "device-002.json").exists()
            )


    async def test_incomplete_lifecycle_report_aborts_queue(self):
        from kamal.gatt_survey import SurveyAbortedError

        records = [
            {"address": "AA:00"},
            {"address": "BB:00"},
        ]
        visited = []

        async def inspect(record):
            visited.append(record["address"])
            return {"target": record["address"]}, 0

        with self.assertRaises(SurveyAbortedError) as caught:
            await run_survey_records(records, inspect)

        self.assertEqual(visited, ["AA:00"])
        self.assertEqual(caught.exception.address, "AA:00")


    async def test_completed_disconnect_requires_attempt(self):
        from kamal.gatt_survey import SurveyAbortedError

        records = [{"address": "AA:00"}]

        async def inspect(record):
            return (
                {
                    "target": record["address"],
                    "connection": {
                        "attempted": True,
                        "client_created": True,
                        "error": None,
                    },
                    "disconnect": {
                        "attempted": False,
                        "completed": True,
                        "error": None,
                    },
                },
                0,
            )

        with self.assertRaises(SurveyAbortedError) as caught:
            await run_survey_records(records, inspect)

        self.assertEqual(caught.exception.address, "AA:00")

if __name__ == "__main__":
    unittest.main()

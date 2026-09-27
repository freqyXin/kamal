"""CLI boundary tests for explicit Bluetooth pairing execution."""

import importlib.util
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

from kamal.pairing_executor import PairingExecutionError


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "kamal-execute-pairing"
loader = SourceFileLoader("kamal_execute_pairing_cli", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class PairingExecutorCLITests(unittest.IsolatedAsyncioTestCase):
    def test_parser_requires_inputs(self):
        with self.assertRaises(SystemExit):
            module.parser().parse_args([])

    def test_safety_state_dir_is_required(self):
        with self.assertRaises(SystemExit):
            module.parser().parse_args(
                [
                    "--plan",
                    "plan.json",
                    "--authorization",
                    "auth.json",
                    "--output-dir",
                    "out",
                ]
            )

    async def test_success_passes_exact_paths_and_adapter(self):
        fake_inputs = (
            {"plan_id": "plan"},
            "a" * 64,
            Path("/tmp/plan.json"),
            {"authorization_id": "auth"},
            "b" * 64,
            Path("/tmp/auth.json"),
        )
        final = {
            "state_after": {
                "paired": True,
                "bonded": True,
                "trusted": False,
            }
        }
        with mock.patch.object(
            module, "load_pairing_execution_inputs", return_value=fake_inputs
        ), mock.patch.object(
            module, "execute_pairing_plan", new=mock.AsyncMock(return_value=final)
        ) as execute, mock.patch("builtins.print"):
            result = await module.async_main(
                [
                    "--plan",
                    "plan.json",
                    "--authorization",
                    "auth.json",
                    "--output-dir",
                    "out",
                    "--safety-state-dir",
                    "safety",
                    "--adapter",
                    "hci7",
                ]
            )
        self.assertEqual(result, 0)
        kwargs = execute.await_args.kwargs
        self.assertEqual(kwargs["authorization_sha256"], "b" * 64)
        self.assertEqual(kwargs["plan_sha256"], "a" * 64)
        self.assertEqual(kwargs["adapter"], "hci7")
        self.assertEqual(kwargs["output_dir"], Path("out"))
        self.assertEqual(kwargs["safety_state_dir"], Path("safety"))

    async def test_execution_error_returns_one(self):
        fake_inputs = (
            {"plan_id": "plan"},
            "a" * 64,
            Path("/tmp/plan.json"),
            {"authorization_id": "auth"},
            "b" * 64,
            Path("/tmp/auth.json"),
        )
        with mock.patch.object(
            module, "load_pairing_execution_inputs", return_value=fake_inputs
        ), mock.patch.object(
            module,
            "execute_pairing_plan",
            new=mock.AsyncMock(side_effect=PairingExecutionError("pair rejected")),
        ), mock.patch("sys.stderr"):
            result = await module.async_main(
                [
                    "--plan",
                    "plan.json",
                    "--authorization",
                    "auth.json",
                    "--output-dir",
                    "out",
                    "--safety-state-dir",
                    "safety",
                ]
            )
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()

import importlib.util
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "kamal-execute-gatt"
loader = SourceFileLoader("kamal_execute_gatt_cli", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class CLITests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

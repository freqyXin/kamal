import importlib.util
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-accept-v012"
loader = SourceFileLoader("kamal_accept_v012_cli", str(CLI))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class V012AcceptanceCLITests(unittest.TestCase):
    def test_parser_requires_work_and_json(self):
        with self.assertRaises(SystemExit):
            module.parser().parse_args([])

    def test_cli_writes_report_without_real_rf_or_network(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        output = root / "acceptance.json"
        rc = module.main([
            "--work-dir", str(root / "work"),
            "--json", str(output),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(output.exists())

    def test_cli_refuses_existing_report(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        output = root / "acceptance.json"
        output.write_text("{}\n")
        rc = module.main([
            "--work-dir", str(root / "work"),
            "--json", str(output),
        ])
        self.assertEqual(rc, 1)
        self.assertEqual(output.read_text(), "{}\n")

    def test_cli_rejects_same_work_and_report_path(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = Path(td.name) / "same"
        rc = module.main(["--work-dir", str(path), "--json", str(path)])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

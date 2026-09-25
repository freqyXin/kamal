import importlib.util, unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/"bin"/"kamal-execute-gatt"
loader=SourceFileLoader("kamal_execute_gatt_cli",str(SCRIPT)); spec=importlib.util.spec_from_loader(loader.name,loader); module=importlib.util.module_from_spec(spec); loader.exec_module(module)
class CLITests(unittest.TestCase):
    def test_parser_requires_inputs(self):
        with self.assertRaises(SystemExit): module.parser().parse_args([])
if __name__=="__main__": unittest.main()

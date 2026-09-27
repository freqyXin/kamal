"""Regression tests for the shell BLE capture adapter contract."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "bin" / "kamal-capture"


class CaptureWrapperTests(unittest.TestCase):
    def test_shell_syntax_is_valid(self):
        result = subprocess.run(
            ["bash", "-n", str(CAPTURE)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_address_option_maps_to_installed_nrfutil_follow(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn(
            '[[ -z "$target_address" ]] || cmd+=(--follow "$target_address")',
            source,
        )
        self.assertNotIn('cmd+=(--follow-by-address "$target_address")', source)

    def test_public_advertising_only_maps_to_installed_nrfutil_option(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn(
            '--advertising-only) advertising_only=true; shift ;;',
            source,
        )
        self.assertIn(
            '[[ "$advertising_only" != true ]] || cmd+=(--only-advertising)',
            source,
        )
        self.assertNotIn(
            '[[ "$advertising_only" != true ]] || cmd+=(--advertising-only)',
            source,
        )


if __name__ == "__main__":
    unittest.main()

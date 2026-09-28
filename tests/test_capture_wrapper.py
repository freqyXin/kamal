"""Regression tests for the shell BLE capture adapter contract."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "bin" / "kamal-capture"
SETUP = ROOT / "setup" / "setup-ble-sniffer.sh"
FIXED_ADV = ROOT / "setup" / "kamal-nrf-fixed-adv.c"


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


    def test_three_channel_mode_is_separate_and_requires_explicit_target(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn('ble-adv3) shift; capture_ble_adv3 "$@" ;;', source)
        self.assertIn("ble-adv3 requires --duration.", source)
        self.assertIn("ble-adv3 requires --address.", source)
        self.assertIn("--only-advertising", source)

    def test_three_channel_mode_uses_persistent_channel_aliases(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn("/dev/kamal-ble-sniffer-37", source)
        self.assertIn("/dev/kamal-ble-sniffer-38", source)
        self.assertIn("/dev/kamal-ble-sniffer-39", source)
        self.assertIn("three distinct BLE sniffer devices", source)

    def test_three_channel_mode_staggers_follow_request_commands(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn("wait_for_follow_request()", source)
        self.assertIn("KAMAL_PRELOAD_READY_FILE", source)
        self.assertIn("follow request sent", source)
        self.assertIn("follow_request_is_not_rf_acquisition_confirmation", source)

    def test_ble_setup_shell_syntax_is_valid(self):
        result = subprocess.run(
            ["bash", "-n", str(SETUP)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ble_setup_installs_fixed_adv_adapter_and_aliases(self):
        source = SETUP.read_text(encoding="utf-8")
        self.assertIn("kamal-nrf-fixed-adv.c", source)
        self.assertIn("libkamal-nrf-fixed-adv.so", source)
        self.assertIn('SYMLINK+="kamal-ble-sniffer-37"', source)
        self.assertIn('SYMLINK+="kamal-ble-sniffer-38"', source)
        self.assertIn('SYMLINK+="kamal-ble-sniffer-39"', source)


    def test_three_channel_stop_receiver_is_nounset_safe(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn('local ch="$1"\n        local receiver_pid="${pid[$ch]:-}"', source)
        self.assertNotIn('local ch="$1" receiver_pid="${pid[$ch]:-}"', source)

    def test_three_channel_failure_summary_is_shell_safe_and_preserves_primary_failure(self):
        source = CAPTURE.read_text(encoding="utf-8")
        summary_line = next(
            line for line in source.splitlines() if "CH%s packets:" in line
        )
        self.assertTrue(summary_line.endswith(" " + chr(92)))
        self.assertFalse(summary_line.endswith(" " + chr(92) * 2))
        self.assertIn(
            '[[ "$overall_status" != "ok" ]] || overall_status="capture-missing"',
            source,
        )
        self.assertIn(
            '[[ "$overall_status" != "ok" ]] || overall_status="channel-validation-failed"',
            source,
        )

    def test_three_channel_validation_requires_packets_and_exact_markers(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn('packet_count[$channel] <= 0', source)
        self.assertIn('overall_status="capture-empty"', source)
        self.assertIn('mutation_count[$channel] != 1', source)
        self.assertIn('follow_request_count[$channel] != 1', source)

    def test_three_channel_validation_uses_crc_valid_channel_observations(self):
        source = CAPTURE.read_text(encoding="utf-8")
        self.assertIn("-e nordic_ble.crcok", source)
        self.assertIn("validated_off_channel_count[$channel]", source)
        self.assertIn(
            "validated_off_channel_count[$channel] != 0",
            source,
        )
        self.assertNotIn(
            "follow_request_count[$channel] != 1 || off_channel_count[$channel] != 0",
            source,
        )
        self.assertIn('"validated_channel_counts": validated_counts', source)
        self.assertIn(
            '"validated_off_channel_packets": validated_off_channel',
            source,
        )
        self.assertIn(
            '"untrusted_off_channel_packets": untrusted_off_channel',
            source,
        )
        self.assertIn(
            '"channel_validation_basis": "nordic_ble.crcok == True"',
            source,
        )

    def test_ble_setup_requires_explicit_assignment_when_more_than_three_radios_exist(self):
        source = SETUP.read_text(encoding="utf-8")
        self.assertIn('KAMAL_BLE_ADV37_SERIAL', source)
        self.assertIn('KAMAL_BLE_ADV38_SERIAL', source)
        self.assertIn('KAMAL_BLE_ADV39_SERIAL', source)
        self.assertIn('More than three BLE sniffers are connected.', source)
        self.assertIn('BLE advertising-plane serial assignments must be distinct.', source)

    def test_fixed_adv_preload_source_compiles_when_cc_is_available(self):
        cc = shutil.which("cc")
        if cc is None:
            self.skipTest("cc is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "libkamal-nrf-fixed-adv.so"
            result = subprocess.run(
                [
                    cc,
                    "-shared",
                    "-fPIC",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-o",
                    str(output),
                    str(FIXED_ADV),
                    "-ldl",
                    "-pthread",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_fixed_adv_preload_rewrites_validated_frame_and_marks_follow_request(self):
        if sys.platform != "linux":
            self.skipTest("LD_PRELOAD behavior test requires Linux")
        cc = shutil.which("cc")
        if cc is None:
            self.skipTest("cc is not installed")

        writer_source = r"""
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 3;
    uint8_t hop[] = {0xab,0x06,0x04,0x01,0x03,0x00,0x17,0x03,0x25,0x26,0x27,0xbc};
    uint8_t follow[] = {0xab,0x06,0x09,0x01,0x06,0x00,0x00,0x00,0x1c,0x4d,0x45,0xde,0x3f,0x01,0x00,0x01,0xbc};
    if (write(fd, hop, sizeof(hop)) != (ssize_t)sizeof(hop)) return 4;
    if (write(fd, follow, sizeof(follow)) != (ssize_t)sizeof(follow)) return 5;
    close(fd);
    return 0;
}
"""

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            library = tmpdir / "libkamal-nrf-fixed-adv.so"
            writer_c = tmpdir / "writer.c"
            writer = tmpdir / "writer"
            serial = tmpdir / "fake-serial"
            meta = tmpdir / "shim.log"
            ready = tmpdir / "follow.ready"
            writer_c.write_text(writer_source, encoding="utf-8")

            for command in (
                [
                    cc,
                    "-shared",
                    "-fPIC",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-o",
                    str(library),
                    str(FIXED_ADV),
                    "-ldl",
                    "-pthread",
                ],
                [cc, "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(writer), str(writer_c)],
            ):
                result = subprocess.run(command, check=False, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

            env = os.environ.copy()
            env.update(
                {
                    "LD_PRELOAD": str(library),
                    "KAMAL_PRELOAD_TARGET": str(serial),
                    "KAMAL_PRELOAD_METALOG": str(meta),
                    "KAMAL_PRELOAD_READY_FILE": str(ready),
                    "KAMAL_FIXED_ADV_CHANNEL": "38",
                }
            )
            result = subprocess.run(
                [str(writer), str(serial)],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            data = serial.read_bytes()
            self.assertEqual(
                data[:12].hex(),
                "ab06040103001701262525bc",
            )
            self.assertEqual(
                data[12:].hex(),
                "ab060901060000001c4d45de3f010001bc",
            )
            metadata = meta.read_text(encoding="utf-8")
            self.assertIn("MUTATED selected_channel=38 count=1\n", metadata)
            self.assertIn("FOLLOW_REQUEST_SENT\n", metadata)
            self.assertEqual(ready.read_text(encoding="utf-8"), "follow_request_sent\n")


if __name__ == "__main__":
    unittest.main()

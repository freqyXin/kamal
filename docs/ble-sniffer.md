## BLE Sniffer Module

K'amal supports a dedicated Bluetooth Low Energy capture radio using a Nordic Semiconductor **nRF52840 Dongle (PCA10059)** running the **nRF Sniffer for Bluetooth LE** firmware.

This allows the Raspberry Pi's onboard Bluetooth controller to remain available for normal BlueZ-based scanning and GATT interaction while the external nRF52840 is used for passive over-the-air packet capture.

### Architecture

```text
Raspberry Pi Bluetooth
        |
        +--> BlueZ / bluetoothctl / active BLE interaction

nRF52840 Dongle
        |
        +--> nRF Sniffer for Bluetooth LE firmware
                 |
                 +--> nrfutil ble-sniffer
                           |
                           +--> PCAP capture
```

### Supported Hardware

Current supported BLE capture hardware:

* Nordic Semiconductor nRF52840 Dongle
* Board: `PCA10059`
* USB DFU VID:PID: `1915:521f`
* BLE sniffer firmware VID:PID: `1915:522a`

The dongle is programmed using Nordic's USB DFU bootloader and does not require a J-Link programmer.

### Installation

Run from the repository root:

```bash
bash setup/setup-ble-sniffer.sh
```

Using `bash` is intentional: it does not depend on the checkout preserving the
executable bit.

The installer:

* Installs the required Debian packages.
* Installs Nordic `nrfutil`.
* Installs the `device` and `ble-sniffer` nrfutil plugins.
* Bootstraps the BLE sniffer tooling.
* Detects an nRF52840 Dongle in DFU or sniffer mode.
* Programs the current nRF Sniffer for Bluetooth LE firmware when required.
* Detects the dongle's application-mode USB serial number.
* Creates a persistent device alias.
* Creates the BLE capture directory.
* Verifies that the radio is available.

### Persistent Device Name

Linux may assign the dongle a different `/dev/ttyACM*` number depending on boot order and other connected USB devices.

K'amal therefore creates:

```text
/dev/kamal-ble-sniffer
```

For example:

```text
/dev/kamal-ble-sniffer -> /dev/ttyACM0
```

The udev rule identifies the dongle by its application-mode USB vendor ID, product ID, interface number, and device serial.

The alias intentionally identifies a dongle running the BLE sniffer firmware rather than a Nordic device merely present in DFU mode.

### nrfutil Device Resolution

Nordic's `ble-sniffer` command expects the underlying kernel serial device and may not resolve a custom udev symlink directly.

Resolve the K'amal device before invoking `nrfutil`:

```bash
PORT="$(readlink -e /dev/kamal-ble-sniffer)"
```

Then use:

```bash
nrfutil ble-sniffer sniff \
    --port "$PORT" \
    --output-pcap-file capture.pcap
```

### Captures

The default K'amal BLE capture directory is:

```text
~/captures/ble/
```

Example:

```bash
mkdir -p ~/captures/ble
cd ~/captures/ble

PORT="$(readlink -e /dev/kamal-ble-sniffer)"

nrfutil ble-sniffer sniff \
    --port "$PORT" \
    --output-pcap-file test-ble.pcap
```

Stop the capture with `Ctrl-C`.

### Verify a Capture

Inspect capture metadata:

```bash
capinfos test-ble.pcap
```

A valid capture should report:

```text
File encapsulation: nRF Sniffer for Bluetooth LE
```

Packets can be inspected directly on the K'amal node:

```bash
tshark -r test-ble.pcap | head -30
```

Or the PCAP can be transferred to a workstation and opened in Wireshark.

### Example Capture

A functioning K'amal BLE node has been validated capturing advertising traffic such as:

```text
ADV_IND
ADV_NONCONN_IND
ADV_EXT_IND
SCAN_RSP
```

The nRF52840 operates as the dedicated BLE capture radio while the Pi's onboard controller remains available independently.

### Device Modes

The nRF52840 presents different USB identities depending on its current firmware state.

#### DFU Mode

```text
VID:PID: 1915:521f
Product: Open DFU Bootloader
```

This state is used when programming the dongle.

#### BLE Sniffer Mode

```text
VID:PID: 1915:522a
Product: nRF Sniffer for Bluetooth LE
```

This is the normal operational state for BLE capture.


### Three-Channel Advertising Observation Plane

K'amal can use three nRF52840 sniffers as a fixed primary-advertising
observation plane. Each receiver is pinned to one advertising channel:

```text
/dev/kamal-ble-sniffer-37  -> channel 37
/dev/kamal-ble-sniffer-38  -> channel 38
/dev/kamal-ble-sniffer-39  -> channel 39
```

The aliases are keyed by each dongle's application-mode USB serial number; they
do not depend on `/dev/ttyACM*` enumeration order. The legacy
`/dev/kamal-ble-sniffer` alias remains available for normal single-radio
capture.

When exactly three sniffers are connected, provisioning assigns those three
automatically. If more than three are connected, provisioning fails closed
unless the advertising-plane radios are selected explicitly with
`KAMAL_BLE_ADV37_SERIAL`, `KAMAL_BLE_ADV38_SERIAL`, and
`KAMAL_BLE_ADV39_SERIAL`. This prevents adding future receiver-pool hardware
from silently changing the fixed advertising-plane assignments.

The mode was hardware-validated with `nrfutil 8.2.1`, BLE-sniffer plugin
`0.21.0`, and Nordic nRF Sniffer for Bluetooth LE firmware `4.1.1`. The current
Nordic CLI does not expose the firmware's one-entry advertising hop sequence,
so `setup/setup-ble-sniffer.sh` installs a small K'amal `LD_PRELOAD` adapter at:

```text
/usr/local/lib/kamal/libkamal-nrf-fixed-adv.so
```

The adapter rewrites only the validated Nordic
`SET_ADV_CHANNEL_HOP_SEQ [37,38,39]` command for the explicitly selected serial
port. Other host-to-device writes pass through unchanged.

Start a bounded three-channel capture with an explicitly selected advertiser:

```bash
bin/kamal-capture ble-adv3 \
    --address AA:BB:CC:DD:EE:FF \
    --duration 60
```

K'amal starts the receivers sequentially and waits until each nrfutil process
has sent its follow request before starting the next receiver. This stagger is
required by the validated three-radio workflow. The follow-request marker is
host-command evidence only; it is **not** proof that the target has already
been acquired over RF.

After all three follow requests have been sent, the requested steady-state
capture duration begins. The output directory contains one PCAP per channel,
shim logs, process logs, and `manifest.json`. The manifest records radio serials,
resolved ports, channel counts, off-channel packet counts, PCAP SHA-256 digests,
and the distinction between follow-request issuance and RF acquisition.

The three PCAPs intentionally remain separate. K'amal does not currently merge
them because Nordic packet timestamps can contain discontinuities that require
separate correlation handling.

### Troubleshooting

#### `/dev/kamal-ble-sniffer` does not exist

Check whether the dongle is connected:

```bash
lsusb
```

Look for:

```text
1915:522a
```

Then inspect available serial devices:

```bash
ls -l /dev/ttyACM*
```

Reload the udev rules if necessary:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=tty
sudo udevadm settle
```

#### Dongle appears as `Open DFU Bootloader`

If `lsusb` shows:

```text
1915:521f
```

the device is currently in DFU mode.

Run:

```bash
nrfutil device list
```

and re-run:

```bash
bash setup/setup-ble-sniffer.sh
```

The installer will detect DFU mode and program the BLE sniffer firmware.

#### `Could not find board ID`

If this command fails:

```bash
nrfutil ble-sniffer sniff \
    --port /dev/kamal-ble-sniffer
```

resolve the actual kernel serial port first:

```bash
PORT="$(readlink -e /dev/kamal-ble-sniffer)"

nrfutil ble-sniffer sniff \
    --port "$PORT"
```

K'amal's higher-level capture tooling will handle this resolution automatically.

### K'amal Capture Interface

The BLE module is exposed through the common K'amal capture interface:

```bash
bin/kamal-capture ble
```

Supported examples include:

```bash
bin/kamal-capture ble --duration 60
bin/kamal-capture ble --name Sensor
bin/kamal-capture ble --address AA:BB:CC:DD:EE:FF
bin/kamal-capture ble --advertising-only --duration 60
bin/kamal-capture ble-adv3 --address AA:BB:CC:DD:EE:FF --duration 60
```

The public K'amal option names are intentionally stable even when Nordic changes
its backend CLI spelling. With the validated `nrfutil 8.2.1` BLE-sniffer plugin,
K'amal translates `--address` to Nordic `--follow` and K'amal
`--advertising-only` to Nordic `--only-advertising`. The wrapper continues to
provide automatic capture naming, metadata generation, duration handling, and
consistent operation across K'amal radio modules.

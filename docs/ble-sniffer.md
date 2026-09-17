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

Run:

```bash
chmod +x setup/setup-ble-sniffer.sh
./setup/setup-ble-sniffer.sh
```

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
./setup/setup-ble-sniffer.sh
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

### Planned Integration

The BLE module will ultimately be exposed through the common K'amal capture interface:

```bash
kamal-capture ble
```

Planned functionality includes:

```bash
kamal-capture ble --duration 60
kamal-capture ble --name Sensor
kamal-capture ble --address AA:BB:CC:DD:EE:FF
```

This will provide automatic capture naming, metadata generation, duration handling, and consistent operation across K'amal radio modules.

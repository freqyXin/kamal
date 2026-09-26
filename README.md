# K'amal


**K’amal** is a portable Raspberry Pi-based cellular field node designed for remote access and wireless security testing.

The name **K’amal** comes from K’iche’ Maya and is intended to mean **“one who carries,” or “one who conducts,”** This is reflected in the device's primary role, which is to carry operational comms between deployed systems and remote operators.

K’amal simplifies pairing a Raspberry Pi 5 with a Sixfab cellular HAT and Telit LE910C4-NF LTE modem. The modem operates as a USB Ethernet device using ECM, providing the Pi with an independent cellular Internet connection.

Tailscale provides remote connectivity across carrier NAT/CGNAT without requiring a publicly routable cellular IP address.

## Architecture

```text
                  Remote Researcher
                         │
                         │ SSH
                         ▼
                     Tailscale
                         │
                    Internet / LTE
                         │
                         ▼
                Telit LE910C4-NF
                         │
                      USB ECM
                         │
                         ▼
                       wwan0
                         │
                         ▼
                   Raspberry Pi
                         │
             ┌───────────┴───────────┐
             │                       │
          RF Tools              Local Network
             │                       │
       SDR / BLE / Wi-Fi          wlan0/eth0
       Zigbee / LoRa / etc.
```

## Hardware

The reference K’amal configuration uses:

* Raspberry Pi
* Sixfab cellular Base HAT
* Telit LE910C4-NF LTE modem
* Sixfab cellular SIM
* Wi-Fi and/or Ethernet for local connectivity

Additional RF hardware can be attached depending on the deployment, including SDRs, BLE adapters, 802.15.4 radios, Wi-Fi adapters, and other research hardware.

## Network Design

K’amal maintains two possible Internet paths:

```text
wlan0 → Wi-Fi Internet
wwan0 → Telit LTE Internet
```

Wi-Fi is normally preferred.

The LTE interface is configured with a higher route metric so it can remain available as a secondary path:

```text
default via <wifi-gateway> dev wlan0 metric 600
default via 192.168.225.1 dev wwan0 metric 900
```

If Wi-Fi becomes unavailable, Linux can select the LTE route.

The cellular interface receives an address from the Telit's internal ECM network, typically:

```text
192.168.225.x/24
```

with the modem available at:

```text
192.168.225.1
```

The carrier-facing address may be behind CGNAT and therefore should not be assumed to accept unsolicited inbound connections.

## Remote Access

K’amal uses Tailscale for remote management.

This provides a stable private address for the node regardless of whether its current upstream connection is Wi-Fi or LTE.

Typical access is therefore:

```bash
ssh <user>@<tailscale-ip>
```

rather than connecting directly to the modem's carrier-facing address.

This architecture also avoids requiring port forwarding or a publicly routable cellular IP address.

## Python development environment

K'amal uses a project-local Python virtual environment for development
and testing.

Create the environment:

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.txt

Run the complete test suite:

    .venv/bin/python -m unittest discover -s tests -v

Use .venv/bin/python explicitly to avoid selecting another Python installation.

The assessment engine operates offline without Bluetooth hardware.
GATT inspection and surveys require Bleak and a configured Bluetooth
environment.

The dependency manifest currently covers BLE GATT functionality, not
every K'amal hardware integration.

## BLE Security Tooling

K'amal includes passive BLE inventory and active GATT enumeration
capabilities alongside its cellular field-node infrastructure.

### Passive inventory

Analyze an existing BLE PCAP:

```bash
bin/kamal-scan ble --input capture.pcap --json inventory.json
```

The scanner uses tshark to process captured advertising traffic.
It reports observed advertisers, advertising data, CRC integrity,
scan-request activity, and offline Bluetooth SIG identifier names.

Passive observations do not confirm physical device identity or
establish that GATT services were enumerated.

### Active GATT enumeration

Inspect an explicitly selected, authorized BLE target:

```bash
bin/kamal-gatt inspect AA:BB:CC:DD:EE:FF \
  --adapter hci0 \
  --timeout 10 \
  --json gatt.json
```

This command uses BlueZ and Bleak to enumerate GATT metadata.
It records services, characteristics, descriptors, characteristic
properties, connection outcomes, and offline UUID resolution.

It does not explicitly read or write characteristic values,
subscribe to notifications, or request pairing. GATT discovery
may involve protocol-level ATT reads.

### Offline assessments

Combine existing passive BLE and active GATT reports into an offline assessment.

See the [assessment guide](docs/assessment.md) for usage, provenance, validation, and limitations.

### Identifier registries

Generate the Bluetooth SIG identifier registries locally before
using the BLE analysis commands.

See [Bluetooth identifier registry setup](data/bluetooth/README.md).

For capture hardware setup, see
[BLE sniffer documentation](docs/ble-sniffer.md).

For the v0.12 Bluetooth pairing/security-state/key-evidence contracts, see
[Bluetooth security evidence](docs/bluetooth-security-evidence.md) and
[ADR-004](docs/adr-004-bluetooth-security-state-key-evidence.md).

BLE-SEC-02 adds read-only inspection of one exact target already present in
BlueZ's local cache/persistent store:

```bash
sudo .venv/bin/python bin/kamal-inspect-bluez-state \
  --adapter 88:A2:9E:C6:E9:09 \
  --target 00:1C:4D:45:DE:3F \
  --engagement-id engagement:example \
  --authorization-ref auth:example \
  --json /tmp/bluez-security-state.json
```

This command does not scan, connect, pair, modify a bond, or emit raw Bluetooth
key values. Pairing, key extraction/copying, RPA resolution, and capture
decryption remain separately gated work.

### Releases

See [v0.9.0 release notes](docs/releases/v0.9.0.md), [v0.8.0 release notes](docs/releases/v0.8.0.md) and [v0.7.0 release notes](docs/releases/v0.7.0.md).

## Project Goals

K'amal is intended to provide a reusable foundation for remotely deployed wireless-security infrastructure.

Potential applications include:

* Remote RF monitoring
* BLE observation and capture
* Wi-Fi monitoring
* 802.15.4 / Zigbee / Thread research
* LoRa experimentation
* SDR collection
* Remote packet capture
* Environmental RF surveys
* Security assessment field infrastructure
* Distributed wireless IDS sensors
* Temporary research nodes
* Remote access to equipment located at test sites

The Raspberry Pi provides the compute platform, the Telit modem provides independent backhaul, and Tailscale provides a manageable remote-access layer.

## Status

Current reference implementation:

```text
Platform:        Raspberry Pi
Cellular HAT:    Sixfab
Modem:           Telit LE910C4-NF
USB networking:  ECM / cdc_ether
Cellular IF:     wwan0
AT interface:    /dev/telit-at
LTE metric:      900
Remote access:   Tailscale + SSH
```

The current implementation has been tested for:

* LTE registration
* PDP context activation
* ECM activation
* DHCP over the Telit ECM interface
* Internet access through `wwan0`
* Wi-Fi/LTE route preference
* Tailscale remote access
* Automated ECM activation
* Persistent AT-device naming

## License

K'amal is licensed under the Apache License, Version 2.0.

You may use, modify, and distribute K'amal, including for commercial
purposes, subject to the terms of the Apache License 2.0.

See [LICENSE](LICENSE) for details.

For security research deployments, ensure all monitoring, interception, collection, and testing is performed only on systems and radio environments where you have appropriate authorization.

# kamal


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

## Telit ECM Configuration

The Telit LE910C4-NF is configured to expose an Ethernet Control Model interface over USB.

The reference USB configuration is:

```text
AT#USBCFG=4
```

The resulting Linux network interface uses the `cdc_ether` driver and appears as:

```text
wwan0
```

A typical enumeration is:

```text
Vendor:  Telit Wireless Solutions
Model:   LE910C4-NF
VID:PID: 1bc7:1206
Driver:  cdc_ether
```

### ECM Data Session

An important behavior observed during development is that cellular registration and PDP activation do **not necessarily mean ECM packet forwarding is active**.

The modem can report:

```text
AT+CGATT?
+CGATT: 1

AT+CGACT?
+CGACT: 1,1
```

while:

```text
AT#ECM?
#ECM: 0,0
```

In this state, the Pi can communicate with the modem at `192.168.225.1`, but the modem may return:

```text
Destination Net Unreachable
```

for Internet-bound traffic.

ECM forwarding is activated with:

```text
AT#ECM=1,0
```

A working state is:

```text
AT#ECM?

#ECM: 0,1
```

K'amal automates this process during boot.

## Persistent AT Interface

The LE910C4-NF exposes several USB serial interfaces, so relying directly on names such as:

```text
/dev/ttyUSB2
```

is undesirable.

K'amal uses a udev rule to identify the modem's AT-command interface and create:

```text
/dev/telit-at
```

The reference hardware currently identifies the AT interface as:

```text
USB VID:            1bc7
USB PID:            1206
USB Interface:      05
Driver:             option
```

The corresponding udev rule is:

```udev
SUBSYSTEM=="tty", ENV{ID_VENDOR_ID}=="1bc7", ENV{ID_MODEL_ID}=="1206", ENV{ID_USB_INTERFACE_NUM}=="05", SYMLINK+="telit-at"
```

This allows scripts and services to use:

```text
/dev/telit-at
```

instead of depending on USB enumeration order.

## systemd-networkd

Only the cellular interface is managed by `systemd-networkd`.

Wi-Fi and Ethernet may remain under NetworkManager.

The reference configuration is:

```ini
[Match]
Name=wwan0
Driver=cdc_ether

[Network]
DHCP=ipv4
IPv6AcceptRA=no

[DHCPv4]
UseRoutes=yes
RouteMetric=900
UseDNS=no
```

This configuration is installed as:

```text
/etc/systemd/network/10-sixfab.network
```

## Automatic ECM Activation

K'amal installs a systemd service responsible for activating the modem's ECM data session during boot.

```text
telit-ecm.service
```

The service waits for:

```text
/dev/telit-at
```

and sends:

```text
AT#ECM=1,0
```

It then verifies that:

```text
AT#ECM?
```

returns:

```text
#ECM: 0,1
```

This allows the cellular connection to recover automatically following a reboot or power cycle.

Service status can be inspected with:

```bash
systemctl status telit-ecm.service
```

Logs are available with:

```bash
journalctl -u telit-ecm.service -b
```

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd kamal
```

Run the provisioning script:

```bash
chmod +x setup-sixfab.sh
sudo ./setup-sixfab.sh
```

The installer configures:

```text
udev
 └── /dev/telit-at

systemd-networkd
 └── wwan0

systemd
 └── telit-ecm.service

/usr/local/sbin
 └── telit-ecm-up.sh
```

## Verification

Confirm that the persistent AT interface exists:

```bash
ls -l /dev/telit-at
```

Confirm ECM activation:

```bash
systemctl status telit-ecm.service
```

Inspect the cellular interface:

```bash
networkctl status wwan0
```

Inspect routing:

```bash
ip route
```

Test the modem gateway:

```bash
ping -I wwan0 -c 4 192.168.225.1
```

Test Internet connectivity explicitly through LTE:

```bash
ping -I wwan0 -c 4 8.8.8.8
```

A successful LTE test demonstrates:

```text
Raspberry Pi
     │
   wwan0
     │
192.168.225.1
     │
Telit LE910C4-NF
     │
     LTE
     │
  Internet
```

## Failover Testing

Before deliberately disabling the primary network interface, ensure local console access or another recovery method is available.

With both Wi-Fi and LTE active:

```bash
ip route
```

The expected preference is approximately:

```text
wlan0 metric 600
wwan0 metric 900
```

Test LTE independently:

```bash
ping -I wwan0 -c 4 8.8.8.8
```

Then Wi-Fi can be temporarily disconnected:

```bash
sudo nmcli device disconnect wlan0
```

Verify Internet access:

```bash
ip route get 8.8.8.8
ping -c 4 8.8.8.8
```

Finally, attempt a new Tailscale SSH connection from another system.

Restore Wi-Fi with:

```bash
sudo nmcli device connect wlan0
```

## Troubleshooting

### `wwan0` exists but has no Internet access

Check:

```bash
networkctl status wwan0
```

Then query the modem:

```text
AT+CPIN?
AT+CEREG?
AT+CGATT?
AT+CGACT?
AT+CGPADDR=1
AT#ECM?
```

A registered modem may look similar to:

```text
+CPIN: READY
+CEREG: 0,5
+CGATT: 1
+CGACT: 1,1
```

If:

```text
#ECM: 0,0
```

activate ECM:

```text
AT#ECM=1,0
```

### Modem gateway returns `Destination Net Unreachable`

If:

```bash
ping -I wwan0 8.8.8.8
```

returns an error from:

```text
192.168.225.1
```

verify:

```text
AT#ECM?
```

The expected state is:

```text
#ECM: 0,1
```

### Check boot-time activation

```bash
journalctl -u telit-ecm.service -b --no-pager
```

### Check USB enumeration

```bash
lsusb
lsusb -t
```

### Check the persistent AT device

```bash
udevadm info -q property -p /sys/class/tty/ttyUSB2
```

and:

```bash
readlink -f /dev/telit-at
```

## Security Considerations

K'amal is intended for remote field deployment and should be treated as an Internet-connected research system.

Recommended baseline controls include:

* SSH key authentication
* Disable SSH password authentication where practical
* Keep the operating system and packages patched
* Restrict remote administrative access to the Tailscale network
* Do not expose SSH directly through the cellular provider
* Protect Tailscale account and device enrollment
* Use least privilege for research services
* Protect stored captures, credentials, API keys, and collected data
* Assume physical access to a deployed node may result in compromise
* Encrypt sensitive local storage where appropriate
* Remove stale nodes from the Tailscale network after retirement

K'amal should not depend on the cellular provider's CGNAT behavior as a security boundary.

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


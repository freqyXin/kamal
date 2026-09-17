#!/usr/bin/env bash
#
# K'amal BLE Sniffer Provisioning
#
# Provisions a Nordic nRF52840 Dongle (PCA10059) as a dedicated
# Bluetooth Low Energy capture radio using Nordic's nRF Sniffer
# for Bluetooth LE firmware.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Maxine Filcher
#

set -Eeuo pipefail

readonly NRFUTIL_URL="https://files.nordicsemi.com/artifactory/swtools/external/nrfutil/executables/aarch64-unknown-linux-gnu/nrfutil"
readonly NRFUTIL_BIN="/usr/local/bin/nrfutil"

readonly UDEV_RULE="/etc/udev/rules.d/99-kamal-radios.rules"
readonly KAMAL_DEVICE="/dev/kamal-ble-sniffer"

readonly NORDIC_VID="1915"
readonly DFU_PID="521f"
readonly SNIFFER_PID="522a"

readonly CAPTURE_DIR="${HOME}/captures/ble"

log() {
    printf '\n[Kamal] %s\n' "$*"
}

die() {
    printf '\n[Kamal] ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 ||
        die "Required command not found: $1"
}

# ----------------------------------------------------------------------
# Platform checks
# ----------------------------------------------------------------------

log "Checking platform..."

ARCH="$(uname -m)"

if [[ "$ARCH" != "aarch64" ]]; then
    die "This installer currently supports aarch64 only. Detected: $ARCH"
fi

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
else
    die "Unable to determine operating system."
fi

log "Detected: ${PRETTY_NAME:-unknown} (${ARCH})"

# ----------------------------------------------------------------------
# Packages
# ----------------------------------------------------------------------

log "Installing required Debian packages..."

sudo apt-get update

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    usbutils \
    udev \
    wireshark \
    wireshark-common \
    tshark

# ----------------------------------------------------------------------
# nrfutil
# ----------------------------------------------------------------------

if command -v nrfutil >/dev/null 2>&1; then
    log "nrfutil already installed: $(command -v nrfutil)"
else
    log "Installing Nordic nrfutil for aarch64..."

    TMP_NRFUTIL="$(mktemp)"

    curl -fL "$NRFUTIL_URL" -o "$TMP_NRFUTIL"

    chmod +x "$TMP_NRFUTIL"

    sudo install -m 0755 "$TMP_NRFUTIL" "$NRFUTIL_BIN"

    rm -f "$TMP_NRFUTIL"
fi

require_command nrfutil

log "nrfutil version:"
nrfutil --version || true

# ----------------------------------------------------------------------
# Nordic plugins
# ----------------------------------------------------------------------

log "Ensuring Nordic device plugin is installed..."

if ! nrfutil list | grep -qE '^device[[:space:]]'; then
    nrfutil install device
else
    log "device plugin already installed."
fi

log "Ensuring Nordic BLE sniffer plugin is installed..."

if ! nrfutil list | grep -qE '^ble-sniffer[[:space:]]'; then
    nrfutil install ble-sniffer
else
    log "ble-sniffer plugin already installed."
fi

# ----------------------------------------------------------------------
# BLE sniffer bootstrap
# ----------------------------------------------------------------------

log "Bootstrapping BLE sniffer..."

nrfutil ble-sniffer bootstrap

# ----------------------------------------------------------------------
# Locate firmware
# ----------------------------------------------------------------------

FIRMWARE_DIR="${HOME}/.nrfutil/share/nrfutil-ble-sniffer/firmware"

FIRMWARE="$(
    find "$FIRMWARE_DIR" \
        -maxdepth 1 \
        -type f \
        -name 'sniffer_nrf52840dongle_nrf52840_*.zip' \
        -print 2>/dev/null |
    sort -V |
    tail -n 1
)"

[[ -n "$FIRMWARE" ]] ||
    die "Could not locate PCA10059 BLE sniffer firmware."

log "Using firmware:"
printf '  %s\n' "$FIRMWARE"

# ----------------------------------------------------------------------
# Detect current USB state
# ----------------------------------------------------------------------

log "Checking for Nordic PCA10059..."

DFU_USB="$(
    lsusb -d "${NORDIC_VID}:${DFU_PID}" 2>/dev/null || true
)"

SNIFFER_USB="$(
    lsusb -d "${NORDIC_VID}:${SNIFFER_PID}" 2>/dev/null || true
)"

if [[ -n "$SNIFFER_USB" ]]; then

    log "BLE sniffer firmware already appears to be running."

elif [[ -n "$DFU_USB" ]]; then

    log "PCA10059 detected in DFU mode."

    DEVICE_LIST="$(nrfutil device list 2>/dev/null || true)"

    DFU_SERIAL="$(
        printf '%s\n' "$DEVICE_LIST" |
        awk '
            /^[[:alnum:]]+$/ {
                candidate=$1
            }
            /Product[[:space:]]+Open DFU Bootloader/ {
                print candidate
                exit
            }
        '
    )"

    [[ -n "$DFU_SERIAL" ]] ||
        die "PCA10059 is visible over USB but its DFU serial number could not be determined."

    log "DFU serial: $DFU_SERIAL"

    log "Programming BLE sniffer firmware..."

    nrfutil device program \
        --firmware "$FIRMWARE" \
        --serial-number "$DFU_SERIAL"

    log "Waiting for USB re-enumeration..."

    for _ in $(seq 1 30); do
        if lsusb -d "${NORDIC_VID}:${SNIFFER_PID}" >/dev/null 2>&1; then
            break
        fi

        sleep 1
    done

    lsusb -d "${NORDIC_VID}:${SNIFFER_PID}" >/dev/null 2>&1 ||
        die "Sniffer did not re-enumerate after programming."

else

    die "No PCA10059 found in DFU or BLE-sniffer mode."

fi

# ----------------------------------------------------------------------
# Discover application-mode serial
# ----------------------------------------------------------------------

log "Discovering BLE sniffer application serial..."

SNIFFER_TTY=""

for tty in /dev/ttyACM*; do

    [[ -e "$tty" ]] || continue

    props="$(
        udevadm info \
            --query=property \
            --name="$tty" 2>/dev/null || true
    )"

    if grep -q '^ID_VENDOR_ID=1915$' <<< "$props" &&
       grep -q '^ID_MODEL_ID=522a$' <<< "$props" &&
       grep -q '^ID_MODEL=nRF_Sniffer_for_Bluetooth_LE$' <<< "$props"; then

        SNIFFER_TTY="$tty"
        break
    fi

done

[[ -n "$SNIFFER_TTY" ]] ||
    die "Could not identify the BLE sniffer serial interface."

SNIFFER_SERIAL="$(
    udevadm info \
        --query=property \
        --name="$SNIFFER_TTY" |
    sed -n 's/^ID_SERIAL_SHORT=//p'
)"

[[ -n "$SNIFFER_SERIAL" ]] ||
    die "Could not determine BLE sniffer USB serial."

log "BLE sniffer detected:"
printf '  Port:   %s\n' "$SNIFFER_TTY"
printf '  Serial: %s\n' "$SNIFFER_SERIAL"

# ----------------------------------------------------------------------
# Persistent udev alias
# ----------------------------------------------------------------------

log "Installing persistent K'amal radio alias..."

sudo tee "$UDEV_RULE" >/dev/null <<EOF
# K'amal radio aliases
#
# nRF52840 PCA10059 running nRF Sniffer for Bluetooth LE firmware
SUBSYSTEM=="tty", ENV{ID_VENDOR_ID}=="1915", ENV{ID_MODEL_ID}=="522a", ENV{ID_USB_INTERFACE_NUM}=="00", ENV{ID_SERIAL_SHORT}=="${SNIFFER_SERIAL}", SYMLINK+="kamal-ble-sniffer"
EOF

sudo udevadm control --reload-rules

sudo udevadm trigger --subsystem-match=tty

sudo udevadm settle

# ----------------------------------------------------------------------
# Verify persistent alias
# ----------------------------------------------------------------------

if [[ ! -e "$KAMAL_DEVICE" ]]; then
    die "$KAMAL_DEVICE was not created."
fi

RESOLVED_DEVICE="$(readlink -e "$KAMAL_DEVICE")"

[[ -n "$RESOLVED_DEVICE" ]] ||
    die "Unable to resolve $KAMAL_DEVICE."

log "Persistent radio mapping:"
printf '  %-26s -> %s\n' "$KAMAL_DEVICE" "$RESOLVED_DEVICE"

# ----------------------------------------------------------------------
# Capture directory
# ----------------------------------------------------------------------

mkdir -p "$CAPTURE_DIR"

# ----------------------------------------------------------------------
# Final verification
# ----------------------------------------------------------------------

log "Nordic device inventory:"

nrfutil device list || true

log "BLE capture directory:"
printf '  %s\n' "$CAPTURE_DIR"

cat <<EOF

============================================================
 K'amal BLE Sniffer provisioning complete
============================================================

Radio:
    Nordic nRF52840 Dongle (PCA10059)

Firmware:
    $(basename "$FIRMWARE")

Persistent device:
    $KAMAL_DEVICE

Resolved serial port:
    $RESOLVED_DEVICE

Capture directory:
    $CAPTURE_DIR

IMPORTANT:

Nordic's ble-sniffer command does not reliably accept the custom
udev symlink directly. Resolve it before invoking nrfutil:

    PORT="\$(readlink -e $KAMAL_DEVICE)"

    nrfutil ble-sniffer sniff \\
        --port "\$PORT" \\
        --output-pcap-file capture.pcap

Verify a capture with:

    capinfos capture.pcap

============================================================

EOF

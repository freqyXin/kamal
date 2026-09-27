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
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FIXED_ADV_SOURCE="${SCRIPT_DIR}/kamal-nrf-fixed-adv.c"
readonly FIXED_ADV_LIB="/usr/local/lib/kamal/libkamal-nrf-fixed-adv.so"

readonly UDEV_RULE="/etc/udev/rules.d/99-kamal-radios.rules"
readonly KAMAL_DEVICE="/dev/kamal-ble-sniffer"

readonly NORDIC_VID="1915"
readonly DFU_PID="521f"
readonly SNIFFER_PID="522a"

readonly CAPTURE_DIR="${HOME}/captures/ble"

readonly ADV37_SERIAL_OVERRIDE="${KAMAL_BLE_ADV37_SERIAL:-}"
readonly ADV38_SERIAL_OVERRIDE="${KAMAL_BLE_ADV38_SERIAL:-}"
readonly ADV39_SERIAL_OVERRIDE="${KAMAL_BLE_ADV39_SERIAL:-}"

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
    tshark \
    build-essential

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
# Fixed advertising-channel adapter
# ----------------------------------------------------------------------

log "Installing K'amal fixed advertising-channel adapter..."

require_command cc
[[ -f "$FIXED_ADV_SOURCE" ]] ||
    die "Fixed advertising-channel source not found: $FIXED_ADV_SOURCE"

TMP_FIXED_ADV="$(mktemp --suffix=.so)"
cc -shared -fPIC -O2 -Wall -Wextra -Werror \
    -o "$TMP_FIXED_ADV" "$FIXED_ADV_SOURCE" -ldl -pthread
sudo install -D -m 0644 "$TMP_FIXED_ADV" "$FIXED_ADV_LIB"
rm -f "$TMP_FIXED_ADV"

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
# Discover application-mode serials
# ----------------------------------------------------------------------

log "Discovering BLE sniffer application serials..."

EXISTING_KAMAL_TTY="$(readlink -e "$KAMAL_DEVICE" 2>/dev/null || true)"
declare -a SNIFFER_TTYS=()
declare -a SNIFFER_SERIALS=()

for tty in /dev/ttyACM*; do
    [[ -e "$tty" ]] || continue

    props="$(udevadm info --query=property --name="$tty" 2>/dev/null || true)"

    if grep -q '^ID_VENDOR_ID=1915$' <<< "$props" &&
       grep -q '^ID_MODEL_ID=522a$' <<< "$props" &&
       grep -q '^ID_MODEL=nRF_Sniffer_for_Bluetooth_LE$' <<< "$props"; then
        serial="$(sed -n 's/^ID_SERIAL_SHORT=//p' <<< "$props")"
        [[ -n "$serial" ]] || die "Could not determine BLE sniffer USB serial for $tty."
        SNIFFER_TTYS+=("$tty")
        SNIFFER_SERIALS+=("$serial")
    fi
done

(( ${#SNIFFER_TTYS[@]} > 0 )) ||
    die "Could not identify a BLE sniffer serial interface."

PRIMARY_INDEX=0
if [[ -n "$EXISTING_KAMAL_TTY" ]]; then
    for index in "${!SNIFFER_TTYS[@]}"; do
        if [[ "${SNIFFER_TTYS[$index]}" == "$EXISTING_KAMAL_TTY" ]]; then
            PRIMARY_INDEX="$index"
            break
        fi
    done
fi

SNIFFER_TTY="${SNIFFER_TTYS[$PRIMARY_INDEX]}"
SNIFFER_SERIAL="${SNIFFER_SERIALS[$PRIMARY_INDEX]}"

ADV37_SERIAL=""
ADV38_SERIAL=""
ADV39_SERIAL=""

OVERRIDE_COUNT=0
for override in "$ADV37_SERIAL_OVERRIDE" "$ADV38_SERIAL_OVERRIDE" "$ADV39_SERIAL_OVERRIDE"; do
    [[ -z "$override" ]] || OVERRIDE_COUNT=$((OVERRIDE_COUNT + 1))
done

if (( OVERRIDE_COUNT != 0 && OVERRIDE_COUNT != 3 )); then
    die "Set all three of KAMAL_BLE_ADV37_SERIAL, KAMAL_BLE_ADV38_SERIAL, and KAMAL_BLE_ADV39_SERIAL, or set none of them."
fi

if (( OVERRIDE_COUNT == 3 )); then
    for override in "$ADV37_SERIAL_OVERRIDE" "$ADV38_SERIAL_OVERRIDE" "$ADV39_SERIAL_OVERRIDE"; do
        [[ "$override" =~ ^[[:alnum:]]+$ ]] ||
            die "Invalid BLE advertising-plane serial: $override"
        printf '%s\n' "${SNIFFER_SERIALS[@]}" | grep -qxF "$override" ||
            die "Requested BLE advertising-plane serial is not connected: $override"
    done
    [[ "$ADV37_SERIAL_OVERRIDE" != "$ADV38_SERIAL_OVERRIDE" &&
       "$ADV37_SERIAL_OVERRIDE" != "$ADV39_SERIAL_OVERRIDE" &&
       "$ADV38_SERIAL_OVERRIDE" != "$ADV39_SERIAL_OVERRIDE" ]] ||
        die "BLE advertising-plane serial assignments must be distinct."

    ADV37_SERIAL="$ADV37_SERIAL_OVERRIDE"
    ADV38_SERIAL="$ADV38_SERIAL_OVERRIDE"
    ADV39_SERIAL="$ADV39_SERIAL_OVERRIDE"
elif (( ${#SNIFFER_SERIALS[@]} == 3 )); then
    ADV37_SERIAL="$SNIFFER_SERIAL"
    mapfile -t REMAINING_SERIALS < <(
        printf '%s\n' "${SNIFFER_SERIALS[@]}" |
        grep -vxF "$SNIFFER_SERIAL" |
        sort
    )
    ADV38_SERIAL="${REMAINING_SERIALS[0]}"
    ADV39_SERIAL="${REMAINING_SERIALS[1]}"
elif (( ${#SNIFFER_SERIALS[@]} > 3 )); then
    die "More than three BLE sniffers are connected. Set KAMAL_BLE_ADV37_SERIAL, KAMAL_BLE_ADV38_SERIAL, and KAMAL_BLE_ADV39_SERIAL explicitly before provisioning."
fi

log "BLE sniffer inventory:"
for index in "${!SNIFFER_TTYS[@]}"; do
    printf '  Port: %-14s Serial: %s\n' "${SNIFFER_TTYS[$index]}" "${SNIFFER_SERIALS[$index]}"
done

log "Primary BLE sniffer:"
printf '  Port:   %s\n' "$SNIFFER_TTY"
printf '  Serial: %s\n' "$SNIFFER_SERIAL"

if [[ -n "$ADV37_SERIAL" && -n "$ADV38_SERIAL" && -n "$ADV39_SERIAL" ]]; then
    log "Three-channel advertising-plane serial assignment:"
    printf '  CH37: %s\n' "$ADV37_SERIAL"
    printf '  CH38: %s\n' "$ADV38_SERIAL"
    printf '  CH39: %s\n' "$ADV39_SERIAL"
else
    log "Fewer than three BLE sniffers are present; ble-adv3 aliases will not be installed."
fi

# ----------------------------------------------------------------------
# Persistent udev alias
# ----------------------------------------------------------------------

log "Installing persistent K'amal radio alias..."

{
    cat <<EOF
# K'amal radio aliases
#
# nRF52840 PCA10059 running nRF Sniffer for Bluetooth LE firmware
SUBSYSTEM=="tty", ENV{ID_VENDOR_ID}=="1915", ENV{ID_MODEL_ID}=="522a", ENV{ID_USB_INTERFACE_NUM}=="00", ENV{ID_SERIAL_SHORT}=="${SNIFFER_SERIAL}", SYMLINK+="kamal-ble-sniffer"
EOF
    if [[ -n "$ADV38_SERIAL" && -n "$ADV39_SERIAL" ]]; then
        cat <<EOF
SUBSYSTEM=="tty", ENV{ID_VENDOR_ID}=="1915", ENV{ID_MODEL_ID}=="522a", ENV{ID_USB_INTERFACE_NUM}=="00", ENV{ID_SERIAL_SHORT}=="${ADV37_SERIAL}", SYMLINK+="kamal-ble-sniffer-37"
SUBSYSTEM=="tty", ENV{ID_VENDOR_ID}=="1915", ENV{ID_MODEL_ID}=="522a", ENV{ID_USB_INTERFACE_NUM}=="00", ENV{ID_SERIAL_SHORT}=="${ADV38_SERIAL}", SYMLINK+="kamal-ble-sniffer-38"
SUBSYSTEM=="tty", ENV{ID_VENDOR_ID}=="1915", ENV{ID_MODEL_ID}=="522a", ENV{ID_USB_INTERFACE_NUM}=="00", ENV{ID_SERIAL_SHORT}=="${ADV39_SERIAL}", SYMLINK+="kamal-ble-sniffer-39"
EOF
    fi
} | sudo tee "$UDEV_RULE" >/dev/null

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

if [[ -n "$ADV38_SERIAL" && -n "$ADV39_SERIAL" ]]; then
    for channel in 37 38 39; do
        alias="/dev/kamal-ble-sniffer-${channel}"
        [[ -e "$alias" ]] || die "$alias was not created."
        resolved="$(readlink -e "$alias")"
        [[ -n "$resolved" ]] || die "Unable to resolve $alias."
        printf '  %-26s -> %s\n' "$alias" "$resolved"
    done
fi

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

Fixed advertising adapter:
    $FIXED_ADV_LIB

IMPORTANT:

Nordic's ble-sniffer command does not reliably accept the custom
udev symlink directly. Resolve it before invoking nrfutil:

    PORT="\$(readlink -e $KAMAL_DEVICE)"

    nrfutil ble-sniffer sniff \\
        --port "\$PORT" \\
        --output-pcap-file capture.pcap

Verify a capture with:

    capinfos capture.pcap

If three sniffer dongles are connected, the installer also creates:

    /dev/kamal-ble-sniffer-37
    /dev/kamal-ble-sniffer-38
    /dev/kamal-ble-sniffer-39

Use the integrated three-channel plane with:

    kamal-capture ble-adv3 --address AA:BB:CC:DD:EE:FF --duration 60

============================================================

EOF

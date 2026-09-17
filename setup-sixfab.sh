#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Sixfab / Telit LE910C4-NF Raspberry Pi setup
#
# Creates:
#   /dev/telit-at
#   systemd-networkd config for wwan0
#   Telit ECM activation helper
#   telit-ecm.service
#
# Assumes:
#   Telit LE910C4-NF
#   USB VID:PID 1bc7:1206
#   AT interface number 05
#   ECM interface wwan0
# ============================================================

TELIT_VENDOR="1bc7"
TELIT_PRODUCT="1206"
TELIT_AT_INTERFACE="05"

UDEV_RULE="/etc/udev/rules.d/99-telit-le910.rules"
NETWORK_FILE="/etc/systemd/network/10-sixfab.network"
ECM_SCRIPT="/usr/local/sbin/telit-ecm-up.sh"
ECM_SERVICE="/etc/systemd/system/telit-ecm.service"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run this script with sudo:"
    echo "  sudo $0"
    exit 1
fi

echo "============================================================"
echo " Sixfab / Telit LE910C4-NF setup"
echo "============================================================"

#
# 1. Sanity-check that the Telit modem exists.
#

echo
echo "[1/7] Checking for Telit modem..."

if lsusb | grep -qi "${TELIT_VENDOR}:${TELIT_PRODUCT}"; then
    echo "Found Telit ${TELIT_VENDOR}:${TELIT_PRODUCT}"
else
    echo "WARNING: Telit ${TELIT_VENDOR}:${TELIT_PRODUCT} not currently visible."
    echo "The configuration will still be installed."
fi

#
# 2. Create stable /dev/telit-at symlink.
#

echo
echo "[2/7] Installing Telit udev rule..."

cat > "$UDEV_RULE" <<EOF
SUBSYSTEM=="tty", ENV{ID_VENDOR_ID}=="${TELIT_VENDOR}", ENV{ID_MODEL_ID}=="${TELIT_PRODUCT}", ENV{ID_USB_INTERFACE_NUM}=="${TELIT_AT_INTERFACE}", SYMLINK+="telit-at"
EOF

udevadm control --reload-rules
udevadm trigger

echo "Installed:"
cat "$UDEV_RULE"

#
# 3. Configure only wwan0 under systemd-networkd.
#
# Wi-Fi / Ethernet can remain under NetworkManager.
#

echo
echo "[3/7] Configuring wwan0..."

mkdir -p /etc/systemd/network

cat > "$NETWORK_FILE" <<'EOF'
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
EOF

echo "Installed:"
cat "$NETWORK_FILE"

#
# 4. Install ECM activation helper.
#

echo
echo "[4/7] Installing Telit ECM activation helper..."

cat > "$ECM_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -u

PORT="/dev/telit-at"
MAX_TRIES=18
WAIT_SECS=5

log()
{
    echo "telit-ecm: $*"
    logger -t telit-ecm "$*" 2>/dev/null || true
}

query_ecm()
{
    local response=""
    local line=""
    local end=$((SECONDS + 5))

    exec 3<>"$PORT" || return 1

    printf 'AT#ECM?\r' >&3

    while (( SECONDS < end )); do
        if IFS= read -r -t 1 line <&3; then
            line="${line//$'\r'/}"
            response+="${line}"$'\n'

            if [[ "$line" == *"#ECM: 0,1"* ]]; then
                exec 3>&-
                return 0
            fi
        fi
    done

    exec 3>&-

    log "ECM query response: ${response//$'\n'/ }"
    return 1
}

for ((attempt=1; attempt<=MAX_TRIES; attempt++)); do

    if [[ ! -e "$PORT" ]]; then
        log "Attempt ${attempt}/${MAX_TRIES}: waiting for ${PORT}"
        sleep "$WAIT_SECS"
        continue
    fi

    log "Attempt ${attempt}/${MAX_TRIES}: found ${PORT}"

    stty -F "$PORT" 115200 raw -echo -echoe -echok -echoctl -echoke \
        2>/dev/null || true

    #
    # See if ECM is already active.
    #

    if query_ecm; then
        log "ECM is already active"
        exit 0
    fi

    #
    # Wake modem AT parser.
    #

    exec 3<>"$PORT" || {
        log "Unable to open ${PORT}"
        sleep "$WAIT_SECS"
        continue
    }

    printf 'AT\r' >&3
    sleep 1

    #
    # Activate ECM.
    #

    log "Sending AT#ECM=1,0"
    printf 'AT#ECM=1,0\r' >&3

    sleep 4
    exec 3>&-

    #
    # Verify.
    #

    if query_ecm; then
        log "ECM successfully activated"
        exit 0
    fi

    log "ECM did not activate; retrying"
    sleep "$WAIT_SECS"
done

log "ERROR: Failed to activate ECM after ${MAX_TRIES} attempts"
exit 1
EOF

chmod 755 "$ECM_SCRIPT"

#
# 5. Install systemd service.
#

echo
echo "[5/7] Installing telit-ecm.service..."

cat > "$ECM_SERVICE" <<'EOF'
[Unit]
Description=Activate Telit LE910C4-NF ECM cellular data session
Wants=systemd-udev-settle.service
After=systemd-udev-settle.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/telit-ecm-up.sh
RemainAfterExit=yes
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

#
# 6. Enable services.
#

echo
echo "[6/7] Enabling services..."

systemctl enable systemd-networkd
systemctl enable telit-ecm.service

#
# Start networkd if it is not already running.
#

systemctl start systemd-networkd

#
# Re-trigger udev after everything is installed.
#

udevadm control --reload-rules
udevadm trigger

sleep 2

#
# Try ECM activation now.
#

systemctl restart telit-ecm.service || true

#
# Reconfigure wwan0 if it exists.
#

if [[ -d /sys/class/net/wwan0 ]]; then
    networkctl reload || true
    networkctl reconfigure wwan0 || true
fi

#
# 7. Verification.
#

echo
echo "[7/7] Verification"
echo "============================================================"

echo
echo "Telit AT device:"

if [[ -e /dev/telit-at ]]; then
    ls -l /dev/telit-at
    echo "Resolves to: $(readlink -f /dev/telit-at)"
else
    echo "WARNING: /dev/telit-at does not currently exist."
fi

echo
echo "ECM service:"
systemctl --no-pager --full status telit-ecm.service || true

echo
echo "wwan0:"
if [[ -d /sys/class/net/wwan0 ]]; then
    networkctl status wwan0 --no-pager || true
else
    echo "wwan0 is not currently present."
fi

echo
echo "Routing table:"
ip route

echo
echo "============================================================"
echo " Installation complete"
echo "============================================================"
echo
echo "Recommended tests:"
echo
echo "  journalctl -u telit-ecm.service -b --no-pager"
echo "  networkctl status wwan0"
echo "  ip route"
echo "  ping -I wwan0 -c 4 8.8.8.8"
echo
echo "After those pass, perform a cold-power-cycle test."

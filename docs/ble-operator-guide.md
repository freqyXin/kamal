# K’amal BLE operator guide

**Applies to:** merged v0.12 development baseline `3676ce3` and descendants unless a later release document supersedes it.

This guide is the shortest supported path from a fresh repository checkout to the BLE capabilities that exist today. It is an operator map, not a replacement for the feature-specific documents linked below.

## 1. Current execution model

K’amal is still a development build. The Python entrypoints use `#!/usr/bin/env python3`, while the tested dependencies live in the project virtual environment. Until runtime entrypoint work (R-01) is complete, invoke Python commands with:

```bash
.venv/bin/python bin/<command> ...
```

`bin/kamal-capture` is a Bash wrapper and can be invoked directly from the repository:

```bash
bin/kamal-capture ...
```

Do not assume `bin/` is installed on `PATH`.

Create the development environment:

```bash
cd ~/kamal
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Run the software regression gate:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Run the synthetic v0.12 acceptance gate with new output paths:

```bash
WORK="$(mktemp -d)"
.venv/bin/python bin/kamal-accept-v012 \
  --work-dir "$WORK/work" \
  --json "$WORK/acceptance.json"
```

The synthetic acceptance command performs no real RF or network operations.

## 2. Command map

| Goal | Current command | Active RF / state change? | Primary documentation |
|---|---|---:|---|
| Capture BLE with one Nordic receiver | `bin/kamal-capture ble ...` | Passive receiver | `docs/ble-sniffer.md` |
| Capture fixed CH37/38/39 advertising plane | `bin/kamal-capture ble-adv3 ...` | Passive receivers | `docs/ble-sniffer.md` |
| Inventory advertisers from a PCAP | `.venv/bin/python bin/kamal-scan ble ...` | No | README + scanner help |
| Inspect one GATT target | `.venv/bin/python bin/kamal-gatt inspect ...` | Yes: connects/enumerates metadata | README |
| Run bounded metadata survey | `.venv/bin/python bin/kamal-gatt survey ...` | Discovery-only unless `--execute`; execution connects | `docs/active-gatt-contracts.md` |
| Build a typed GATT plan | `.venv/bin/python bin/kamal-plan-gatt ...` | No | `docs/active-gatt-contracts.md` |
| Execute a typed GATT plan | `.venv/bin/python bin/kamal-execute-gatt ...` | Yes | `docs/gatt-executor.md` |
| Review GATT result/effect semantics | `.venv/bin/python bin/kamal-review-gatt-result ...` | No | `docs/gatt-result-semantics.md` |
| Resolve blocked active-BLE safety state | `.venv/bin/python bin/kamal-resolve-gatt-unsafe ...` | Operator recovery record | `docs/gatt-safety-interlock.md` |
| Inspect existing BlueZ security state | `sudo .venv/bin/python bin/kamal-inspect-bluez-state ...` | No Bluetooth RF | `docs/bluetooth-security-evidence.md` |
| Analyze existing BlueZ key material locally | `sudo .venv/bin/python bin/kamal-analyze-bluez-keys ...` | No Bluetooth RF | `docs/bluetooth-security-evidence.md` |
| Build a pairing plan | `.venv/bin/python bin/kamal-plan-pairing ...` | No | `docs/pairing-executor.md` |
| Execute pairing/bond attempt | `.venv/bin/python bin/kamal-execute-pairing ...` | Yes; state-changing | `docs/pairing-executor.md` |
| Build offline assessment | `.venv/bin/python bin/kamal-assess ...` | No | `docs/assessment.md` |
| Correlate assessment runs | `.venv/bin/python bin/kamal-correlate ...` | No | `docs/ble-correlation.md` |
| Enrich with local device-intelligence catalog | `.venv/bin/python bin/kamal-enrich ...` | No | `docs/ble-device-intelligence.md` |
| Map evidence to BSAM coverage | `.venv/bin/python bin/kamal-map-bsam ...` | No | `docs/bsam-mapping.md` |

Run any command with `--help` through the same invocation form before use.

## 3. Dedicated Nordic BLE capture setup

K’amal currently supports Nordic nRF52840/PCA10059 receivers running Nordic nRF Sniffer for Bluetooth LE firmware.

Provision the capture tooling with:

```bash
cd ~/kamal
bash setup/setup-ble-sniffer.sh
```

See `docs/ble-sniffer.md` for USB identities, firmware mode, persistent aliases, and troubleshooting.

The three-channel advertising plane expects:

```text
/dev/kamal-ble-sniffer-37
/dev/kamal-ble-sniffer-38
/dev/kamal-ble-sniffer-39
```

The installer can assign exactly three connected sniffers automatically. If more than three sniffers are attached, explicitly set the three serial-number override variables documented in `docs/ble-sniffer.md`; K’amal fails closed rather than silently changing the advertising-plane membership.

## 4. Passive capture workflows

### Single Nordic receiver

List capture capability:

```bash
bin/kamal-capture list
```

Bounded capture:

```bash
bin/kamal-capture ble \
  --duration 60 \
  --output /tmp/kamal-example.pcap
```

Follow one advertiser:

```bash
bin/kamal-capture ble \
  --address AA:BB:CC:DD:EE:FF \
  --duration 60 \
  --output /tmp/kamal-target.pcap
```

Advertising-only capture:

```bash
bin/kamal-capture ble \
  --advertising-only \
  --duration 60 \
  --output /tmp/kamal-advertising.pcap
```

### Fixed three-channel advertising plane

```bash
bin/kamal-capture ble-adv3 \
  --address AA:BB:CC:DD:EE:FF \
  --duration 60 \
  --output-dir /tmp/kamal-adv3-example
```

The output directory contains three separate PCAPs, per-radio logs, follow-request markers, and `manifest.json`. K’amal intentionally keeps the PCAPs separate. A follow-request marker proves that the host sent the follow request; it does **not** prove RF acquisition of the target.

Current supported operator behavior pins the primary advertising channels 37, 38, and 39. Separately, the dedicated receive-only DATA firmware prototype has been hardware-validated for manual fixed LE1M reception on representative CH0, CH18, and CH36 using fresh provenance-bound access-address/CRCInit inputs and matching CRC-valid packets. That prototype HIL does **not** make `ble-adv3` a data-channel capture mode and is not yet exposed as a supported operator workflow; the test DATA receiver was restored to stock Nordic firmware after validation.

### Inventory an existing PCAP

```bash
.venv/bin/python bin/kamal-scan ble \
  --input /tmp/kamal-advertising.pcap \
  --json /tmp/kamal-inventory.json
```

## 5. GATT metadata and bounded active operations

### Inspect one explicitly selected target

```bash
.venv/bin/python bin/kamal-gatt inspect \
  AA:BB:CC:DD:EE:FF \
  --adapter hci0 \
  --timeout 10 \
  --json /tmp/kamal-gatt.json
```

This performs active connection/GATT metadata enumeration. It does not explicitly read or write characteristic values, subscribe to notifications, or request pairing.

### Authorization-gated metadata survey

The full survey contract and authorization shape are documented in `docs/active-gatt-contracts.md`.

Example execution form:

```bash
.venv/bin/python bin/kamal-gatt survey \
  --allowlist authorized-targets.json \
  --execute \
  --authorization authorization.json \
  --safety-state-dir ~/.local/state/kamal/gatt-safety-v012 \
  --discover-seconds 30 \
  --max-devices 45 \
  --timeout 5 \
  --output-dir /path/to/new/evidence-dir
```

Use a new output directory. Active survey execution validates authorization before RF and revalidates scope during execution.

### Typed operation plan and executor

Planning performs no RF:

```bash
.venv/bin/python bin/kamal-plan-gatt \
  --authorization authorization.json \
  --operations operations.json \
  --json plan.json
```

Execution performs authorized RF operations and requires the persistent interlock:

```bash
.venv/bin/python bin/kamal-execute-gatt \
  --plan plan.json \
  --authorization authorization.json \
  --output-dir gatt-run \
  --safety-state-dir ~/.local/state/kamal/gatt-safety-v012 \
  --adapter hci0
```

K’amal stops a plan on the first operation failure or unexpected connection loss. It does not automatically reconnect and continue.

If cleanup state is uncertain, later active BLE work is blocked until the operator verifies recovery and records it using `kamal-resolve-gatt-unsafe`. See `docs/gatt-safety-interlock.md`.

## 6. Security-state, key analysis, and pairing

### Inspect existing BlueZ state

This reads existing host state and performs no Bluetooth RF:

```bash
sudo .venv/bin/python bin/kamal-inspect-bluez-state \
  --adapter AA:BB:CC:DD:EE:01 \
  --target AA:BB:CC:DD:EE:FF \
  --engagement-id engagement:example \
  --authorization-ref auth:example \
  --json /tmp/bluez-security-state.json
```

### Analyze recognized existing key material

```bash
sudo .venv/bin/python bin/kamal-analyze-bluez-keys \
  --adapter AA:BB:CC:DD:EE:01 \
  --target AA:BB:CC:DD:EE:FF \
  --engagement-id engagement:example \
  --authorization-ref auth:example \
  --pairing-session-ref pairing:example \
  --json /tmp/bluez-key-analysis.json
```

The analyzer reads supported raw values transiently in memory and emits redacted/fingerprinted evidence rather than raw key bytes.

### Plan and execute pairing

Planning is non-RF:

```bash
.venv/bin/python bin/kamal-plan-pairing \
  --authorization pairing-authorization.json \
  --request pairing-request.json \
  --json pairing-plan.json
```

Execution is active and state-changing:

```bash
.venv/bin/python bin/kamal-execute-pairing \
  --plan pairing-plan.json \
  --authorization pairing-authorization.json \
  --output-dir pairing-run \
  --safety-state-dir ~/.local/state/kamal/gatt-safety-v012 \
  --adapter hci0
```

The current BlueZ backend calls `Device1.Pair` directly, does not set `Trusted`, and requires explicit bond authorization because BlueZ does not provide K’amal a reliable pair-only/nonpersistent control through this path. Bond removal/reset is not implied by pairing authorization.

A successful D-Bus call alone is not sufficient evidence of the negotiated SMP association model. Use synchronized OTA capture when protocol-level pairing facts are required.

## 7. Offline analysis pipeline

Build an assessment from one or more existing K’amal reports:

```bash
.venv/bin/python bin/kamal-assess \
  --assessment-id assessment:example \
  --input gatt-report.json \
  --json assessment.json
```

Correlate multiple assessments:

```bash
.venv/bin/python bin/kamal-correlate \
  --input assessment-a.json \
  --input assessment-b.json \
  --json correlation.json
```

Optionally enrich from a local provenance-bearing catalog:

```bash
.venv/bin/python bin/kamal-enrich \
  --assessment assessment.json \
  --catalog ble-intelligence.json \
  --json enrichment.json
```

Create a conservative BSAM evidence-coverage mapping:

```bash
.venv/bin/python bin/kamal-map-bsam \
  --assessment assessment.json \
  --enrichment enrichment.json \
  --json bsam-mapping.json
```

These analysis commands do not initiate BLE RF operations.

## 8. Evidence and output expectations

K’amal generally uses create-only outputs. Prefer a new path for every run rather than expecting an existing artifact to be overwritten.

For HIL or diagnostic work, preserve the whole evidence set together: authorization/request/plan inputs, run-start/final artifacts, per-operation records, manifests, PCAPs, safety-state evidence, tool versions, and checksums.

Raw Bluetooth keys and client-sensitive captures are not ordinary console/report content. Keep them out of Git and out of general-purpose development prompts.

## 9. Current limitations that operators must know

- Python command entrypoints are not yet packaged to guarantee the project venv automatically; use `.venv/bin/python` as shown above.
- The three-channel fixed observation plane covers primary advertising channels 37–39. A separate custom receive-only firmware path has representative CH0/CH18/CH36 hardware evidence, but arbitrary fixed data-channel reception is not yet a supported operator-facing capability: there is no stable CLI/job contract for it, the DATA dongle is normally restored to stock firmware, and scheduler-grade anchor/event-counter/CSA handling remains incomplete.
- The explicit pairing executor is implemented, but the current controlled `go dawgs` HIL attempt returned `AuthenticationFailed`; do not interpret implementation as proof that every target can be paired.
- Key-aware OTA decryption/correlation, live IRK/RPA execution, bond reset/removal, and a successful positive-write HIL remain incomplete.
- The operator control UI is a future goal. The CLI/contracts remain the current authoritative execution surface.

## 10. Related documentation

- `docs/master-development-roadmap.md` — current implementation roadmap and verified/planned boundary.
- `docs/ble-sniffer.md` — Nordic hardware, provisioning, capture modes and troubleshooting.
- `docs/active-gatt-contracts.md` — authorization and planning contracts.
- `docs/gatt-executor.md` — bounded active GATT executor.
- `docs/gatt-result-semantics.md` — transport/protocol/application/security-effect distinction.
- `docs/gatt-safety-interlock.md` — persistent active-BLE safety state and recovery.
- `docs/bluetooth-security-evidence.md` — security-state/key-evidence contracts.
- `docs/pairing-executor.md` — explicit pairing/bond workflow.
- `docs/assessment.md` — offline assessment.
- `docs/ble-correlation.md` — cross-run correlation.
- `docs/ble-device-intelligence.md` — local intelligence enrichment.
- `docs/bsam-mapping.md` — conservative BSAM evidence coverage.
- `docs/v0.12-acceptance.md` — synthetic integration gate.

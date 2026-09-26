# ADR-004: Bluetooth security-state, pairing/bonding, and key-aware evidence contracts

**Status:** Accepted for v0.12 contract design. Pairing execution, key extraction/copying, capture decryption, and RPA-resolution execution are deferred to later BLE-SEC work packages.

**Implementation status:** BLE-SEC-02 implements `inspect_security_state` for one exact target using BlueZ's existing filesystem cache/persistent store. The reader is local and read-only, redacts every `Key=` value before structured parsing, and emits no `bluetooth_key_evidence` record yet. Live D-Bus/MGMT observation, pairing/bond execution, protected raw-key collection, RPA resolution, and capture decryption remain later work packages.

## Context

K'amal's v0.12 active GATT path already separates authorization, bounded RF execution, transport/protocol outcome, application effect, security effect, and persistent safety state. Hardware validation has now exposed the next security boundary: an authorized read may succeed while an exact-value write is rejected with ATT `Insufficient Authorization`, and the host may have no persistent bond state for the target.

For Bluetooth security research, pairing state and cryptographic material are assessment evidence, not merely implementation details. LTK, IRK, CSRK, and BR/EDR link-key material can inform encryption analysis, privacy-address resolution, signed-data review, key-reuse analysis, and authorized packet decryption. At the same time, raw keys and derived cleartext are highly sensitive client evidence and must not leak into ordinary reports, logs, fixtures, Git, or AI/SIEM paths.

K'amal also needs to distinguish a host-stack outcome from a directly observed OTA protocol event. A Bleak/BlueZ exception that corresponds to an ATT error does not prove the ATT PDU was captured. Conversely, a decrypted ATT frame proves a packet-level observation but does not automatically prove application state change or security impact.

## Decision

K'amal will introduce pure, non-executing Bluetooth security-evidence contracts before implementing any new pairing or key-aware RF workflow.

### 1. Explicit security operation taxonomy

The contract layer recognizes the following proposed operation classes:

- `inspect_security_state`
- `pair_target`
- `establish_bond`
- `remove_bond`
- `reset_pairing_state`
- `capture_pairing_ota`
- `analyze_key_material`
- `decrypt_capture`
- `resolve_rpa`

The taxonomy records whether an operation is local, passive-RF, or active-RF; whether it can transmit; whether it mutates security state; and whether it requires secret access.

**This taxonomy does not grant authorization or execution capability.** In particular, `pair_target` and the other new classes are deliberately not added to the existing GATT planner/executor in BLE-SEC-01. The current active contract therefore continues to reject them fail-closed.

### 2. Security evidence records

BLE-SEC-01 defines strict validators for these record types:

- `bluetooth_pairing_session`
- `bluetooth_security_state`
- `bluetooth_key_evidence`
- `secret_evidence_artifact`
- `bluetooth_decryption_derivation`
- `bluetooth_packet_observation`

The records preserve engagement/authorization references, target selectors, timestamps, source evidence, limitations, and cryptographic hashes where applicable.

### 3. Secret material is separated from analytical evidence

`bluetooth_key_evidence` may contain key class, byte length, SHA-256 fingerprint, authentication/Secure-Connections metadata, encryption size when applicable, debug-key state when evidenced, source references, and a pointer to a protected secret artifact.

It must not contain the raw key. `raw_key_embedded` is required to be false. Known raw-secret field names are rejected recursively.

`secret_evidence_artifact` describes a protected artifact that contains secret material. It is always `highly_restricted`, declares the secret classes present, records a content hash/size/storage state, and states that raw secret bytes are not embedded in the metadata record itself.

The initial storage-state vocabulary is:

- `encrypted_at_rest`
- `os_protected_source`
- `transient_memory_only`

This supports the current root-controlled BlueZ source as well as the later encrypted NVMe evidence store without pretending that root-only permissions are encryption.

### 4. Unknown security state is not false security state

Pairing/security records use nullable booleans for observations that may be unavailable from a particular source. `null` means not established by that evidence source; `false` is an observed negative state. This prevents a disconnected D-Bus view or absent field from becoming a claim that encryption, pairing, or bonding is disabled.

### 5. Pairing and bonding are state-changing operations

Future pairing execution must be explicit and authorization-gated. Bond persistence is represented separately from transient pairing state. Bond removal/reset is a separate state-mutating class and cannot be implied by successful pairing, test cleanup, or engagement teardown.

A `bluetooth_pairing_session` records requested pair/bond behavior, before/after state observations, security metadata when supported, evidence references, and limitations. A completed/failed/cancelled session requires a completion timestamp.

### 6. Pairing/security semantics remain evidence-limited

Security metadata such as authenticated state, Secure Connections, association model, and encryption size is recorded only when the source supports it. The contract does not infer a vulnerability from Just Works, unauthenticated keys, key possession, successful decryption, or a writable GATT property.

The key-analysis layer may later detect known/pathological conditions and cross-device fingerprint reuse, but a single visually simple 128-bit value is not sufficient evidence for a randomness/entropy defect.

### 7. Original captures remain immutable

Key-assisted decoding is represented by `bluetooth_decryption_derivation`. It binds:

- the SHA-256 of the immutable source capture;
- one or more key-evidence references and fingerprints;
- decoder name/version;
- attempted/succeeded state and decrypted-frame count;
- derived packet-observation references; and
- an explicit offline/no-RF/no-network execution record.

The derivation never replaces or rewrites the original capture as if it had been collected in cleartext.

### 8. Direct packet observation is a separate evidence layer

A `bluetooth_packet_observation` is valid only for a frame directly present in capture evidence. If the observation required decryption, it must reference its decryption derivation.

Later correlation may use such an artifact to justify `att_pdu_directly_observed=true` in a separate result/review artifact. The host API must never set that flag merely because its error maps to an ATT status code.

Direct observation of an ATT/SMP/Link Layer PDU still does not establish application acknowledgment, state change, or validated security effect.

### 9. IRK/RPA resolution remains cryptographic evidence

BLE-SEC-01 reserves `resolve_rpa` as a local secret-using operation class. Later implementation must emit a validated identity relationship only when the BLE RPA resolution algorithm succeeds against an authorized IRK. Non-match is not proof that two observations belong to different physical devices.

## Consequences

K'amal gains a stable vocabulary and strict data boundary before touching pairing or raw key material. Future BLE-SEC work can implement BlueZ/MGMT collection, pairing, nRF capture, decryption, and RPA resolution without weakening the existing GATT planner or conflating evidence layers.

The immediate cost is additional artifact types and secret-handling policy. Implementations must maintain two evidence paths: redacted analytical records suitable for ordinary reports and highly restricted secret-bearing artifacts suitable only for explicitly authorized local analysis.

## Deferred implementation

BLE-SEC-01 does **not**:

- call `BleakClient(..., pair=True)`;
- invoke BlueZ pairing methods;
- create/remove a bond;
- read/copy `/var/lib/bluetooth` key values;
- subscribe to BlueZ MGMT key events;
- start the nRF sniffer;
- inject keys into Wireshark/TShark/nrfutil;
- decrypt a capture;
- resolve an RPA; or
- modify the persistent GATT safety interlock.

Those capabilities require later work packages and hardware acceptance.

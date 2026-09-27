# ADR-004: Bluetooth security-state, pairing/bonding, and key-aware evidence contracts

**Status:** Accepted for v0.12 contract design and incremental implementation. Explicit pairing/bond execution is implemented in BLE-SEC-04; raw-key export/copying into K'amal-owned storage, capture decryption, RPA-resolution execution, and bond removal/reset remain deferred.

**Implementation status:** BLE-SEC-02 implements `inspect_security_state` for one exact target using BlueZ's existing filesystem cache/persistent store. BLE-SEC-03 implements local analysis of recognized 128-bit key material in an existing BlueZ persistent `info` record: raw values are read transiently, fingerprinted and analyzed in memory, but are not printed or copied into a second plaintext artifact. BLE-SEC-04 adds a separate exact-target pairing authorization/plan plus a bounded BlueZ executor using direct `Device1.Pair`; it records `Paired`, `Bonded`, and `Trusted` independently, never sets `Trusted`, and reuses the persistent active-BLE safety lease. Encrypted K'amal-owned key export, pairing OTA interpretation, RPA resolution, capture decryption, and bond removal/reset remain later work packages.

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

Pairing execution is explicit and authorization-gated. BLE-SEC-04 uses a dedicated `bluetooth_pairing_authorization` rather than extending ordinary GATT authorization. The authorization is exact-target, permits only one attempt in v0.12, bounds discovery/pair/disconnect timeouts, requires post-run disconnect, and separately gates `pair_target` and `establish_bond`.

The BlueZ backend calls `org.bluez.Device1.Pair` directly instead of enabling Bleak's pairing convenience option, and it never sets `Trusted`. `Paired`, `Bonded`, and `Trusted` are observed independently. Because the BlueZ Pair API does not let K'amal guarantee a non-persistent pair-only outcome, the v0.12 BlueZ backend refuses a pair-only plan before RF; live BlueZ execution requires an explicitly authorized bond request. The pure contract retains pair-only semantics for a future backend that can guarantee them.

Bond removal/reset remains a separate state-mutating class and cannot be implied by successful pairing, test cleanup, or engagement teardown.

A `bluetooth_pairing_session` records requested pair/bond behavior, before/after state observations, security metadata when supported, evidence references, and limitations. A completed/failed/cancelled session requires a completion timestamp. BLE-SEC-04 leaves association model, Secure Connections, authentication, encryption size, and current link encryption unknown unless separate evidence establishes them.

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

K'amal gains a stable vocabulary and strict data boundary around security-state inspection, protected-key analysis, and pairing state mutation. BLE-SEC-03 may transiently read raw key values from an explicitly selected, operating-system-protected BlueZ source solely to derive redacted evidence; it does not create another plaintext key store. BLE-SEC-04 adds pairing without widening GATT authorization: pairing has its own contract/executor and shares only the persistent active-BLE safety lease. Future BLE-SEC work can add pairing OTA capture, decryption, and RPA resolution without conflating host-state and packet-evidence layers.

The immediate cost is additional artifact types and secret-handling policy. Implementations must maintain two evidence paths: redacted analytical records suitable for ordinary reports and highly restricted secret-bearing artifacts suitable only for explicitly authorized local analysis.

## Deferred implementation after BLE-SEC-04

The following capabilities remain deferred:

- call `BleakClient(..., pair=True)` as an implicit side effect of GATT work;
- remove/reset a bond;
- copy/export `/var/lib/bluetooth` key values into K'amal-owned plaintext or encrypted secret storage;
- subscribe to BlueZ MGMT key events;
- interpret an OTA pairing capture as pairing/security evidence;
- inject keys into Wireshark/TShark/nrfutil;
- decrypt a capture; or
- resolve an RPA.

The pairing executor is implemented, but live pairing remains subject to hardware acceptance with synchronized OTA capture. Those remaining capabilities require later work packages.

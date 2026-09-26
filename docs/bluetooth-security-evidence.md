# Bluetooth security-state and key-aware evidence contracts

K'amal v0.12 defines a non-executing contract layer for future Bluetooth pairing, bonding, key analysis, privacy-address resolution, and key-assisted packet correlation.

The implementation is in `kamal.bluetooth_security`. It performs validation only and has no Bluetooth/RF/network imports.

See [ADR-004](adr-004-bluetooth-security-state-key-evidence.md) for the design decision and boundaries.

## Operation taxonomy

| Operation | Domain | Transmit capable | Mutates security state | Secret access |
|---|---|---:|---:|---:|
| `inspect_security_state` | local | no | no | no |
| `pair_target` | active RF | yes | yes | no |
| `establish_bond` | active RF | yes | yes | no |
| `remove_bond` | local | no | yes | yes |
| `reset_pairing_state` | local | no | yes | yes |
| `capture_pairing_ota` | passive RF | no | no | no |
| `analyze_key_material` | local | no | no | yes |
| `decrypt_capture` | local | no | no | yes |
| `resolve_rpa` | local | no | no | yes |

These names are **not** executable operations yet. The existing `gatt_operation_request` deliberately continues to reject them.

## Pairing session

A `bluetooth_pairing_session` captures requested pair/bond behavior and evidence-limited before/after observations.

```json
{
  "schema_version": "0.12.0",
  "record_type": "bluetooth_pairing_session",
  "pairing_session_id": "pairing:example",
  "engagement_id": "engagement:example",
  "authorization_ref": "auth:example",
  "target": {
    "address": "AA:BB:CC:DD:EE:FF",
    "address_type": "public"
  },
  "started_at_utc": "2026-09-25T05:00:00Z",
  "completed_at_utc": "2026-09-25T05:00:05Z",
  "status": "completed",
  "requested": {
    "pair": true,
    "bond": true
  },
  "observed": {
    "paired_before": false,
    "bonded_before": false,
    "trusted_before": false,
    "paired_after": true,
    "bonded_after": true,
    "trusted_after": false,
    "connected_after": true,
    "encrypted_after": true
  },
  "security": {
    "authenticated": false,
    "secure_connections": true,
    "encryption_size": 16,
    "association_model": "just_works"
  },
  "evidence": [
    "artifact:bluez-mgmt",
    "artifact:pairing-pcap"
  ],
  "limitations": [
    "application authorization not assessed"
  ]
}
```

A nullable observation is intentionally different from `false`: `null` means the cited source did not establish that fact.

## Bluetooth security state

`bluetooth_security_state` is a point-in-time observation from one explicit source such as BlueZ D-Bus, BlueZ MGMT, the persistent BlueZ store, or packet evidence. Cached device visibility, persisted bond state, current connection state, and encryption state must not be treated as synonyms.

The state record may reference zero or more separate `bluetooth_key_evidence` artifacts.

## Key evidence

Ordinary key evidence contains metadata and a fingerprint, never the raw key:

```json
{
  "schema_version": "0.12.0",
  "record_type": "bluetooth_key_evidence",
  "key_evidence_id": "key-evidence:ltk-example",
  "engagement_id": "engagement:example",
  "authorization_ref": "auth:example",
  "target": {
    "address": "AA:BB:CC:DD:EE:FF",
    "address_type": "public"
  },
  "pairing_session_ref": "pairing:example",
  "key_class": "ltk",
  "key_bytes": 16,
  "key_fingerprint_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "authenticated": false,
  "secure_connections": true,
  "encryption_size": 16,
  "debug_key": false,
  "source": {
    "kind": "bluez_mgmt",
    "artifact_ref": "artifact:mgmt-key-event"
  },
  "secret_artifact_ref": "secret-artifact:bond-example",
  "raw_key_embedded": false,
  "limitations": []
}
```

Supported analytical key classes are `ltk`, `irk`, `csrk`, and `link_key`. `encryption_size` is only valid for LTK evidence in this contract.

Raw key material belongs in a separately protected `secret_evidence_artifact`, classified `highly_restricted`. Its metadata records content hash, size, secret classes, and storage state without embedding the secret itself.

## Key analysis boundaries

Future local analysis may use authorized raw key artifacts to identify:

- key class/type and length;
- authenticated/unauthenticated state when evidenced;
- Secure Connections vs legacy state when evidenced;
- negotiated encryption size;
- known debug/default/pathological keys;
- all-zero, all-`ff`, and simple repeated-pattern conditions;
- duplicate fingerprints across independently paired devices within the approved corpus;
- IRK reuse;
- signing/counter anomalies where CSRK evidence supports them; and
- persistence/security-state inconsistencies.

Do not claim defective entropy or randomness from one isolated key merely because it appears visually simple. Such a conclusion requires a suitable corpus or a known deterministic/default construction.

## Decryption derivations

`bluetooth_decryption_derivation` describes a local/offline derived interpretation of an immutable capture. It binds the source capture hash, key-evidence references/fingerprints, decoder/version, result, and derived packet-observation references.

It explicitly records:

```json
"execution": {
  "status": "offline_derivation",
  "rf_performed": false,
  "network_performed": false
}
```

The raw capture remains the source artifact and must not be overwritten by a decrypted/exported representation.

## Packet observations

A `bluetooth_packet_observation` identifies a frame actually present in capture evidence. `directly_observed` must be true. A decrypted observation must carry a `decryption_derivation_ref`.

Example:

```json
{
  "schema_version": "0.12.0",
  "record_type": "bluetooth_packet_observation",
  "packet_observation_id": "packet:1844",
  "source_capture_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "frame_number": 1844,
  "protocol": "att",
  "direction": "responder_to_initiator",
  "decrypted": true,
  "decryption_derivation_ref": "derivation:example",
  "directly_observed": true,
  "opcode": "Error Response",
  "error_code": "0x08",
  "summary": "ATT Error Response: Insufficient Authorization"
}
```

This artifact can later support a result review that says an ATT PDU was directly observed. It still does not establish application state change or a security vulnerability.

## Secret-output rules

Raw Bluetooth keys or equivalent secret material must not be placed in:

- ordinary analytical JSON;
- console summaries;
- Git or source fixtures;
- CI output;
- exception strings;
- dashboard/SIEM exports;
- AI prompts/responses; or
- packet-observation summaries.

Normal evidence may carry a SHA-256 key fingerprint and a protected artifact reference. Access to the secret artifact itself is a separate audited action.

# GATT result and effect semantics

K'amal separates execution success from application and security conclusions. A
successful GATT call is not, by itself, evidence that the target application
accepted a command, changed state, or experienced a security-relevant effect.

Every `gatt_operation_result` therefore carries `effect_semantics` with five
layers:

1. **Transport** — whether the Bleak client API completed without an exception.
2. **Protocol** — the narrow GATT outcome visible through that API, such as a
   returned value, a completed write request, a submitted write command, or a
   received notification. K'amal does not claim direct ATT-PDU observation from
   Bleak's high-level API.
3. **Application acknowledgment** — whether application-specific behavior
   explicitly acknowledged the operation.
4. **State change** — whether an independently observed application/device state
   change was established.
5. **Security effect** — whether a security-relevant effect is a candidate,
   validated, or refuted conclusion.

The executor can populate only the first two layers. It always leaves the last
three as `not_assessed`.

## Write semantics

For `write_mode: request`, successful return from `BleakClient.write_gatt_char`
with `response=True` is recorded as `write_request_completed`. This does not
claim that K'amal directly captured an ATT Write Response PDU, and it does not
claim application acknowledgment or state change.

For `write_mode: command`, successful API return is recorded as
`write_command_submitted`. No response is expected, so API success is even less
informative about remote application behavior.

The compatibility fields `transport_success` and `application_effect` remain in
executor artifacts. `transport_success` mirrors the transport semantic state;
`application_effect` remains `not_assessed`. New consumers should use
`effect_semantics`.

## Offline analyst review

`kamal-review-gatt-result` creates a separate immutable review artifact. It
never modifies the executor result. The review is bound to the exact operation
result bytes by SHA-256 and can explicitly assess any of these reviewable stages:

- `application_acknowledgment`: `observed` or `not_observed`
- `state_change`: `observed` or `not_observed`
- `security_effect`: `candidate`, `validated`, or `refuted`

Every reviewed stage requires a non-empty basis and at least one textual evidence
reference. The review also records the reviewer, review basis, exact review-input
hash, and review timestamp. A `validated` security effect is therefore an
explicit analyst conclusion, never a promotion from transport success.

Example review request:

```json
{
  "schema_version": "0.12.0",
  "record_type": "gatt_effect_review_request",
  "review_id": "review-001",
  "reviewer": "analyst-1",
  "basis": "Authorized lab validation against an owned test device",
  "stages": {
    "state_change": {
      "state": "observed",
      "basis": "Independent device UI changed after the authorized write",
      "evidence": ["video:evidence/device-ui-after-write.mp4"]
    },
    "security_effect": {
      "state": "candidate",
      "basis": "Observed state change may bypass the expected application path",
      "evidence": ["note:review-001"]
    }
  }
}
```

Create the offline review with:

```bash
bin/kamal-review-gatt-result \
  --operation operation-001.json \
  --review review-request.json \
  --json operation-001-review.json
```

No RF or network activity occurs during review construction.

## Current integration boundary

This increment defines executor semantics and immutable offline review artifacts. The
assessment and BSAM mapper do not ingest effect-review artifacts yet; that linkage is
left explicit for a later integration step so no result is silently promoted into a
finding or BSAM pass/fail conclusion.

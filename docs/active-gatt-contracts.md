# Active BLE GATT authorization and operation contracts

K'amal v0.12 separates **permission to perform an active operation** from the
code that will eventually execute it. Increment 8 adds validation and plan
construction only. `kamal-plan-gatt` does not import a BLE radio library,
connect to a device, read an attribute, write an attribute, or subscribe to a
notification.

## Authorization scope

An authorization record is an explicit `authorization_scope` with:

- engagement, owner, operator, and location;
- issue, start, and expiration timestamps in UTC;
- an exact BLE target allowlist using address plus address type;
- an explicit list of allowed operation classes;
- hard bounds for operation count, payload size, timeout, and subscription
  duration;
- separate opt-in flags for writes and write-without-response; and
- approval metadata identifying the approver and authorization basis.

The BLE address is a **scope selector**, not a stable device identity. Address
rotation or reuse can invalidate the practical meaning of a scope record, so an
operator must confirm the target at execution time in the later executor layer.

The current operation taxonomy is deliberately small:

- `read_characteristic`
- `read_descriptor`
- `write_characteristic`
- `subscribe_notifications`

Unknown operation classes, including fuzzing, replay, pairing, injection, or
arbitrary raw ATT operations, fail closed. Writes require both the explicit
`write_characteristic` operation class and `allow_writes=true`.
Write-without-response additionally requires
`allow_write_without_response=true`.

## Typed operation requests

Each operation names one authorized BLE target and one attribute selector. A
selector is either an ATT handle or a UUID path. Characteristic UUID paths
require service plus characteristic UUIDs. Descriptor reads additionally
require a descriptor UUID.

Write payloads are hex-encoded whole bytes and are bounded by both the
per-authorization limit and K'amal's hard 512-byte ceiling. Timeouts are bounded
at 30 seconds and notification subscriptions at 300 seconds even when an
external authorization document attempts to permit more. An authorization can
always choose stricter limits.

Notification plans carry `cleanup.unsubscribe_required=true`; this is a
contract for the future executor, not evidence that cleanup occurred.

## Plan artifacts

`kamal-plan-gatt` takes two immutable inputs:

```text
bin/kamal-plan-gatt \
  --authorization authorization.json \
  --operations operations.json \
  --json plan.json
```

The plan records the SHA-256 of the exact authorization bytes and operation-request
bytes, the authorization ID and engagement, the normalized operations, and the
UTC time at which the authorization window was evaluated. Operation order is
preserved because sequencing may be safety-relevant to a later executor. Output
uses K'amal's atomic no-overwrite JSON persistence helper.

Every generated plan currently contains:

```json
"execution": {
  "status": "contract_only",
  "rf_performed": false,
  "executor_required": true
}
```

A valid plan therefore means **the requested operations fit the structured
scope at plan-construction time**. It does not mean RF was attempted, an ATT
request succeeded, application state changed, or a security impact was
validated.

## Failure semantics

Plan construction fails closed when authorization is absent, not yet valid,
expired, ambiguous, target-mismatched, over-bounded, or missing an explicit
operation permission. Unknown fields are rejected rather than ignored so a
misspelled safety control cannot silently disappear.

This increment treats approval metadata as an auditable human authorization
record. It does **not** claim cryptographic signature verification. A future
policy/signature envelope can bind these same normalized contracts without
changing the executor's operation taxonomy.

## Separation from assessment rules

Assessment rules still cannot initiate RF operations. A finding or heuristic
may eventually propose a reviewed operation request, but it cannot create
permission. Authorization and the bounded operation request must independently
validate before a later executor is allowed to act.

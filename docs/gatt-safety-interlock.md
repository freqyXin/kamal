# GATT execution safety interlock

K'amal active GATT execution uses a persistent safety-state directory that is
separate from per-run evidence.  Every `kamal-execute-gatt` invocation and every
`kamal-gatt survey --execute` run requires `--safety-state-dir`.  The directory
provides two fail-closed controls:

- `active-run.json` is a single-executor lease created before RF work.  A second
  executor cannot start while that file exists.  If a process crashes or is
  killed before it can confirm cleanup, the lease remains and blocks later
  active execution.
- `unsafe-stop.json` is a recovery-required latch.  It is created when K'amal
  cannot confirm required cleanup, including an unconfirmed disconnect or
  notification unsubscribe failure.  The active-run lease is removed only
  after the unsafe latch has been published.

A normal run with confirmed cleanup removes the active-run lease durably.  An
ordinary operation failure also clears the lease if the BLE session is confirmed
disconnected; failed operations are still preserved as immutable evidence and
remaining plan operations are not attempted.  Active survey execution holds one
lease across discovery and the sequential device queue.  It releases the lease
only after every attempted device has confirmed-safe cleanup; an unsafe survey
disconnect or unexpected abort with unconfirmed cleanup publishes the same
recovery-required latch used by the bounded executor.

## Connection loss

Unexpected connection loss always stops the current plan.  K'amal never silently
reconnects and continues with later operations.  If the client API reports the
link is already disconnected, the stop does not require recovery because no
active session remains.  If disconnect state is uncertain, the unsafe latch is
set and further active execution is blocked.

## Explicit recovery

K'amal does not claim it can determine physical recovery from software alone.
The operator must review the target and confirm that no active BLE session
remains before clearing an unsafe or orphaned state.

`kamal-resolve-gatt-unsafe` consumes a JSON request with this shape:

```json
{
  "schema_version": "0.12.0",
  "record_type": "gatt_safety_recovery_request",
  "recovery_id": "recovery-2026-09-25-001",
  "operator": "analyst-name",
  "confirmed_at_utc": "2026-09-25T20:00:00Z",
  "basis": "Verified target disconnected and reviewed target state.",
  "confirmations": {
    "no_active_ble_session": true,
    "target_state_reviewed": true
  },
  "evidence": [
    "lab-note:recovery-2026-09-25-001"
  ]
}
```

Both confirmations and at least one evidence reference are mandatory.  The tool
writes an immutable recovery artifact under `STATE_DIR/resolutions/`, binds it
to the exact blocking state and exact recovery-request bytes with SHA-256, then
clears the latch.  The recovery artifact explicitly states that K'amal did not
independently verify the operator's physical recovery claims.

Deleting the safety-state files by hand bypasses this workflow and loses the
recovery audit trail.

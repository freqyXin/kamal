"""Bounded executor for already-authorized BLE GATT operation plans."""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from kamal.active_contracts import (
    ACTIVE_CONTRACT_VERSION,
    ContractValidationError,
    SUPPORTED_OPERATIONS,
    load_json_source,
    validate_authorization_scope,
)
from kamal.evidence_contracts import atomic_create_json
from kamal.result_semantics import (
    RESULT_SEMANTICS_VERSION,
    build_initial_effect_semantics,
    mark_executor_failure,
    mark_executor_success,
)

EXECUTOR_VERSION = "0.12.0"
MAX_NOTIFICATION_EVENTS = 256
MAX_NOTIFICATION_BYTES = 65536

class ExecutionError(RuntimeError): pass
class UnsafeStopError(ExecutionError): pass

def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _target_key(value):
    return value["address"].upper(), value["address_type"]

def _verify_plan(plan, authorization, authorization_sha256):
    if not isinstance(plan, dict) or plan.get("schema_version") != ACTIVE_CONTRACT_VERSION or plan.get("record_type") != "gatt_operation_plan":
        raise ExecutionError("invalid GATT operation plan")
    execution = plan.get("execution")
    if execution != {"status":"contract_only","rf_performed":False,"executor_required":True}:
        raise ExecutionError("plan is not an unexecuted contract-only plan")
    prov = plan.get("authorization_provenance") or {}
    if prov.get("sha256") != authorization_sha256.lower():
        raise ExecutionError("authorization bytes do not match plan provenance")
    normalized = validate_authorization_scope(authorization)
    if normalized["authorization_id"] != plan.get("authorization_ref"):
        raise ExecutionError("authorization_id does not match plan")
    ops = plan.get("operations")
    if not isinstance(ops, list) or not ops:
        raise ExecutionError("plan operations must be a non-empty array")
    if len(ops) > normalized["constraints"]["max_operations"]:
        raise ExecutionError("plan exceeds current authorization operation limit")
    seen=set()
    allowed_targets={_target_key(t) for t in normalized["targets"]}
    for op in ops:
        if not isinstance(op, dict): raise ExecutionError("invalid plan operation")
        oid=op.get("operation_id")
        if not isinstance(oid,str) or not oid or oid in seen: raise ExecutionError("invalid or duplicate operation_id")
        seen.add(oid)
        typ=op.get("operation_type")
        if typ not in SUPPORTED_OPERATIONS or typ not in normalized["allowed_operations"]: raise ExecutionError("plan contains unauthorized operation class")
        target=op.get("target") or {}
        if _target_key(target) not in allowed_targets: raise ExecutionError("plan target is outside authorization scope")
        timeout=op.get("timeout_seconds")
        if isinstance(timeout,bool) or not isinstance(timeout,int) or not 1 <= timeout <= normalized["constraints"]["max_timeout_seconds"]: raise ExecutionError("operation timeout exceeds authorization")
        if typ == "write_characteristic":
            if not normalized["constraints"]["allow_writes"]: raise ExecutionError("writes are not currently authorized")
            payload=op.get("payload_hex")
            if not isinstance(payload,str) or len(payload)%2 or len(payload)//2 > normalized["constraints"]["max_payload_bytes"]: raise ExecutionError("write payload exceeds authorization")
            mode=op.get("write_mode")
            if mode == "command" and not normalized["constraints"]["allow_write_without_response"]: raise ExecutionError("write command is not currently authorized")
        if typ == "subscribe_notifications":
            duration=op.get("duration_seconds")
            if isinstance(duration,bool) or not isinstance(duration,int) or not 1 <= duration <= normalized["constraints"]["max_subscription_seconds"]: raise ExecutionError("subscription duration exceeds authorization")
    return normalized

def _resolve_selector(services, selector, operation_type):
    if "handle" in selector:
        handle=selector["handle"]
        matches=[]
        for service in services:
            for char in service.characteristics:
                if operation_type != "read_descriptor" and char.handle == handle: matches.append(char)
                for desc in char.descriptors:
                    if operation_type == "read_descriptor" and desc.handle == handle: matches.append(desc)
        if len(matches) != 1: raise ExecutionError("selector handle did not resolve uniquely")
        return matches[0]
    su=selector["service_uuid"].lower(); cu=selector["characteristic_uuid"].lower()
    services_match=[s for s in services if s.uuid.lower()==su]
    chars=[c for s in services_match for c in s.characteristics if c.uuid.lower()==cu]
    if operation_type == "read_descriptor":
        du=selector["descriptor_uuid"].lower(); matches=[d for c in chars for d in c.descriptors if d.uuid.lower()==du]
    else: matches=chars
    if len(matches) != 1: raise ExecutionError("UUID selector did not resolve uniquely")
    return matches[0]

class BleakBackend:
    async def discover(self, address, adapter, timeout):
        from bleak import BleakScanner
        devices=await BleakScanner.discover(timeout=timeout, return_adv=True, bluez={"adapter":adapter})
        for key,(device,adv) in devices.items():
            if key.upper()==address.upper(): return device,adv
        return None,None
    def client(self, device, timeout):
        from bleak import BleakClient
        return BleakClient(device, timeout=timeout, pair=False)

async def execute_plan(plan, authorization, *, authorization_sha256, plan_sha256, output_dir, adapter="hci0", backend=None):
    auth=_verify_plan(plan, authorization, authorization_sha256)
    out=Path(output_dir)
    out.mkdir(parents=True, exist_ok=False)
    backend=backend or BleakBackend()
    start={"schema_version":EXECUTOR_VERSION,"record_type":"gatt_execution_start","plan_id":plan["plan_id"],"plan_sha256":plan_sha256,"authorization_sha256":authorization_sha256,"started_at_utc":utc_now(),"adapter":adapter}
    atomic_create_json(out/"run-start.json", start)
    results=[]; current_client=None; current_target=None; unsafe=False

    async def disconnect_current():
        nonlocal current_client,current_target,unsafe
        if current_client is None: return {"attempted":False,"completed":True,"error":None}
        rec={"attempted":True,"completed":False,"error":None}
        try:
            await asyncio.wait_for(current_client.disconnect(), timeout=auth["constraints"]["max_timeout_seconds"])
            rec["completed"]=not current_client.is_connected
            if not rec["completed"]: rec["error"]="disconnect returned while still connected"
        except Exception as exc: rec["error"]=f"{type(exc).__name__}: {exc}"
        if rec["error"] is not None or not rec["completed"]: unsafe=True
        current_client=None; current_target=None
        return rec

    try:
        for index,op in enumerate(plan["operations"],1):
            auth=validate_authorization_scope(authorization)  # fail closed on expiry before every op
            target=_target_key(op["target"])
            if current_target != target:
                if current_client is not None:
                    disc=await disconnect_current()
                    if unsafe: raise UnsafeStopError(f"unsafe disconnect before operation {op['operation_id']}: {disc['error']}")
                auth=validate_authorization_scope(authorization)
                device,_=await asyncio.wait_for(backend.discover(op["target"]["address"], adapter, op["timeout_seconds"]), timeout=op["timeout_seconds"]+1)
                if device is None: raise ExecutionError(f"target not found for operation {op['operation_id']}")
                current_client=backend.client(device, op["timeout_seconds"]); current_target=target
                await asyncio.wait_for(current_client.connect(), timeout=op["timeout_seconds"])
                if not current_client.is_connected: raise ExecutionError("connect returned without connected state")
            auth=validate_authorization_scope(authorization)
            typ=op["operation_type"]
            if typ in {"write_characteristic","subscribe_notifications"}: _verify_plan({**plan,"operations":[op]}, authorization, authorization_sha256)
            selected=_resolve_selector(current_client.services, op["selector"], typ)
            rec={"schema_version":EXECUTOR_VERSION,"record_type":"gatt_operation_result","plan_id":plan["plan_id"],"operation_id":op["operation_id"],"operation_type":typ,"target":op["target"],"started_at_utc":utc_now(),"transport_success":False,"application_effect":"not_assessed","effect_semantics":build_initial_effect_semantics(typ, write_mode=op.get("write_mode")),"error":None}
            try:
                if typ=="read_characteristic":
                    data=bytes(await asyncio.wait_for(current_client.read_gatt_char(selected), timeout=op["timeout_seconds"])); rec["value_hex"]=data.hex(); rec["value_bytes"]=len(data)
                elif typ=="read_descriptor":
                    data=bytes(await asyncio.wait_for(current_client.read_gatt_descriptor(selected.handle), timeout=op["timeout_seconds"])); rec["value_hex"]=data.hex(); rec["value_bytes"]=len(data)
                elif typ=="write_characteristic":
                    payload=bytes.fromhex(op["payload_hex"]); await asyncio.wait_for(current_client.write_gatt_char(selected,payload,response=(op["write_mode"]=="request")), timeout=op["timeout_seconds"]); rec["payload_sha256"]=hashlib.sha256(payload).hexdigest(); rec["payload_bytes"]=len(payload)
                elif typ=="subscribe_notifications":
                    events=[]; total=0; truncated=False
                    def callback(sender,data):
                        nonlocal total,truncated
                        b=bytes(data)
                        if len(events)>=MAX_NOTIFICATION_EVENTS or total+len(b)>MAX_NOTIFICATION_BYTES: truncated=True; return
                        events.append({"received_at_utc":utc_now(),"value_hex":b.hex(),"value_bytes":len(b)}); total+=len(b)
                    await asyncio.wait_for(current_client.start_notify(selected,callback), timeout=op["timeout_seconds"])
                    try: await asyncio.sleep(op["duration_seconds"])
                    finally:
                        try: await asyncio.wait_for(current_client.stop_notify(selected), timeout=op["timeout_seconds"])
                        except Exception as exc: unsafe=True; raise UnsafeStopError(f"notification cleanup failed: {type(exc).__name__}: {exc}") from exc
                    rec["notifications"]=events; rec["notification_count"]=len(events); rec["notification_bytes"]=total; rec["notifications_truncated"]=truncated
                rec["effect_semantics"]=mark_executor_success(rec["effect_semantics"],typ,write_mode=op.get("write_mode"),notification_count=rec.get("notification_count"))
                rec["transport_success"]=True
            except Exception as exc:
                rec["error"]=f"{type(exc).__name__}: {exc}"
                rec["effect_semantics"]=mark_executor_failure(rec["effect_semantics"],rec["error"])
                rec["completed_at_utc"]=utc_now(); atomic_create_json(out/f"operation-{index:03d}.json",rec); results.append(rec)
                if isinstance(exc,UnsafeStopError): raise
                raise ExecutionError(rec["error"]) from exc
            rec["completed_at_utc"]=utc_now(); atomic_create_json(out/f"operation-{index:03d}.json",rec); results.append(rec)
    except Exception as exc:
        error=exc
    else: error=None
    finally:
        disc=await disconnect_current()
        if unsafe and error is None: error=UnsafeStopError(disc.get("error") or "cleanup was not confirmed")
        final={"schema_version":EXECUTOR_VERSION,"record_type":"gatt_execution_summary","plan_id":plan["plan_id"],"completed_at_utc":utc_now(),"planned_operations":len(plan["operations"]),"completed_operations":len(results),"transport_success_count":sum(item["effect_semantics"]["transport"]["state"]=="succeeded" for item in results),"higher_effects_assessed_count":sum(item["effect_semantics"]["application_acknowledgment"]["state"]!="not_assessed" or item["effect_semantics"]["state_change"]["state"]!="not_assessed" or item["effect_semantics"]["security_effect"]["state"]!="not_assessed" for item in results),"result_semantics_version":RESULT_SEMANTICS_VERSION,"rf_performed":True,"unsafe_stop":unsafe,"complete":error is None and len(results)==len(plan["operations"]),"error":None if error is None else f"{type(error).__name__}: {error}","disconnect":disc}
        atomic_create_json(out/"run-final.json",final)
    if error is not None: raise error
    return final

def load_execution_inputs(plan_path, authorization_path):
    plan,plan_sha,path=load_json_source(plan_path); auth,auth_sha,auth_path=load_json_source(authorization_path)
    return plan,plan_sha,path,auth,auth_sha,auth_path

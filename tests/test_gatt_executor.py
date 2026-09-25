import asyncio, hashlib, json, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from kamal.active_contracts import build_gatt_operation_plan
from kamal.gatt_executor import ExecutionError, UnsafeStopError, execute_plan

def auth():
    return {"schema_version":"0.12.0","record_type":"authorization_scope","authorization_id":"auth-1","engagement_id":"eng-1","owner":"Lab","operator":"Tester","location":"Lab","issued_at_utc":"2026-01-01T00:00:00Z","not_before_utc":"2026-01-01T00:00:00Z","expires_at_utc":"2099-01-01T00:00:00Z","targets":[{"protocol":"ble","address":"AA:BB:CC:DD:EE:FF","address_type":"public"}],"allowed_operations":["read_characteristic","read_descriptor","write_characteristic","subscribe_notifications"],"constraints":{"max_operations":8,"max_payload_bytes":32,"max_timeout_seconds":5,"max_subscription_seconds":5,"allow_writes":True,"allow_write_without_response":False},"approval":{"approver":"Owner","approved_at_utc":"2026-01-01T00:00:00Z","basis":"owned lab device"}}
def request(op): return {"schema_version":"0.12.0","record_type":"gatt_operation_request","plan_id":"plan-1","operations":[op]}
def op(kind="read_characteristic"):
    d={"operation_id":"op-1","operation_type":kind,"target":{"address":"AA:BB:CC:DD:EE:FF","address_type":"public"},"selector":{"handle":3},"timeout_seconds":1}
    if kind=="write_characteristic": d.update(payload_hex="0102",write_mode="request")
    if kind=="subscribe_notifications": d.update(duration_seconds=1)
    return d
def plan(kind="read_characteristic"):
    a=auth(); raw=b"auth"; return build_gatt_operation_plan(a,request(op(kind)),authorization_sha256=hashlib.sha256(raw).hexdigest(),request_sha256="1"*64),a,hashlib.sha256(raw).hexdigest()
class FakeChar:
    handle=3; uuid="1234"; descriptors=[]
class FakeService:
    uuid="1800"; characteristics=[FakeChar()]
class FakeClient:
    def __init__(self, *, disconnect_stuck=False, stop_error=False): self.is_connected=False; self.services=[FakeService()]; self.disconnect_stuck=disconnect_stuck; self.stop_error=stop_error; self.writes=[]
    async def connect(self): self.is_connected=True
    async def disconnect(self): self.is_connected=self.disconnect_stuck
    async def read_gatt_char(self,x): return b"abc"
    async def read_gatt_descriptor(self,h): return b"def"
    async def write_gatt_char(self,x,payload,response=True): self.writes.append((bytes(payload),response))
    async def start_notify(self,x,cb): cb(x,b"z")
    async def stop_notify(self,x):
        if self.stop_error: raise RuntimeError("stop failed")
class Backend:
    def __init__(self,client): self.c=client
    async def discover(self,*a,**k): return SimpleNamespace(address="AA:BB:CC:DD:EE:FF"),SimpleNamespace()
    def client(self,*a,**k): return self.c
class ExecTests(unittest.TestCase):
    def run_case(self,kind="read_characteristic",client=None):
        p,a,sha=plan(kind); td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup)
        final=asyncio.run(execute_plan(p,a,authorization_sha256=sha,plan_sha256="2"*64,output_dir=Path(td.name)/"out",backend=Backend(client or FakeClient())))
        return final,Path(td.name)/"out"
    def test_read_persists_incrementally(self):
        final,out=self.run_case(); self.assertTrue(final["complete"]); self.assertTrue((out/"run-start.json").exists()); self.assertTrue((out/"operation-001.json").exists()); self.assertTrue((out/"run-final.json").exists())
        result=json.loads((out/"operation-001.json").read_text())
        self.assertEqual(result["effect_semantics"]["transport"]["state"],"succeeded")
        self.assertEqual(result["effect_semantics"]["protocol"]["state"],"value_received")
        self.assertEqual(result["effect_semantics"]["security_effect"]["state"],"not_assessed")
        self.assertEqual(final["transport_success_count"],1)
        self.assertEqual(final["higher_effects_assessed_count"],0)
    def test_write_executes_bounded_payload(self):
        c=FakeClient(); final,out=self.run_case("write_characteristic",c); self.assertEqual(c.writes,[(b"\x01\x02",True)])
        result=json.loads((out/"operation-001.json").read_text())
        self.assertEqual(result["effect_semantics"]["protocol"]["state"],"write_request_completed")
        self.assertEqual(result["effect_semantics"]["application_acknowledgment"]["state"],"not_assessed")
        self.assertEqual(result["application_effect"],"not_assessed")
    def test_notification_cleanup(self): self.run_case("subscribe_notifications")
    def test_unsafe_disconnect_fails(self):
        p,a,sha=plan(); td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup)
        with self.assertRaises(UnsafeStopError): asyncio.run(execute_plan(p,a,authorization_sha256=sha,plan_sha256="2"*64,output_dir=Path(td.name)/"out",backend=Backend(FakeClient(disconnect_stuck=True))))
    def test_authorization_hash_mismatch_fails_before_output(self):
        p,a,sha=plan(); td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup); out=Path(td.name)/"out"
        with self.assertRaises(ExecutionError): asyncio.run(execute_plan(p,a,authorization_sha256="0"*64,plan_sha256="2"*64,output_dir=out,backend=Backend(FakeClient())))
        self.assertFalse(out.exists())
if __name__=="__main__": unittest.main()

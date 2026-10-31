import asyncio
from copy import deepcopy
import json
import time
from datetime import datetime, timezone
import threading
from unittest.mock import MagicMock, patch
from uuid import uuid4
import pytest
from fastapi import HTTPException
from starlette.responses import JSONResponse
import query_idempotency as qi
import query_replay as qr


class RedisModel:
    """Serialized contract model; real Lua is exercised separately in runtime."""
    def __init__(self):
        self.entries={};self.expiry={};self.bytes=0;self.now=time.time();self.lock=threading.Lock();self.failure=None

    def eval(self,script,count,*arguments):
        with self.lock:
            if self.failure=="before":raise ConnectionError()
            capacity,identity,digest,owner,*a=arguments[3:]
            now=int(self.now*1000)
            for key in [k for k,t in self.expiry.items() if t<=now]:
                self.entries.pop(key,None);self.expiry.pop(key,None)
            raw=self.entries.get(identity)
            try:
                r=json.loads(raw) if raw else None
                if r and (r.get("idempotency_schema_version")!=1 or r.get("query_execution_id")!=identity or r.get("status") not in {"CLAIMED","COMPLETE","AMBIGUOUS","COMPLETE_UNREPLAYABLE"}):return ["INTEGRITY"]
            except (ValueError,TypeError):return ["INTEGRITY"]
            if script==qi.CLAIM:
                retention,stale,maximum,started=a
                if r:
                    if r["request_digest"]!=digest:return ["CONFLICT"]
                    if r["status"]=="CLAIMED" and now-r["claimed_at"]>=stale*1000:r["status"]="AMBIGUOUS"
                    self.entries[identity]=qi.encode(r)
                    result=[r["status"],self.entries[identity]]
                elif started>now+30000 or started+retention*1000<=now:result=["EXPIRED"]
                elif len(self.entries)>=capacity or sum(len(x) for x in self.entries.values())>=maximum:result=["FULL"]
                else:
                    r=dict(idempotency_schema_version=1,query_execution_id=identity,request_digest=digest,
                        owner_token=owner,claimed_at=now,expires_at=started+retention*1000,status="CLAIMED")
                    self.entries[identity]=qi.encode(r);self.expiry[identity]=r["expires_at"]
                    result=["OWNER",self.entries[identity]]
            elif script==qi.FINISH:
                status,payload,record_limit,total_limit=a
                if not r or r["status"]!="CLAIMED" or r["owner_token"]!=owner or r["request_digest"]!=digest:return ["STALE"]
                r["status"]=status
                if status=="COMPLETE":r["payload"]=payload
                proposed=qi.encode(r)
                if len(proposed)>record_limit or sum(len(v) for k,v in self.entries.items() if k!=identity)+len(proposed)>total_limit:
                    r["status"]="COMPLETE_UNREPLAYABLE";r.pop("payload",None)
                self.entries[identity]=qi.encode(r);result=[r["status"]]
            else:raise AssertionError("unexpected Lua")
            if self.failure=="after":raise ConnectionError()
            return result


@pytest.fixture(autouse=True)
def replay_store():
    store=qi.ReplayStore(RedisModel())
    with patch.object(qr,"get_store",return_value=store):yield store


def body():
    return dict(session_id="s1",protocol="postgres",query_raw="select version()",query_normalized="select version()",
        database="testdb",username="fake_compro1",deception_level=1,query_execution_id=str(uuid4()),request_started_at=datetime.now(timezone.utc).isoformat())


def claim(store,identity,digest,owner,started=None):
    return store.claim(identity,digest,owner,store.client.now if started is None else started)


def test_claim_complete_conflict_owner_fencing_and_serialization(replay_store):
    b=body();identity=b["query_execution_id"];digest=qi.request_digest("decide",b);owner=qi.owner_token()
    assert claim(replay_store,identity,digest,owner)[0]=="OWNER"
    assert claim(replay_store,identity,digest,qi.owner_token())[0]=="CLAIMED"
    assert claim(replay_store,identity,"f"*64,qi.owner_token())[0]=="CONFLICT"
    assert replay_store.finish(identity,digest,qi.owner_token(),JSONResponse({"wrong":1}))=="STALE"
    response=JSONResponse({"rows":[{"id":1}],"_correlation":{"query_execution_id":identity,"decision_id":str(uuid4()),"application_id":str(uuid4())}})
    assert replay_store.finish(identity,digest,owner,response)=="COMPLETE"
    status,cached=claim(qi.ReplayStore(replay_store.client),identity,digest,qi.owner_token())
    assert status=="COMPLETE" and cached.body==response.body and cached.raw_headers==response.raw_headers


@pytest.mark.parametrize("field,value",[("session_id","s2"),("protocol","mysql"),("query_raw","select 2"),
    ("query_normalized","select 2"),("database","other"),("transaction_state","failed_transaction"),
    ("request_started_at","2026-10-30T00:01:00Z")])
def test_digest_material_semantics(field,value):
    b=body();digest=qi.request_digest("decide",b)
    assert qi.request_digest("decide",{**b,field:value})!=digest
    assert qi.request_digest("decide",dict(reversed(list(b.items()))))==digest
    assert qi.request_digest("decide",{**b,"deadline_ms":999})==digest
    assert qi.request_digest("decide",b,"principal1")!=qi.request_digest("decide",b,"principal2")


def test_crash_ambiguity_no_takeover_and_horizon(replay_store):
    store=qi.ReplayStore(replay_store.client,retention=10,stale_after=2)
    b=body();i=b["query_execution_id"];d=qi.request_digest("decide",b);owner=qi.owner_token()
    started=replay_store.client.now
    assert claim(store,i,d,owner,started)[0]=="OWNER"
    replay_store.client.now+=3
    assert claim(store,i,d,qi.owner_token(),started)[0]=="AMBIGUOUS"
    assert store.finish(i,d,owner,JSONResponse({"rows":[]}))=="STALE"
    replay_store.client.now+=6
    assert claim(store,i,d,qi.owner_token(),started)[0]=="AMBIGUOUS"
    replay_store.client.now+=2
    assert claim(store,i,d,qi.owner_token(),started)[0]=="EXPIRED"  # No takeover after tombstone cleanup.


def test_capacity_and_corruption_do_not_execute(replay_store):
    store=qi.ReplayStore(replay_store.client,capacity=1)
    b=body();i=b["query_execution_id"];d=qi.request_digest("decide",b)
    assert claim(store,i,d,qi.owner_token())[0]=="OWNER"
    assert claim(store,str(uuid4()),d,qi.owner_token())[0]=="FULL"
    replay_store.client.entries[i]="malformed"
    with pytest.raises(qi.ReplayIntegrityError):claim(store,i,d,qi.owner_token())


def test_unreplayable_response_is_tombstoned(replay_store):
    b=body();i=b["query_execution_id"];d=qi.request_digest("decide",b);owner=qi.owner_token()
    claim(replay_store,i,d,owner)
    assert replay_store.finish(i,d,owner,JSONResponse({"value":"x"*qi.MAX_RESPONSE_BYTES}))=="COMPLETE_UNREPLAYABLE"
    assert claim(replay_store,i,d,qi.owner_token())[0]=="COMPLETE_UNREPLAYABLE"


def test_waiter_replays_without_execution_and_failures_preserve_claim(replay_store):
    calls=[]
    @qr.replay("test-wait","body")
    async def work(body):
        calls.append(1);await asyncio.sleep(0.02);return {"id":str(uuid4())}
    b=body()
    async def run():return await asyncio.gather(*(work(dict(b)) for _ in range(12)))
    results=asyncio.run(run())
    assert len(calls)==1 and all(r==results[0] for r in results)
    replay_store.client.failure="before"
    with pytest.raises(HTTPException) as exc:asyncio.run(work(body()))
    assert exc.value.status_code==503 and len(calls)==1


def test_owner_exception_or_completion_failure_never_reexecutes(replay_store):
    calls=[]
    @qr.replay("crash","body")
    async def work(body):calls.append(1);raise RuntimeError("test failure")
    b=body()
    with pytest.raises(RuntimeError):asyncio.run(work(b))
    with pytest.raises(HTTPException):asyncio.run(work(b))
    assert calls==[1]


@pytest.mark.parametrize("protocol",["postgres","mysql"])
def test_actual_mutation_and_exposure_replay(protocol,replay_store):
    import api
    import live_trace
    from test_principal_state import PrincipalLifecycleTests
    from test_live_trace import Sink
    fixture=PrincipalLifecycleTests();fixture.setUp()
    try:
        fixture.f.redis.hset("exposure:s1",mapping={"depth":3})
        sink=Sink();b={**body(),"protocol":protocol,"query_raw":"delete from employees where id = 1","query_normalized":"delete from employees where id = 1"}
        with patch.object(live_trace,"sink",sink):
            first=asyncio.run(api.decide(MagicMock(),b))
            before=deepcopy((fixture.f.redis.values,fixture.f.redis.hashes))
            second=asyncio.run(api.decide(MagicMock(),b))
        assert first.body==second.body and (fixture.f.redis.values,fixture.f.redis.hashes)==before and len(sink.pairs)==1
        b={**body(),"protocol":protocol,"query_raw":"select id from employees","query_normalized":"select id from employees"}
        with patch.object(live_trace,"sink",sink),patch.object(api._exposure,"record_table_access",wraps=api._exposure.record_table_access) as record:
            asyncio.run(api.decide(MagicMock(),b));asyncio.run(api.decide(MagicMock(),b))
            assert record.call_count==1
    finally:fixture.doCleanups()


@pytest.mark.parametrize("protocol",["postgres","mysql"])
def test_principal_outer_boundary_mutation_exposure_and_commitment(protocol,replay_store):
    import api,live_trace,principal_runtime
    from test_principal_state import PrincipalLifecycleTests
    from test_live_trace import Sink
    from test_world_commitment_lifecycle import observe
    from world_commitments import FIELD
    fixture=PrincipalLifecycleTests();fixture.setUp()
    try:
        sid=fixture.prepare(protocol);sink=Sink()
        def request(sql):return dict(session_id=sid,sql=sql,query_execution_id=str(uuid4()),request_started_at=datetime.now(timezone.utc).isoformat())
        def query(b):return asyncio.run(principal_runtime.query(fixture.f.reg,api,MagicMock(),b))
        with patch.object(live_trace,"sink",sink):
            b=request("update employees set salary = 12345 where id = 1")
            first=query(b);state=deepcopy((fixture.f.redis.values,fixture.f.redis.hashes))
            assert query(dict(b))==first and (fixture.f.redis.values,fixture.f.redis.hashes)==state
            assert fixture.record(protocol)["world_revision"]==1 and len(sink.pairs)==1
            # An actual depth-1 read advances once and yields receipt candidates.
            assert api._exposure.get_depth(sid)==1
            b=request("select id from employees where id = 1")
            first=query(b)
            assert api._exposure.get_depth(sid)==2
            assert observe(fixture,sid,first["observation_candidates"]).json()["inserted"]==1
            facts=deepcopy(fixture.record(protocol)[FIELD]);revision=fixture.record(protocol)["world_revision"]
            with patch.object(live_trace,"finalize",side_effect=AssertionError("replay selected a strategy")), \
                 patch.object(live_trace,"applied",side_effect=AssertionError("replay built an application")), \
                 patch.object(sink,"submit",side_effect=AssertionError("replay enqueued a trace")), \
                 patch.object(api._exposure,"record_table_access",side_effect=AssertionError("replay changed exposure")):
                assert query(dict(b))==first
            assert fixture.record(protocol)[FIELD]==facts and fixture.record(protocol)["world_revision"]==revision
            assert api._exposure.get_depth(sid)==2 and len(sink.pairs)==2
            # Principal failure/transaction cleanup retains existing protocol rules.
            begin=request("begin");assert query(begin)["tx_status"]=="T";assert query(begin)["tx_status"]=="T"
            bad=request("select missing_column from employees");result=query(bad);before=deepcopy(fixture.binding(sid))
            assert query(bad)==result and fixture.binding(sid)==before
            end=request("commit" if protocol=="postgres" else "rollback")
            finished=query(end);after=deepcopy(fixture.binding(sid));assert query(end)==finished
            assert after==fixture.binding(sid) and finished["tx_status"]=="I"
        # One distributed request record per outer request, no nested /decide claim.
        assert len(replay_store.client.entries)==5
    finally:fixture.doCleanups()


def test_expired_and_inflight_requests_do_not_run_and_completion_ack_loss(replay_store):
    calls=[]
    @qr.replay("guarded","body")
    async def work(body):calls.append(1);return {"ok":True}
    b=body();started=datetime.fromisoformat(b["request_started_at"]).timestamp()
    i=b["query_execution_id"];d=qi.request_digest("guarded",b)
    assert replay_store.claim(i,d,qi.owner_token(),started)[0]=="OWNER"
    with patch.object(qr,"WAIT_SECONDS",0):
        with pytest.raises(HTTPException) as exc:asyncio.run(work(b))
        assert exc.value.status_code==503
    replay_store.client.now+=601
    with pytest.raises(HTTPException):asyncio.run(work(b))
    assert calls==[]
    replay_store.client.now=time.time()
    b=body()
    original=replay_store.finish
    def lost_ack(*args,**kwargs):original(*args,**kwargs);raise ConnectionError()
    with patch.object(replay_store,"finish",side_effect=lost_ack):assert asyncio.run(work(b))=={"ok":True}
    assert asyncio.run(work(b))=={"ok":True} and calls==[1]


def test_completed_expiry_and_corrupt_payload_fail_closed(replay_store):
    s=qi.ReplayStore(replay_store.client,retention=2)
    b=body();i=b["query_execution_id"];d=qi.request_digest("decide",b);owner=qi.owner_token();started=s.client.now
    assert s.claim(i,d,owner,started)[0]=="OWNER"
    assert s.finish(i,d,owner,JSONResponse({"rows":[]}))=="COMPLETE"
    entry=json.loads(s.client.entries[i]);payload=json.loads(entry["payload"])
    payload["headers"]=[["content-length","999"],["content-type","application/json"]]
    entry["payload"]=json.dumps(payload);s.client.entries[i]=json.dumps(entry)
    with pytest.raises(qi.ReplayIntegrityError):s.claim(i,d,qi.owner_token(),started)
    s.client.now+=3
    assert s.claim(i,d,qi.owner_token(),started)[0]=="EXPIRED"


def test_byte_budget_keeps_terminal_nonreplayable_record(replay_store):
    b=body();i=b["query_execution_id"];d=qi.request_digest("decide",b);owner=qi.owner_token()
    claim(replay_store,i,d,owner)
    with patch.object(qi,"TOTAL_BYTES",1024):
        assert replay_store.finish(i,d,owner,JSONResponse({"value":"x"*1000}))=="COMPLETE_UNREPLAYABLE"
    assert claim(replay_store,i,d,qi.owner_token())[0]=="COMPLETE_UNREPLAYABLE"


def test_allowed_future_clock_skew_never_opens_a_takeover_window(replay_store):
    s=qi.ReplayStore(replay_store.client,retention=5,stale_after=0)
    started=s.client.now+2;i=str(uuid4());d="a"*64
    assert s.claim(i,d,qi.owner_token(),started)[0]=="OWNER"
    s.client.now+=6
    assert s.claim(i,d,qi.owner_token(),started)[0]=="AMBIGUOUS"
    s.client.now+=2
    assert s.claim(i,d,qi.owner_token(),started)[0]=="EXPIRED"

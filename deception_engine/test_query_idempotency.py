import asyncio
from copy import deepcopy
import json
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
        self.entries={};self.expiry={};self.bytes=0;self.now=1000;self.lock=threading.Lock();self.failure=None

    def eval(self,script,count,*arguments):
        with self.lock:
            if self.failure=="before":raise ConnectionError()
            capacity,identity,digest,owner,*a=arguments[3:]
            for key in [k for k,t in self.expiry.items() if t<=self.now]:
                self.entries.pop(key,None);self.expiry.pop(key,None)
            raw=self.entries.get(identity)
            try:
                r=json.loads(raw) if raw else None
                if r and (r.get("idempotency_schema_version")!=1 or r.get("query_execution_id")!=identity or r.get("status") not in {"CLAIMED","COMPLETE","AMBIGUOUS","COMPLETE_UNREPLAYABLE"}):return ["INTEGRITY"]
            except (ValueError,TypeError):return ["INTEGRITY"]
            if script==qi.CLAIM:
                retention,stale,maximum=a
                if r:
                    if r["request_digest"]!=digest:return ["CONFLICT"]
                    if r["status"]=="CLAIMED" and self.now-r["claimed_at"]>=stale:r["status"]="AMBIGUOUS"
                    self.entries[identity]=qi.encode(r)
                    result=[r["status"],self.entries[identity]]
                elif len(self.entries)>=capacity or sum(len(x) for x in self.entries.values())>=maximum:result=["FULL"]
                else:
                    r=dict(idempotency_schema_version=1,query_execution_id=identity,request_digest=digest,
                        owner_token=owner,claimed_at=self.now,expires_at=self.now+retention,status="CLAIMED")
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
        database="testdb",username="fake_compro1",deception_level=1,query_execution_id=str(uuid4()),request_started_at="2026-10-30T00:00:00Z")


def test_claim_complete_conflict_owner_fencing_and_serialization(replay_store):
    b=body();identity=b["query_execution_id"];digest=qi.request_digest("decide",b);owner=qi.owner_token()
    assert replay_store.claim(identity,digest,owner)[0]=="OWNER"
    assert replay_store.claim(identity,digest,qi.owner_token())[0]=="CLAIMED"
    assert replay_store.claim(identity,"f"*64,qi.owner_token())[0]=="CONFLICT"
    assert replay_store.finish(identity,digest,qi.owner_token(),JSONResponse({"wrong":1}))=="STALE"
    response=JSONResponse({"rows":[{"id":1}],"_correlation":{"query_execution_id":identity,"decision_id":str(uuid4()),"application_id":str(uuid4())}})
    assert replay_store.finish(identity,digest,owner,response)=="COMPLETE"
    status,cached=qi.ReplayStore(replay_store.client).claim(identity,digest,qi.owner_token())
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
    assert store.claim(i,d,owner)[0]=="OWNER"
    replay_store.client.now+=3
    assert store.claim(i,d,qi.owner_token())[0]=="AMBIGUOUS"
    assert store.finish(i,d,owner,JSONResponse({"rows":[]}))=="STALE"
    replay_store.client.now+=6
    assert store.claim(i,d,qi.owner_token())[0]=="AMBIGUOUS"
    replay_store.client.now+=2
    assert store.claim(i,d,qi.owner_token())[0]=="OWNER"  # Outside declared horizon.


def test_capacity_and_corruption_do_not_execute(replay_store):
    store=qi.ReplayStore(replay_store.client,capacity=1)
    b=body();i=b["query_execution_id"];d=qi.request_digest("decide",b)
    assert store.claim(i,d,qi.owner_token())[0]=="OWNER"
    assert store.claim(str(uuid4()),d,qi.owner_token())[0]=="FULL"
    replay_store.client.entries[i]="malformed"
    with pytest.raises(qi.ReplayIntegrityError):store.claim(i,d,qi.owner_token())


def test_unreplayable_response_is_tombstoned(replay_store):
    b=body();i=b["query_execution_id"];d=qi.request_digest("decide",b);owner=qi.owner_token()
    replay_store.claim(i,d,owner)
    assert replay_store.finish(i,d,owner,JSONResponse({"value":"x"*qi.MAX_RESPONSE_BYTES}))=="COMPLETE_UNREPLAYABLE"
    assert replay_store.claim(i,d,qi.owner_token())[0]=="COMPLETE_UNREPLAYABLE"


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
            before=deepcopy(fixture.f.redis.data)
            second=asyncio.run(api.decide(MagicMock(),b))
        assert first.body==second.body and fixture.f.redis.data==before and len(sink.pairs)==1
        b={**body(),"protocol":protocol,"query_raw":"select id from employees","query_normalized":"select id from employees"}
        with patch.object(live_trace,"sink",sink),patch.object(api._exposure,"record_table_access",wraps=api._exposure.record_table_access) as record:
            asyncio.run(api.decide(MagicMock(),b));asyncio.run(api.decide(MagicMock(),b))
            assert record.call_count==1
    finally:fixture.doCleanups()

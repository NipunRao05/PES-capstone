import asyncio
import json
from uuid import uuid4
from unittest.mock import MagicMock, patch
import pytest
from fastapi import HTTPException
import api
import live_trace
from query_correlation import metadata
from test_action_provenance import state
from test_live_trace import Sink
from test_query_idempotency import replay_store


def test_script_entrypoint_and_producer_share_one_api_module():
    """Docker runs python api.py; producer imports must use that same module."""
    import subprocess
    import sys
    from pathlib import Path
    code = '''
import importlib, runpy, uvicorn
def server(app, **kwargs):
    assert importlib.import_module("api").app is app
uvicorn.run = server
runpy.run_path("api.py", run_name="__main__")
'''
    result = subprocess.run([sys.executable,"-c",code],cwd=Path(__file__).parent,
        capture_output=True,text=True,timeout=15)
    assert result.returncode==0, result.stderr


def body(sql="select id from employees"):
    return dict(session_id="s1",query_raw=sql,query_normalized=sql,protocol="postgres",
        database="testdb",username="fake_compro1",deception_level=1,
        query_execution_id=str(uuid4()),request_started_at="2026-10-30T00:00:00Z")


def test_query_replay_and_private_response(state):
    b=body(); sink=Sink()
    with patch.object(live_trace,"sink",sink):
        first=asyncio.run(api.decide(MagicMock(),b))
        second=asyncio.run(api.decide(MagicMock(),dict(b)))
    assert len(sink.pairs)==1
    payload=json.loads(first.body)
    assert second.body==first.body
    envelope=payload["_correlation"]
    decision=sink.pairs[0]["decision"]
    assert decision["query_execution_id"]==b["query_execution_id"]==envelope["query_execution_id"]
    assert envelope["decision_id"]==decision["decision_id"]
    assert envelope["application_id"]==sink.pairs[0]["application"]["application_id"]
    assert first.headers["content-length"]==str(len(first.body))
    assert "query_execution_id" not in str(payload["rows"])
    with pytest.raises(HTTPException):
        asyncio.run(api.decide(MagicMock(),{**b,"query_normalized":"select version()"}))


def test_identical_sql_distinct_execution_ids(state):
    sink=Sink()
    with patch.object(live_trace,"sink",sink):
        a=asyncio.run(api.decide(MagicMock(),body()))
        b=asyncio.run(api.decide(MagicMock(),body()))
    assert len(sink.pairs)==2
    assert sink.pairs[0]["decision"]["decision_id"]!=sink.pairs[1]["decision"]["decision_id"]


@pytest.mark.parametrize("value",[{"query_execution_id":"x","request_started_at":"x"},
    {"query_execution_id":str(uuid4())},{"request_started_at":"2026-10-30T00:00:00Z"}])
def test_invalid_metadata_rejected(value):
    with pytest.raises(ValueError): metadata(value)


def test_outbox_accepts_correlated_pair(state):
    from test_trace_outbox import RedisModel
    from trace_outbox import Outbox
    sink=Sink()
    with patch.object(live_trace,"sink",sink): asyncio.run(api.decide(MagicMock(),body()))
    pair=sink.pairs[0]
    assert Outbox(RedisModel()).enqueue(pair)=="DURABLE_PENDING"


def test_concurrent_replay_invokes_once():
    from query_replay import replay
    calls=[]
    @replay("concurrency-test","body")
    async def produce(body):
        calls.append("produce")
        await asyncio.sleep(0)
        return {"id":str(uuid4())}
    b=body()
    async def run(): return await asyncio.gather(produce(b),produce(b))
    first,second=asyncio.run(run())
    assert first==second and calls==["produce"]


def test_principal_replay_keeps_binding_and_disable_checks(state):
    import principal_runtime
    from principal_registry import PrincipalError
    b=dict(session_id="s1",sql="select id from employees",query_execution_id=str(uuid4()),request_started_at="2026-10-30T00:00:00Z")
    first=asyncio.run(principal_runtime.query(state.f.reg,api,MagicMock(),b))
    second=asyncio.run(principal_runtime.query(state.f.reg,api,MagicMock(),dict(b)))
    assert first==second and first["_correlation"]["query_execution_id"]==b["query_execution_id"]
    key=state.f.reg.key("mysql","fake_compro1")
    record=state.f.reg.load(key);record["enabled"]=False
    state.f.reg.save(key,record)
    with pytest.raises(PrincipalError,match="disabled"):
        asyncio.run(principal_runtime.query(state.f.reg,api,MagicMock(),b))


def test_actual_decide_http_contract(state):
    import httpx
    b=body("select version()")
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app),base_url="http://test") as client:
            first=await client.post("/decide",json=b)
            again=await client.post("/decide",json=b)
            return first,again
    first,again=asyncio.run(request())
    assert first.status_code==200 and first.content==again.content
    assert first.json()["_correlation"]["query_execution_id"]==b["query_execution_id"]
    assert int(first.headers["content-length"])==len(first.content)


@pytest.mark.parametrize("sql,depth,action", [
    ("select * from unknown_relation", 3, "baseline_response"),
    ("select id from api_keys_backup", 1, "policy_rejection"),
    ("select missing_column from employees", 3, "statement_error"),
])
def test_passthrough_and_error_applications_keep_exact_linkage(state, sql, depth, action):
    state.f.redis.hset("exposure:s1", mapping={"depth": depth})
    request=body(sql); sink=Sink()
    with patch.object(live_trace,"sink",sink):
        response=asyncio.run(api.decide(MagicMock(),request))
    pair=sink.pairs[0]
    envelope=json.loads(response.body)["_correlation"]
    assert response.action_provenance.actual==action
    assert envelope["query_execution_id"]==request["query_execution_id"]
    assert envelope["decision_id"]==pair["decision"]["decision_id"]
    assert envelope["application_id"]==pair["application"]["application_id"]

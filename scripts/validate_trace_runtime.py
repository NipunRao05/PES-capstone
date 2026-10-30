#!/usr/bin/env python3
"""Explicit Pass 8E container-network validation. Synthetic fixtures only.

Stage this file and unchanged trace_outbox.py in a temporary folder under shared/,
then run inside Evidence Store via its existing /opt/honeypot read-only mount. Private
namespaces are substituted only in this test process; production code/config is
not changed. Only explicitly tracked keys in that namespace are deleted.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch
from uuid import uuid4

ROOT = Path("/opt/honeypot")
sys.path.insert(0, "/app")
sys.path.append(str(ROOT / "deception_engine"))
import redis
import requests
import trace_index
from strategy_traces import TraceStore, TraceConflict, validate_ingestion
from indexed_aggregation import indexed_aggregate
from strategy_outcomes import evaluate
from trace_outbox import Outbox

RUN = "pass8e_" + uuid4().hex
RESULTS = {}
CLIENT = redis.Redis(host=os.environ["REDIS_HOST"], port=int(os.getenv("REDIS_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0")), decode_responses=True, socket_timeout=10)
OUTBOX_CLIENT = redis.Redis(host="redis-deception", decode_responses=True, socket_timeout=5)
URL = "http://evidence-store:8011"
DIGEST = hashlib.sha256(RUN.encode()).hexdigest()  # Clearly synthetic fixture context.
SCOPE = dict(experiment_id="deterministic_baseline", experiment_version=1,
             scoring_profile_id="deterministic_components", scoring_profile_version=1,
             strategy_definition_digest=DIGEST)


def pair(status="APPLIED"):
    stamp = datetime.now(timezone.utc).isoformat()
    d = dict(schema_version=1, decision_id=str(uuid4()), timestamp=stamp,
        experiment_id="deterministic_baseline", experiment_version=1, mode="deterministic_rule_based",
        active=True, session_id=RUN, principal_id=None, protocol="postgres", strategy_id="D0",
        strategy_version=1, strategy_definition_digest=DIGEST, expected_action_binding="baseline_response",
        approval_status="APPROVED", eligibility={"eligible":True,"reason":"APPROVED"},
        reason_code="PASS8E_FIXTURE", state_before=dict(transaction_state="idle",exposure_depth=1,
            commitment_scope="unavailable",commitment_set_digest=None,evaluated_commitments=[]))
    a = dict(schema_version=1,application_id=str(uuid4()),decision_id=d["decision_id"],timestamp=stamp,
        expected_action_binding="baseline_response",actual_action_binding="baseline_response",
        provenance_status="MATCH",application_status=status,result_class="fake")
    return dict(decision=d,application=a)


def outcome(p):
    close = (datetime.fromisoformat(p["application"]["timestamp"])+timedelta(seconds=1)).isoformat()
    return evaluate(RUN,[p],[],closed_at=close,as_of=close,query_coverage=True,trace_coverage=True)[0]


def put(store,p,with_outcome=False):
    for kind in ("decision","application"):store.store(kind,p[kind])
    if with_outcome:store.store("outcome",outcome(p))


@contextmanager
def isolated(label,ttl=120,capacity=1000):
    prefix = RUN+":"+label
    record_prefix = prefix+":trace:"
    tracked=set()
    original_key=TraceStore.key
    class IsolatedStore(TraceStore):
        @staticmethod
        def key(kind,identity):
            key=original_key(kind,identity).replace("evidence:strategy_trace:",record_prefix,1)
            tracked.add(key)
            return key
    patches = [patch.object(trace_index,"PREFIX",prefix+":index"),patch.object(trace_index,"CAPACITY",capacity)]
    for name in ("WRITE","READ","ACTIVATE"):
        patches.append(patch.object(trace_index,name,getattr(trace_index,name).replace("evidence:strategy_trace:",record_prefix)))
    try:
        for item in patches:item.start()
        tracked.update(trace_index.index_keys())
        yield IsolatedStore(CLIENT,ttl)
    finally:
        assert all(key.startswith(prefix+":") for key in tracked)
        if tracked:CLIENT.delete(*tracked)
        for item in reversed(patches):item.stop()


def index_checks():
    with isolated("core") as store:
        p=pair();put(store,p,True)
        first=store.indexed_snapshot()
        assert first["index_version"]==1 and first["index_epoch"] and first["index_enabled_at"]
        assert first["snapshot_max_sequence"]==3
        for kind,record in (("decision",p["decision"]),("application",p["application"]),("outcome",outcome(p))):
            key=store.key(kind,record[kind+"_id"]);before=CLIENT.pttl(key)
            assert store.store(kind,record)=="unchanged"
            assert CLIENT.pttl(key)<=before
            assert store.get(kind,record[kind+"_id"])==record
        assert store.indexed_snapshot()==first
        try:store.store("decision",{**p["decision"],"reason_code":"CHANGED"})
        except TraceConflict:pass
        else:raise AssertionError("conflicting content accepted")
        assert store.indexed_snapshot()==first
        RESULTS["lua_atomic_replay_conflict"]="VERIFIED"
    with isolated("pages") as store:
        ds=[pair()["decision"] for _ in range(132)]
        for d in ds:store.store("decision",d)
        first=store.list_records("decision",limit=128)
        store.store("decision",pair()["decision"])
        second=store.list_records("decision",limit=128,after_sequence=first["kinds"]["decision"]["after_sequence"],
            snapshot_max_sequence=first["snapshot_max_sequence"],index_epoch=first["index_epoch"])
        rows=first["kinds"]["decision"]["entries"]+second["kinds"]["decision"]["entries"]
        assert [e["record"] for e in rows]==ds and second["kinds"]["decision"]["done"]
        RESULTS["snapshot_pagination"]={"status":"VERIFIED","records":132,"page_counts":[128,4]}
    with isolated("expiry",ttl=1) as store:
        d=pair()["decision"];store.store("decision",d)
        time.sleep(1.15)
        result=store.indexed_snapshot()
        assert result["kinds"]["decision"]["retained_count"]==0 and result["stale_members_removed"]==1
        store.store("decision",d)
        assert store.indexed_snapshot()["snapshot_max_sequence"]==2
        RESULTS["expiry_cleanup"]="VERIFIED"
    with isolated("concurrency") as store:
        d=pair()["decision"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:store.store("decision",d),range(12)))
            distinct=list(pool.map(lambda _:store.store("decision",pair()["decision"]),range(12)))
        assert results.count("inserted")==1 and results.count("unchanged")==11
        assert store.indexed_snapshot()["kinds"]["decision"]["retained_count"]==13
        RESULTS["concurrency"]={"status":"VERIFIED","same_id_writers":12,"distinct_writers":12}
    with isolated("capacity",capacity=3) as store:
        ds=[pair()["decision"] for _ in range(4)]
        for d in ds[:3]:store.store("decision",d)
        before=store.indexed_snapshot()
        try:store.store("decision",ds[3])
        except trace_index.IndexCapacityError:pass
        else:raise AssertionError("capacity not enforced")
        assert store.get("decision",ds[3]["decision_id"]) is None and store.indexed_snapshot()==before
        RESULTS["functional_capacity"]={"status":"VERIFIED","test_capacity":3,"production_capacity":1000}


def report_timings():
    RESULTS["report_timings"]=[]
    for count in (100,500):
        with isolated("timing"+str(count)) as store:
            for _ in range(count):put(store,pair(),True)
            begin=time.perf_counter()
            report=indexed_aggregate(store,filters=SCOPE)
            elapsed=time.perf_counter()-begin
            assert report["retained_applications"]==count and report["retained_store_outcome_coverage"]==1
            RESULTS["report_timings"].append(dict(records_per_kind=count,elapsed_seconds=round(elapsed,6),
                timeout=False,memory_or_request_error=False))


def http_post(path,payload):
    return requests.post(URL+path,json=payload,timeout=10)


def delivery_checks():
    store=TraceStore(CLIENT,2592000)
    p1,p2,p3=pair(),pair("BLOCKED"),pair()
    for p in (p1,p2,p3):validate_ingestion(p)
    assert http_post("/evidence/strategy-trace",p1).json()=={"decision":"inserted","application":"inserted"}
    assert http_post("/evidence/strategy-trace",p1).json()=={"decision":"unchanged","application":"unchanged"}
    changed=deepcopy(p1);changed["decision"]["reason_code"]="CONFLICT_FIXTURE"
    assert http_post("/evidence/strategy-trace",changed).status_code==409
    assert http_post("/evidence/strategy-trace",p2).status_code==200
    prefix=RUN+":outbox"
    clock=[time.time()]
    box=Outbox(OUTBOX_CLIENT,prefix=prefix,clock=lambda:clock[0])
    try:
        assert box.enqueue(p3)=="DURABLE_PENDING"
        assert box.step(lambda _:type("Unavailable",(),{"status_code":503})())=="RETRY_PENDING"
        pending=json.loads(OUTBOX_CLIENT.hget(box.keys[0],p3["application"]["application_id"]))
        assert pending["attempt_count"]==1 and pending["pair"]==p3
        # Recreate the worker in a NEW Python process. Force a lost ACK locally,
        # after successful real HTTP delivery, without altering any service/network.
        worker=r'''
import json,sys,time,redis,requests
from trace_outbox import Outbox
prefix,offset,lost=sys.argv[1:]
r=redis.Redis(host="redis-deception",decode_responses=True)
box=Outbox(r,prefix=prefix,clock=lambda:time.time()+float(offset))
def send(pair):
 response=requests.post("http://evidence-store:8011/evidence/strategy-trace",json=pair,timeout=5)
 if lost=="yes":
  assert response.status_code==200
  raise ConnectionError("test-only lost acknowledgement")
 return response
print(box.step(send))
'''
        env=dict(os.environ,PYTHONPATH=os.pathsep.join((str(Path(__file__).parent),str(ROOT/"deception_engine"))))
        lost=subprocess.run([sys.executable,"-c",worker,prefix,"3","yes"],env=env,capture_output=True,text=True,timeout=15)
        assert lost.returncode==0 and lost.stdout.strip()=="RETRY_PENDING"
        recovered=subprocess.run([sys.executable,"-c",worker,prefix,"10","no"],env=env,capture_output=True,text=True,timeout=15)
        assert recovered.returncode==0 and recovered.stdout.strip()=="DELIVERED"
        assert OUTBOX_CLIENT.hget(box.keys[0],p3["application"]["application_id"]) is None
        assert store.get("application",p3["application"]["application_id"])==p3["application"]
        RESULTS["outbox_retry_lost_ack_process_recreation"]="VERIFIED"
    finally:
        assert all(k.startswith(RUN+":") for k in box.keys)
        OUTBOX_CLIENT.delete(*box.keys)
    for p in (p1,p3):store.store("outcome",outcome(p))
    response=http_post("/evidence/strategy-outcomes/aggregate",dict(population_mode="INDEXED_RETAINED",filters=SCOPE))
    response.raise_for_status();report=response.json();c=report["coverage"]
    assert report["coverage_denominator_status"]=="AUTHORITATIVE_INDEXED_SCOPE"
    assert (c["retained_applications"],c["applications_with_outcomes"],c["applications_without_outcomes"],c["outcome_coverage"])==(3,2,1,2/3)
    assert c["eligible_retained_applications"]==2 and c["eligible_outcome_coverage"]==1
    empty=http_post("/evidence/strategy-outcomes/aggregate",dict(population_mode="INDEXED_RETAINED",filters={**SCOPE,"experiment_id":RUN})).json()
    assert empty["retained_applications"]==0 and empty["retained_store_outcome_coverage"] is None
    RESULTS["http_denominator"]=c
    RESULTS["empty_denominator"]="VERIFIED"
    RESULTS["production_fixture_retention"]={"session_id":RUN,"definition_digest":DIGEST,
        "applications":[p["application"]["application_id"] for p in (p1,p2,p3)],"ttl_seconds":2592000}
    with isolated("orphan",ttl=60) as isolated_store:
        p=pair();put(isolated_store,p,True)
        CLIENT.delete(isolated_store.key("application",p["application"]["application_id"]))
        r=indexed_aggregate(isolated_store,filters=SCOPE)
        assert r["retained_applications"]==0 and r["orphan_diagnostics"]["outcome_without_retained_application"]==1
        RESULTS["orphan_diagnostic"]="VERIFIED"


def main():
    assert CLIENT.ping() and OUTBOX_CLIENT.ping()
    index_checks()
    report_timings()
    delivery_checks()
    RESULTS["status"]="PASS"
    print(json.dumps(RESULTS,sort_keys=True,indent=2))


if __name__=="__main__":
    main()

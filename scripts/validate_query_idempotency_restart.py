#!/usr/bin/env python3
"""Prepare/check a bounded real-engine replay across an engine-only restart.

Uses isolated synthetic sessions, no DB credentials or physical SQL mutations.
Checkpoint contains engineering fixture requests/responses only, under .runtime.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import time
import urllib.request
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
CHECKPOINT=ROOT/".runtime/pass8f-restart.json"


def call(port,path,body):
    req=urllib.request.Request(f"http://127.0.0.1:{port}"+path,data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=5) as response:return response.read()


def state(requests):
    code='''import hashlib,json,os,redis,sys
r=redis.Redis(host=os.environ["REDIS_HOST"],decode_responses=True)
result={}
for request in json.loads(sys.argv[1]):
 sid=request["session_id"];identity=request["query_execution_id"]
 raw=r.hget("deception:query-idempotency:v1:records",identity)
 entry=json.loads(raw or "null")
 assert entry and entry["status"]=="COMPLETE"
 result[identity]={"replay_hash":hashlib.sha256(raw.encode()).hexdigest(),
  "mutation":r.get("mutation:"+sid+":employees"),"exposure":r.hgetall("exposure:"+sid)}
print(json.dumps(result,sort_keys=True))'''
    completed=subprocess.run(["docker","exec","capstone-main-deception-engine-1","python","-c",code,json.dumps(requests)],capture_output=True,text=True,timeout=10)
    assert completed.returncode==0,"Runtime replay state missing or incomplete"
    return json.loads(completed.stdout)


def trace_count(sessions):
    report=json.loads(call(8011,"/evidence/strategy-traces/list",{"kind":"decision","limit":128}))
    assert report["kinds"]["decision"]["done"],"Validation requires bounded local population"
    return sum(e["record"]["session_id"] in sessions for e in report["kinds"]["decision"]["entries"])


def prepare():
    requests=[];responses=[]
    for protocol in ("postgres","mysql"):
        sid="pass8f_"+protocol+"_"+uuid4().hex
        for sql in ("update employees set salary = 12345 where id = 1","select id from employees where id = 1"):
            b=dict(session_id=sid,protocol=protocol,database="testdb",username="postgres" if protocol=="postgres" else "proxyuser",
                deception_level=1,query_raw=sql,query_normalized=sql,query_execution_id=str(uuid4()),request_started_at=datetime.now(timezone.utc).isoformat())
            raw=call(8001,"/decide",b);payload=json.loads(raw)
            assert payload["mode"]=="fake" and payload["_correlation"]["query_execution_id"]==b["query_execution_id"]
            assert call(8001,"/decide",b)==raw
            requests.append(b);responses.append(raw.decode())
    until=time.monotonic()+20
    while trace_count({r["session_id"] for r in requests})!=4:
        assert time.monotonic()<until,"Fixture traces not delivered"
        time.sleep(0.25)
    checkpoint=dict(requests=requests,responses=responses,state=state(requests),trace_count=4)
    CHECKPOINT.write_text(json.dumps(checkpoint,indent=2),encoding="utf-8")
    print(json.dumps(dict(status="PREPARED",requests=4,protocols=["postgres","mysql"],sessions=sorted({r["session_id"] for r in requests}))))


def check():
    until=time.monotonic()+20
    while True:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8001/readyz",timeout=2) as response:
                if json.load(response).get("ready") is True:break
        except (OSError,http.client.HTTPException):pass
        assert time.monotonic()<until,"Engine did not become ready after restart"
        time.sleep(0.2)
    checkpoint=json.loads(CHECKPOINT.read_text(encoding="utf-8"))
    for body,original in zip(checkpoint["requests"],checkpoint["responses"]):
        assert call(8001,"/decide",body).decode()==original,"Restart replay changed response or trace IDs"
    assert state(checkpoint["requests"])==checkpoint["state"],"Replay repeated a state effect"
    assert trace_count({r["session_id"] for r in checkpoint["requests"]})==4,"Replay built a new trace"
    print(json.dumps(dict(status="PASS",restart_replay="VERIFIED",requests=4,protocols=["postgres","mysql"],
        same_response_and_ids=True,mutation_and_exposure_unchanged=True,trace_count=4),sort_keys=True,indent=2))


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("stage",choices=["prepare","check"])
    args=parser.parse_args()
    prepare() if args.stage=="prepare" else check()

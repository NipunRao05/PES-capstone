#!/usr/bin/env python3
"""Pass 8F real Redis checks in the engine container, isolated exact test keys.

Stage this script and query_idempotency.py/query_replay.py together under shared/.
The running engine is unchanged by these independent test processes.
"""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4
from datetime import datetime, timezone
sys.path.insert(0,str(Path(__file__).parent))
sys.path.append("/app")
import redis
from fastapi import HTTPException
from starlette.responses import JSONResponse
import query_idempotency as qi
import query_replay as qr


def client():
    return redis.Redis(host=os.environ["REDIS_HOST"],decode_responses=True,socket_timeout=2)


def body(identity=None,sql="select version()"):
    return dict(session_id="pass8f_runtime",protocol="postgres",query_execution_id=identity or str(uuid4()),
        request_started_at=datetime.now(timezone.utc).isoformat(),query_normalized=sql,query_raw=sql)


def worker(prefix,serialized,repetitions):
    from decision_trace import begin, applied
    from action_provenance import verify_action
    from strategy_registry import StrategyRegistry
    r=client();b=json.loads(serialized);store=qi.ReplayStore(r,prefix=prefix)
    qr.get_store=lambda:store
    registry=StrategyRegistry.load()
    @qr.replay("integration","body")
    async def produce(body):
        r.incr(prefix+":count:"+body["query_execution_id"])
        d=begin(registry,"D0",session_id=body["session_id"],protocol=body["protocol"],transaction_state="idle",exposure_depth=1)
        await asyncio.sleep(0.04)
        a=applied(d,verify_action(registry.get("D0"),"baseline_response"),result_mode="fake")
        r.rpush(prefix+":pairs",json.dumps({"decision":d,"application":a}))
        return JSONResponse({"mode":"fake","rows":[{"value":1}],"_correlation":{
            "query_execution_id":body["query_execution_id"],"request_started_at":body["request_started_at"],
            "decision_id":d["decision_id"],"application_id":a["application_id"]}})
    r.incr(prefix+":ready")
    until=time.monotonic()+10
    while not r.get(prefix+":go"):
        assert time.monotonic()<until
        time.sleep(0.01)
    async def one():
        try:
            result=await produce(dict(b))
            return dict(status=200,body=result.body.decode(),headers=result.raw_headers==[(b"content-length",str(len(result.body)).encode()),(b"content-type",b"application/json")])
        except HTTPException as exc:return dict(status=exc.status_code)
    async def run():return await asyncio.gather(*(one() for _ in range(int(repetitions))))
    print(json.dumps(asyncio.run(run())))


def main():
    r=client();assert r.ping()
    root="pass8f:"+uuid4().hex
    keys=set();result={}
    def store(label,**kwargs):
        s=qi.ReplayStore(r,prefix=root+":"+label,**kwargs);keys.update(s.keys);return s
    def parallel(label,requests,repetitions):
        prefix=root+":"+label
        keys.update(qi.ReplayStore(r,prefix=prefix).keys)
        keys.update(prefix+suffix for suffix in (":ready",":go",":pairs"))
        keys.update(prefix+":count:"+b["query_execution_id"] for b in requests)
        procs=[subprocess.Popen([sys.executable,__file__,"worker",prefix,json.dumps(b),str(repetitions)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for b in requests]
        until=time.monotonic()+10
        while int(r.get(prefix+":ready") or 0)!=len(requests):
            assert time.monotonic()<until,"workers did not initialize"
            time.sleep(0.02)
        r.set(prefix+":go","1")
        outputs=[]
        for proc in procs:
            out,err=proc.communicate(timeout=15)
            assert proc.returncode==0,err
            outputs.extend(json.loads(out))
        return prefix,outputs
    try:
        s=store("serialization");b=body();i=b["query_execution_id"];d=qi.request_digest("serialization",b);owner=qi.owner_token();started=time.time()
        assert s.claim(i,d,owner,started)[0]=="OWNER"
        response=JSONResponse({"rows":[],"_correlation":{"query_execution_id":i,"decision_id":str(uuid4()),"application_id":str(uuid4())}})
        assert s.finish(i,d,owner,response)=="COMPLETE"
        status,cached=s.claim(i,d,qi.owner_token(),started)
        assert status=="COMPLETE" and cached.body==response.body and cached.raw_headers==response.raw_headers
        assert all(r.ttl(key)>0 for key in s.keys)
        result["serialization_and_key_ttls"]="PASS"
        b=body();prefix,outputs=parallel("same",[b,b],5)
        assert all(o["status"]==200 and o["body"]==outputs[0]["body"] and o["headers"] for o in outputs)
        assert int(r.get(prefix+":count:"+b["query_execution_id"]))==1 and r.llen(prefix+":pairs")==1
        result["two_processes_ten_requests"]="PASS: one producer, one decision/application pair, exact replay"
        changed={**b,"query_raw":"select 2","query_normalized":"select 2"}
        prefix,outputs=parallel("conflict",[b,changed],1)
        assert sorted(o["status"] for o in outputs)==[200,409] and r.llen(prefix+":pairs")==1
        result["concurrent_conflict"]="PASS"
        a,b=body(),body();prefix,outputs=parallel("distinct",[a,b],1)
        assert all(o["status"]==200 for o in outputs) and r.llen(prefix+":pairs")==2
        result["different_ids_same_sql"]="PASS"
        s=store("crash",stale_after=0);b=body();i=b["query_execution_id"];d=qi.request_digest("crash",b);owner=qi.owner_token();started=time.time()
        # Independent owner exits after the atomic claim, before producer/COMPLETE.
        code="import json,sys,os;sys.path.insert(0,sys.argv[1]);import query_idempotency as q,redis;r=redis.Redis(host=os.environ['REDIS_HOST'],decode_responses=True);print(q.ReplayStore(r,prefix=sys.argv[2]).claim(sys.argv[3],sys.argv[4],sys.argv[5],float(sys.argv[6]))[0])"
        child=subprocess.run([sys.executable,"-c",code,str(Path(__file__).parent),root+":crash",i,d,owner,str(started)],capture_output=True,text=True,timeout=10)
        assert child.returncode==0 and child.stdout.strip()=="OWNER"
        assert s.claim(i,d,qi.owner_token(),started)[0]=="AMBIGUOUS"
        assert s.finish(i,d,owner,JSONResponse({"ok":True}))=="STALE"
        result["owner_loss_before_complete"]="PASS: ambiguous, no takeover"
        s=store("expiry",retention=1,stale_after=0);b=body();i=b["query_execution_id"];d=qi.request_digest("expiry",b);started=time.time()
        assert s.claim(i,d,qi.owner_token(),started)[0]=="OWNER"
        assert s.claim(i,d,qi.owner_token(),started)[0]=="AMBIGUOUS"
        time.sleep(1.1)
        assert s.claim(i,d,qi.owner_token(),started)[0]=="EXPIRED"
        assert r.hget(s.keys[0],i) is None
        result["expired_incomplete_request"]="PASS: old request rejected after cleanup"
        s=store("future",retention=1,stale_after=0);i=str(uuid4());started=time.time()+0.5;d="a"*64
        assert s.claim(i,d,qi.owner_token(),started)[0]=="OWNER"
        time.sleep(1.1)
        assert s.claim(i,d,qi.owner_token(),started)[0]=="AMBIGUOUS"
        time.sleep(0.5)
        assert s.claim(i,d,qi.owner_token(),started)[0]=="EXPIRED"
        result["clock_skew_expiry_fence"]="PASS"
        s=store("capacity",capacity=2)
        for _ in range(2):assert s.claim(str(uuid4()),"a"*64,qi.owner_token(),time.time())[0]=="OWNER"
        assert s.claim(str(uuid4()),"a"*64,qi.owner_token(),time.time())[0]=="FULL"
        assert r.hlen(s.keys[0])==2
        result["capacity"]="PASS"
        s=store("corrupt");i=str(uuid4());assert s.claim(i,"a"*64,qi.owner_token(),time.time())[0]=="OWNER"
        r.hset(s.keys[0],i,"malformed")
        try:s.claim(i,"a"*64,qi.owner_token(),time.time())
        except qi.ReplayIntegrityError:pass
        else:raise AssertionError("corrupt record accepted")
        assert r.hget(s.keys[0],i)=="malformed"
        result["corruption"]="PASS"
        result["status"]="PASS"
        print(json.dumps(result,indent=2,sort_keys=True))
    finally:
        assert all(k.startswith(root+":") for k in keys)
        r.delete(*keys)


if __name__=="__main__":
    if len(sys.argv)>1 and sys.argv[1]=="worker":worker(*sys.argv[2:])
    else:main()

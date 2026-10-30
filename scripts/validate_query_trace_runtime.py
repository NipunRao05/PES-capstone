#!/usr/bin/env python3
"""One read-only PG simple query using credentials already inside its DB container.

No credentials leave the container or enter argv/output. This creates ordinary
engineering-validation session evidence; it is not attacker research data.
"""
import json
import subprocess
import time
import urllib.request
from uuid import UUID

BASE="http://127.0.0.1:8011"


def request(path,body=None):
    data=json.dumps(body).encode() if body is not None else None
    req=urllib.request.Request(BASE+path,data=data,headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=5) as response:return json.load(response)


def page(kind):
    return request("/evidence/strategy-traces/list",{"kind":kind,"limit":128})


def main():
    boundary=page("application")["snapshot_max_sequence"]
    result=subprocess.run(["docker","exec","capstone-main-postgres-1","sh","-c",
        'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -h pgproxy -p 5432 -U postgres -d testdb -Atc "select version()"'],
        capture_output=True,text=True,timeout=15)
    assert result.returncode==0, "Controlled PostgreSQL authentication/query failed"
    assert all(field not in result.stdout for field in ("_correlation","query_execution_id","application_id","decision_id"))
    deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        applications=[e for e in page("application")["kinds"]["application"]["entries"] if e["sequence"]>boundary]
        decisions={e["record_id"]:e["record"] for e in page("decision")["kinds"]["decision"]["entries"]}
        for entry in applications:
            a=entry["record"];d=decisions.get(a["decision_id"])
            if not d or d.get("protocol")!="postgres" or not d.get("query_execution_id"):continue
            evidence=request("/evidence/session/"+d["session_id"])
            # The existing endpoint returns the session object directly.
            session=evidence.get("session",evidence)
            matches=[q for q in session.get("queries",[]) if q.get("query_execution_id")==d["query_execution_id"]]
            if not matches:continue
            query=matches[0]
            assert query["application_id"]==a["application_id"] and query["decision_id"]==d["decision_id"]
            assert query["request_started_at"]==d["request_started_at"]
            assert str(UUID(query["query_execution_id"]))==query["query_execution_id"]
            check=subprocess.run(["docker","exec","capstone-main-deception-engine-1","python","-c",
                "import os,redis,sys; r=redis.Redis(host=os.environ['REDIS_HOST']); print(r.hget('trace-outbox:v1:entries',sys.argv[1]) is None)",a["application_id"]],
                capture_output=True,text=True,timeout=5)
            assert check.returncode==0 and check.stdout.strip()=="True"
            print(json.dumps(dict(status="PASS",protocol="postgres",query_execution_id=query["query_execution_id"],
                session_id=d["session_id"],decision_id=d["decision_id"],application_id=a["application_id"],
                request_started_at=query["request_started_at"],outbox_acknowledged=True,
                attacker_metadata_absent=True,indexed_application=True),sort_keys=True,indent=2))
            return
        time.sleep(0.5)
    raise AssertionError("Bounded proxy-to-event/trace linkage was not observed")


if __name__=="__main__":main()

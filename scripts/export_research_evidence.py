"""Checksummed admission-bounded export of sanitized evidence; never raw Kafka/Redis."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import urllib.request
from uuid import uuid4


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)


def request(base,path,body=None,headers=None):
    data=None if body is None else encoded(body).encode()
    req=urllib.request.Request(base.rstrip("/")+path,data=data,headers={"Content-Type":"application/json",**(headers or {})})
    with urllib.request.urlopen(req,timeout=15) as response:
        return json.load(response)


def file_digest(path):
    total=0;checksum=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda:stream.read(1048576),b""):
            total+=len(chunk);checksum.update(chunk)
    return {"sha256":checksum.hexdigest(),"bytes":total}


def export(base,output,traffic_origin="research_external",manifest_id=None,delivery_base=None):
    output=Path(output).resolve()
    output.mkdir(parents=True,exist_ok=False)  # Never replace an earlier dataset.
    registry=request(base,"/evidence/deployment-manifests")["manifests"]
    status_before=request(base,"/evidence/research/status")
    journal=request(base,"/evidence/research-journal/list",{})
    trace=request(base,"/evidence/strategy-traces/list",{"kind":"decision","limit":128})
    boundary={k:trace[k] for k in ("snapshot_max_sequence","index_epoch")}
    journal_boundary={"maximum":journal["snapshot_max_sequence"],"epoch":journal["epoch"]}
    counts=Counter();origins=Counter();missing=Counter();used_manifests=set()
    database=sqlite3.connect(output/".export-catalog.sqlite")
    database.execute("CREATE TABLE identities(kind TEXT,id TEXT,PRIMARY KEY(kind,id))")
    database.execute("CREATE TABLE refs(kind TEXT,id TEXT)")
    database.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,origin TEXT,manifest TEXT,events INTEGER,queries INTEGER)")

    def selected(record):
        origin=record.get("traffic_origin","unknown")
        reference=record.get("deployment_manifest_id")
        return (traffic_origin=="all" or origin==traffic_origin) and (manifest_id is None or reference==manifest_id)

    def provenance(record):
        origins[record.get("traffic_origin","unknown")]+=1
        reference=record.get("deployment_manifest_id")
        if reference:used_manifests.add(reference)
        else:missing["legacy_unknown_manifest"]+=1

    with (output/"events.jsonl").open("w",encoding="utf-8",newline="\n") as stream:
        while True:
            missing["expired_or_missing_journal_records"]+=journal["missing_records"]
            for entry in journal["entries"]:
                envelope=entry["record"];payload=envelope["payload"]
                if not selected(payload):continue
                provenance(payload)
                stream.write(encoded(entry)+"\n");counts["events"]+=1
                sid=envelope["session_id"]
                database.execute("INSERT INTO sessions VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET events=events+1,queries=queries+excluded.queries",
                    (sid,payload.get("traffic_origin","unknown"),payload.get("deployment_manifest_id"),1,int(envelope["collection"]=="queries")))
            if journal["done"]:break
            journal=request(base,"/evidence/research-journal/list",{"after":journal["after_sequence"],**journal_boundary})

    with (output/"traces.jsonl").open("w",encoding="utf-8",newline="\n") as stream:
        for kind in ("decision","application","outcome"):
            page=trace if kind=="decision" else request(base,"/evidence/strategy-traces/list",{"kind":kind,"limit":128,**boundary})
            while True:
                missing["stale_trace_members"]+=page["stale_members_removed"]
                group=page["kinds"][kind]
                for entry in group["entries"]:
                    record=entry["record"]
                    if not selected(record):continue
                    provenance(record)
                    stream.write(encoded({"kind":kind,**entry})+"\n");counts[kind]+=1
                    database.execute("INSERT INTO identities VALUES(?,?)",(kind,entry["record_id"]))
                    if kind in ("application","outcome"):
                        refkind="decision" if kind=="application" else "application"
                        database.execute("INSERT INTO refs VALUES(?,?)",(refkind,record[refkind+"_id"]))
                if group["done"]:break
                page=request(base,"/evidence/strategy-traces/list",{"kind":kind,"limit":128,
                    "after_sequence":group["after_sequence"],**boundary})

    with (output/"journal-session-summaries.jsonl").open("w",encoding="utf-8",newline="\n") as stream:
        for sid,origin,reference,events,queries in database.execute("SELECT * FROM sessions ORDER BY id"):
            stream.write(encoded({"session_id":sid,"traffic_origin":origin,"deployment_manifest_id":reference,
                "retained_journal_events":events,"retained_query_events":queries,
                "source_scope":"BOUNDED_JOURNAL_SNAPSHOT","completeness":"NOT_VERIFIED"})+"\n")
            counts["journal_session_summaries"]+=1
    projection=request(base,"/evidence/research/session-projections/list",{})
    projection_boundary={k:projection[k] for k in ("maximum","consistency","truncated")}
    seen_sessions=set()
    with (output/"sessions.jsonl").open("w",encoding="utf-8",newline="\n") as stream:
        while True:
            missing["missing_session_projections"]+=projection["missing_sessions"]
            for session in projection["sessions"]:
                sid=session["session_id"]
                if sid in seen_sessions:
                    missing["projection_rank_duplicates"]+=1
                    continue
                seen_sessions.add(sid)
                if not selected(session):continue
                provenance(session)
                stream.write(encoded(session)+"\n");counts["sessions"]+=1
            if projection["done"]:break
            projection=request(base,"/evidence/research/session-projections/list",{"offset":projection["after"],"maximum":projection["maximum"]})
    unresolved=database.execute("SELECT COUNT(*) FROM refs r LEFT JOIN identities i ON i.kind=r.kind AND i.id=r.id WHERE i.id IS NULL").fetchone()[0]
    database.close();(output/".export-catalog.sqlite").unlink()
    missing["unresolved_trace_references"]=unresolved
    missing["unresolved_deployment_manifests"]=len(used_manifests-set(registry))
    selected_registry={k:registry[k] for k in sorted(used_manifests & set(registry))}
    if selected_registry:
        current=max(selected_registry.values(),key=lambda x:x["created_at"])
    elif registry:
        current=max(registry.values(),key=lambda x:x["created_at"])
    else:
        current={}
    # Even an empty filtered dataset includes its export-context deployment.
    # This does not assign that provenance to any historical record.
    if not selected_registry and current:
        selected_registry={current["manifest_id"]:current}
    (output/"deployments.json").write_text(encoded(selected_registry)+"\n",encoding="utf-8")
    delivery={"status":"NOT_VERIFIED"}
    if delivery_base:
        try:delivery=request(delivery_base,"/research/delivery-status")
        except Exception:pass
    status_after=request(base,"/evidence/research/status")
    info={"export_schema_version":1,"export_id":str(uuid4()),"created_at":datetime.now(timezone.utc).isoformat(),
        "exporter_sha256":file_digest(__file__)["sha256"],
        **{k:current.get(k) for k in ("experiment_id","experiment_version","deployment_id","run_id","git_commit",
            "configuration_digest","world_id","world_version","strategy_registry_digest","strategy_registry_version",
            "scoring_profile_id","scoring_profile_version")},
        "traffic_origin_filter":traffic_origin,"deployment_manifest_filter":manifest_id,
        "deployment_manifest_ids":sorted(used_manifests|set(selected_registry)),
        "export_context_manifest_id":current.get("manifest_id"),
        "record_counts":{k:counts[k] for k in ("events","sessions","journal_session_summaries","decision","application","outcome")},
        "origin_counts":dict(origins),"diagnostics":dict(missing),"collection_completeness":"NOT_VERIFIED",
        "snapshot_semantics":"SEPARATE_IMMUTABLE_ADMISSION_HIGH_WATERS; not an atomic cross-pipeline cut",
        "trace_boundary":boundary,"journal_boundary":journal_boundary,"session_projection_boundary":projection_boundary,
        "status_before":status_before,"status_after":status_after,"delivery_status":delivery,
        "null_semantics":"Preserved verbatim. Missing outcomes are not synthesized.",
        "files":{}}
    for name in ("events.jsonl","traces.jsonl","sessions.jsonl","journal-session-summaries.jsonl","deployments.json"):
        info["files"][name]=file_digest(output/name)
    manifest=output/"export-manifest.json"
    manifest.write_text(encoded(info)+"\n",encoding="utf-8")
    (output/"export-manifest.sha256").write_text(hashlib.sha256(manifest.read_bytes()).hexdigest()+"\n",encoding="ascii")
    return info


def validate(directory):
    directory=Path(directory).resolve()
    raw=(directory/"export-manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest()!=(directory/"export-manifest.sha256").read_text().strip():raise ValueError("Export manifest checksum mismatch")
    manifest=json.loads(raw);counts=Counter();identities=set();references=[]
    for name,expected in manifest["files"].items():
        if name not in {"events.jsonl","traces.jsonl","sessions.jsonl","journal-session-summaries.jsonl","deployments.json"}:raise ValueError("Unexpected export file")
        if file_digest(directory/name)!=expected:raise ValueError("Export file checksum mismatch")
        if name.endswith(".jsonl"):
            for line in (directory/name).open("rb"):
                record=json.loads(line)
                kind=record.get("kind") if name=="traces.jsonl" else "events" if name=="events.jsonl" else "journal_session_summaries" if name=="journal-session-summaries.jsonl" else "sessions"
                counts[kind]+=1
                if name=="traces.jsonl":
                    identity=(kind,record["record_id"])
                    if identity in identities:raise ValueError("Duplicate exported trace")
                    identities.add(identity)
                    if kind in ("application","outcome"):
                        target="decision" if kind=="application" else "application"
                        references.append((target,record["record"][target+"_id"]))
    if any(counts[k]!=v for k,v in manifest["record_counts"].items()):raise ValueError("Export record-count mismatch")
    missing=sum(ref not in identities for ref in references)
    if missing!=manifest["diagnostics"].get("unresolved_trace_references",0):raise ValueError("Export relationship diagnostic mismatch")
    deployments=json.loads((directory/"deployments.json").read_text(encoding="utf-8"))
    for identity,record in deployments.items():
        from deployment_manifest import canonical
        if record.get("image_inventory_digest") and hashlib.sha256(canonical(record["images"]).encode()).hexdigest()!=record["image_inventory_digest"]:
            raise ValueError("Image inventory checksum mismatch")
        base=dict(record);base.pop("manifest_id");base.pop("image_inventory_digest",None)
        base.update(images={},image_inventory_status="NOT_CAPTURED")
        if hashlib.sha256(canonical(base).encode()).hexdigest()!=identity:raise ValueError("Deployment manifest checksum mismatch")
    return {"valid":True,"record_counts":dict(counts),"unresolved_relationships":missing,
            "relationships_resolvable":missing==0,"collection_completeness":manifest["collection_completeness"]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--validate",type=Path)
    parser.add_argument("--base-url",default="http://127.0.0.1:8011")
    parser.add_argument("--traffic-origin",choices=("research_external","operator_validation","unknown","all"),default="research_external")
    parser.add_argument("--manifest-id")
    args=parser.parse_args()
    if args.validate:print(encoded(validate(args.validate)));return 0
    if args.output is None:parser.error("--output is required")
    info=export(args.base_url,args.output,args.traffic_origin,args.manifest_id,"http://127.0.0.1:8001")
    check=validate(args.output)
    # Acknowledge only after checksums/counts/relationship diagnostics validate.
    from configuration import load
    key=load()[3]["RESEARCH_OPERATOR_KEY"]
    request(args.base_url,"/evidence/research/export-ack",{"export_id":info["export_id"],"manifest_sha256":hashlib.sha256((args.output/"export-manifest.json").read_bytes()).hexdigest()},
        {"X-Research-Operator-Key":key})
    print(encoded({"export_id":info["export_id"],"output":str(args.output.resolve()),**check}))
    return 0


if __name__=="__main__":
    raise SystemExit(main())

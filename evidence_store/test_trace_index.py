"""Redis contract model tests; these do not execute Redis or Lua."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
import pytest
from strategy_traces import TraceStore, TraceConflict
from trace_index import index_keys, CAPACITY, PAGE_LIMIT, IndexIntegrityError, IndexCapacityError, WRITE
from test_strategy_traces import RedisDouble
from test_strategy_trace_endpoint import pair
from strategy_outcomes import evaluate
from indexed_aggregation import indexed_aggregate

SCOPE = dict(experiment_id="deterministic_baseline", experiment_version=1,
             scoring_profile_id="deterministic_components", scoring_profile_version=1)


def setup():
    redis = RedisDouble()
    return redis, TraceStore(redis, 3600)


def put(store, *, with_outcome=False, status="APPLIED", **context):
    p = pair()
    p["decision"].update(context)
    p["application"]["application_status"] = status
    for kind in ("decision", "application"):
        store.store(kind, p[kind])
    r = evaluate("s1", [p], [], closed_at="2026-10-30T00:00:10+00:00", as_of="2026-10-30T00:00:10+00:00")[0]
    if with_outcome: store.store("outcome", r)
    return p, r


def report(store, **scope):
    return indexed_aggregate(store, filters={**SCOPE, **scope}, generated_at="2026-10-30T01:00:00+00:00")


def expire(redis, kind, record):
    redis.values.pop(TraceStore.key(kind, record[kind+"_id"]))


def test_all_kinds_atomic_replay_conflict_and_ttl():
    redis, store = setup()
    p, r = put(store, with_outcome=True)
    initial = store.indexed_snapshot()
    assert initial["snapshot_max_sequence"] == 3
    for kind, record in ("decision",p["decision"]),("application",p["application"]),("outcome",r):
        entry = initial["kinds"][kind]["entries"][0]
        assert entry["record"] == record and entry["sequence"] > 0
        deadline = redis.expires[store.key(kind,record[kind+"_id"])]
        assert store.store(kind,deepcopy(record)) == "unchanged"
        assert redis.expires[store.key(kind,record[kind+"_id"])] == deadline
    with pytest.raises(TraceConflict):
        store.store("decision",{**p["decision"],"reason_code":"CHANGED"})
    assert store.indexed_snapshot() == initial
    other = {**p["decision"], "decision_id":str(uuid4())}
    store.store("decision",other)
    assert store.indexed_snapshot()["kinds"]["decision"]["retained_count"] == 2


@pytest.mark.parametrize("failure", ["before", "after"])
def test_atomic_failure_and_unknown_ack_recovery(failure):
    redis, store = setup(); d = pair()["decision"]
    redis.failure = failure
    with pytest.raises(ConnectionError): store.store("decision",d)
    redis.failure = None
    raw = store.get("decision",d["decision_id"])
    members = redis.zsets.get(index_keys()[1],{})
    assert (raw is not None) == (d["decision_id"] in members)
    store.store("decision",d)
    assert store.indexed_snapshot()["snapshot_max_sequence"] == 1
    # Explicitly test the designed single-EVAL write rather than SET-then-index.
    assert "redis.call('SET',KEYS[11]" in WRITE and "redis.call('ZADD',KEYS[base]" in WRITE


def test_concurrent_same_id_has_one_position():
    redis, store = setup(); d = pair()["decision"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _:store.store("decision",d),range(12)))
    assert results.count("inserted") == 1 and results.count("unchanged") == 11
    assert store.indexed_snapshot()["snapshot_max_sequence"] == 1


def test_snapshot_pagination_excludes_later_writes():
    redis, store = setup()
    ds = [pair()["decision"] for _ in range(5)]
    for d in ds: store.store("decision",d)
    first = store.list_records("decision",limit=2)
    maximum, epoch = first["snapshot_max_sequence"],first["index_epoch"]
    store.store("decision",pair()["decision"])
    entries = list(first["kinds"]["decision"]["entries"])
    page = first
    while not page["kinds"]["decision"]["done"]:
        page = store.list_records("decision",limit=2,
            after_sequence=page["kinds"]["decision"]["after_sequence"], snapshot_max_sequence=maximum,index_epoch=epoch)
        entries.extend(page["kinds"]["decision"]["entries"])
    assert [e["record"] for e in entries] == ds
    assert [e["sequence"] for e in entries] == list(range(1,6))
    for bad in (0,PAGE_LIMIT+1,True):
        with pytest.raises(ValueError): store.list_records("decision",limit=bad)


def test_expiry_cleanup_live_preservation_and_sequence_survival():
    redis, store = setup(); a,b = pair()["decision"],pair()["decision"]
    store.store("decision",a);store.store("decision",b)
    expire(redis,"decision",a)
    snapshot = store.indexed_snapshot()
    assert snapshot["stale_members_removed"] == 1
    assert [e["record"] for e in snapshot["kinds"]["decision"]["entries"]] == [b]
    assert a["decision_id"] not in redis.zsets[index_keys()[1]]
    redis.now += 3600001
    assert store.indexed_snapshot()["kinds"]["decision"]["retained_count"] == 0
    store.store("decision",a)
    assert store.indexed_snapshot()["snapshot_max_sequence"] == 3


def test_epoch_legacy_replay_and_remaining_ttl():
    redis, store = setup(); d = pair()["decision"]; key=store.key("decision",d["decision_id"])
    redis.values[key] = json.dumps(d,sort_keys=True,separators=(",", ":"))
    redis.expires[key] = redis.now+10000
    meta = store.activate_index()
    assert meta["index_version"]==1 and meta["historical_pre_index_coverage"]=="NOT_VERIFIED"
    assert store.indexed_snapshot()["kinds"]["decision"]["retained_count"]==0
    enabled=meta["index_enabled_at"];redis.now+=1000
    assert store.store("decision",d)=="unchanged"
    assert redis.expires[key]==1000000+10000
    assert store.indexed_snapshot()["kinds"]["decision"]["retained_count"]==1
    assert TraceStore(redis,3600).indexed_snapshot()["index_enabled_at"]==enabled
    with pytest.raises(IndexIntegrityError):
        store.indexed_snapshot(snapshot_max_sequence=1,index_epoch=str(uuid4()))


def test_capacity_rejects_without_record_or_sequence_and_corruption_fails_closed():
    redis, store = setup(); store.activate_index(); d=pair()["decision"]
    # Model a full valid sequence index without writing 1,000 records.
    redis.zsets[index_keys()[1]]={str(uuid4()):i for i in range(1,CAPACITY+1)}
    redis.zsets[index_keys()[2]]={i:redis.now+99999 for i in redis.zsets[index_keys()[1]]}
    redis.hashes[index_keys()[3]]={i:"{}" for i in redis.zsets[index_keys()[1]]}
    redis.hashes[index_keys()[0]]["sequence"]=str(CAPACITY)
    redis.hashes[index_keys()[0]]["decision_count"]=str(CAPACITY)
    with pytest.raises(IndexCapacityError):store.store("decision",d)
    assert store.get("decision",d["decision_id"]) is None
    assert redis.hashes[index_keys()[0]]["sequence"]==str(CAPACITY)
    redis.hashes[index_keys()[0]]["index_version"]="bad"
    with pytest.raises(IndexIntegrityError):store.indexed_snapshot()
    with pytest.raises(IndexIntegrityError):store.store("decision",d)


def test_three_applications_two_outcomes_and_readonly_determinism():
    redis, store=setup()
    put(store,with_outcome=True);put(store);put(store,with_outcome=True)
    before=deepcopy((redis.values,redis.hashes,redis.zsets,redis.expires))
    first=report(store)
    c=first["coverage"]
    assert (c["retained_applications"],c["applications_with_outcomes"],c["applications_without_outcomes"],c["outcome_coverage"])==(3,2,1,2/3)
    assert first["coverage_denominator_status"]=="AUTHORITATIVE_INDEXED_SCOPE"
    boundary=first["index_snapshot"]
    put(store,with_outcome=True)
    again=indexed_aggregate(store,filters=SCOPE,generated_at=first["generated_at"],
        snapshot_max_sequence=boundary["snapshot_max_sequence"],index_epoch=boundary["index_epoch"])
    assert again==first
    # Fresh reporting never changes any source/index content in the absence of stale entries.
    after_write=deepcopy((redis.values,redis.hashes,redis.zsets,redis.expires))
    report(store)
    assert (redis.values,redis.hashes,redis.zsets,redis.expires)==after_write
    assert before[0].items() <= redis.values.items()


def test_empty_population_and_required_scope():
    redis, store=setup();store.activate_index()
    r=report(store)
    assert r["coverage"]["outcome_coverage"] is None and r["retained_applications"]==0
    with pytest.raises(ValueError):indexed_aggregate(store,filters={"experiment_id":"deterministic_baseline"})


def test_profiles_experiments_strategies_digests_and_eligibility():
    redis, store=setup()
    put(store,with_outcome=True,strategy_id="D2")
    put(store,status="BLOCKED",strategy_id="D2")
    put(store,with_outcome=True,strategy_id="D4",experiment_version=2)
    put(store,strategy_id="D2",strategy_definition_digest="b"*64)
    r=report(store,strategy_id="D2")
    assert r["coverage"]["retained_applications"]==3
    assert r["coverage"]["eligible_retained_applications"]==2
    assert r["coverage"]["eligible_outcome_coverage"]==1/2
    assert len(r["per_strategy"])==2 and r["integrity_diagnostics"][0]["issue"]=="MULTIPLE_DEFINITION_DIGESTS"
    assert report(store,strategy_id="D4")["retained_applications"]==0
    assert report(store,experiment_version=2)["retained_applications"]==1
    assert report(store,scoring_profile_version=2)["coverage"]["applications_with_outcomes"]==0


def test_expired_outcome_application_and_decision_diagnostics():
    redis, store=setup();p,r=put(store,with_outcome=True)
    expire(redis,"outcome",r)
    assert report(store)["coverage"]["applications_without_outcomes"]==1
    store.store("outcome",r)
    expire(redis,"decision",p["decision"])
    result=report(store)
    assert result["retained_applications"]==1
    assert result["orphan_diagnostics"]["application_without_retained_decision"]==1
    # Replay of an indexed record remains unchanged even if its dependencies expired.
    assert store.store("application",p["application"])=="unchanged"
    expire(redis,"application",p["application"])
    result=report(store)
    assert result["retained_applications"]==0
    assert result["orphan_diagnostics"]["outcome_without_retained_application"]==1


def test_legacy_reference_is_diagnosed_without_claiming_history():
    redis, store=setup();p,r=put(store,with_outcome=True)
    identity=p["decision"]["decision_id"]
    for key in index_keys()[1:3]:redis.zsets[key].pop(identity)
    redis.hashes[index_keys()[3]].pop(identity)
    redis.hashes[index_keys()[0]]["decision_count"]="0"
    result=report(store)
    assert result["retained_applications"]==1
    assert result["orphan_diagnostics"]["record_without_index_detected"]==1
    assert result["historical_pre_index_coverage"]=="NOT_VERIFIED"


def test_endpoint_explicit_modes_and_bounded_pages():
    import main
    redis,store=setup();p,r=put(store,with_outcome=True)
    with patch.object(main,"require_runtime",return_value=SimpleNamespace(repository=SimpleNamespace(strategy_traces=lambda:store))):
        indexed=main.aggregate_strategy_outcomes({"population_mode":"INDEXED_RETAINED","filters":SCOPE})
        assert indexed["coverage_denominator_status"]=="AUTHORITATIVE_INDEXED_SCOPE"
        old=main.aggregate_strategy_outcomes({"outcome_ids":[r["outcome_id"]]})
        assert old["population"]=="EXPLICIT_RETAINED_OUTCOME_MANIFEST"
        assert main.list_strategy_traces({"kind":"application","limit":1})["kinds"]["application"]["retained_count"]==1
        for body in ({"kind":"application","limit":10000}, {"kind":"invalid"}):
            with pytest.raises(main.HTTPException) as exc:main.list_strategy_traces(body)
            assert exc.value.status_code==422
        redis.hashes[index_keys()[0]]["index_version"]="bad"
        with pytest.raises(main.HTTPException) as exc:main.aggregate_strategy_outcomes({"population_mode":"INDEXED_RETAINED","filters":SCOPE})
        assert exc.value.status_code==409


def test_expiry_between_pages_and_stale_expiry_metadata_never_deletes_live_trace():
    redis,store=setup()
    ds=[pair()["decision"] for _ in range(3)]
    for d in ds:store.store("decision",d)
    first=store.list_records("decision",limit=1)
    expire(redis,"decision",ds[1])
    second=store.list_records("decision",limit=2,after_sequence=1,
        snapshot_max_sequence=first["snapshot_max_sequence"],index_epoch=first["index_epoch"])
    assert [e["record"] for e in second["kinds"]["decision"]["entries"]]==[ds[2]]
    assert second["stale_members_removed"]==1 and second["kinds"]["decision"]["done"]
    redis.zsets[index_keys()[2]][ds[0]["decision_id"]]=redis.now-1
    store.store("decision",pair()["decision"])
    assert store.get("decision",ds[0]["decision_id"])==ds[0]


def test_lost_index_membership_fails_closed_and_never_deletes_trace():
    redis,store=setup();p,_=put(store)
    redis.zsets.pop(index_keys()[1])
    with pytest.raises(IndexIntegrityError):report(store)
    assert store.get("decision",p["decision"]["decision_id"])==p["decision"]


def test_operational_coverage_includes_ineligible_applications():
    redis,store=setup()
    put(store,with_outcome=True,status="BLOCKED")
    put(store)
    c=report(store)["coverage"]
    assert c["outcome_coverage"]==1/2 and c["eligible_outcome_coverage"]==0
    assert c["eligible_retained_applications"]==1


def test_capacity_is_retryable_at_ingestion_and_not_active_is_explicit():
    import main
    redis,store=setup()
    with pytest.raises(IndexIntegrityError,match="INDEX_NOT_ACTIVE"):report(store)
    with patch.object(main,"require_runtime",return_value=SimpleNamespace(repository=SimpleNamespace(strategy_traces=lambda:store))):
        with patch.object(store,"store",side_effect=IndexCapacityError()):
            with pytest.raises(main.HTTPException) as exc:main.store_strategy_trace(pair())
            assert exc.value.status_code==503
        with pytest.raises(main.HTTPException) as exc:main.list_strategy_traces({"kind":"all","limit":1000})
        assert exc.value.status_code==422

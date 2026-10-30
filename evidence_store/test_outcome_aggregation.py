from copy import deepcopy
import math
from uuid import uuid4
import pytest
from outcome_aggregation import aggregate
from strategy_outcomes import evaluate
from test_strategy_outcomes import pair,t


def outcome(value=None, **overrides):
    result=evaluate("s1",[pair()],[],closed_at=t(10),as_of=t(10))[0]
    result["raw_features"]["verified_followup_queries"]=value
    result["component_scores"]["engagement"]=None if value is None else min(value/20,1)
    result.update(overrides)
    return result


def test_empty_and_missing_vs_zero():
    empty=aggregate([],generated_at=t(10))
    assert empty["overall"]["outcome_count"]==0 and empty["per_strategy"]==[]
    assert empty["retained_store_outcome_coverage"] is None
    data=[outcome(None),outcome(0),outcome(2)]
    report=aggregate(data,generated_at=t(10))
    stats=report["per_strategy"][0]["all_outcomes"]["raw_features"]["verified_followup_queries"]
    assert (stats["n"],stats["missing_count"],stats["mean"],stats["median"])==(2,1,1,1)
    assert report["feature_observability"]["new_commitments"]["observed_count"]==0
    assert report["per_strategy"][0]["all_outcomes"]["raw_features"]["new_commitments"]["mean"] is None
    zero=aggregate([outcome(0),outcome(0)])["per_strategy"][0]["all_outcomes"]["raw_features"]["verified_followup_queries"]
    assert zero["mean"]==0 and zero["missing_count"]==0


@pytest.mark.parametrize("field,value",[("strategy_version",2),("strategy_definition_digest","b"*64),
    ("experiment_id","other"),("experiment_version",2),("scoring_profile_id","other"),("scoring_profile_version",2)])
def test_exact_group_identity(field,value):
    a,b=outcome(0),outcome(2,**{field:value})
    report=aggregate([a,b])
    assert len(report["per_strategy"])==2
    assert all(g["all_outcomes"]["outcome_count"]==1 for g in report["per_strategy"])
    if field=="strategy_definition_digest": assert report["integrity_diagnostics"]


def test_populations_booleans_and_termination():
    a=outcome(0,completeness="COMPLETE")
    b=outcome(20,application_status="BLOCKED",provenance_status="MISMATCH",effectiveness_eligible=False,completeness="INSUFFICIENT_EVIDENCE",termination_reason="MAX_EVENTS")
    b["raw_features"]["disconnect_observed"]=False
    c=outcome(None)
    c["raw_features"]["disconnect_observed"]=None
    report=aggregate([a,b,c])
    summary=report["per_strategy"][0]
    assert report["overall"]["eligible_count"]==2 and report["overall"]["ineligible_count"]==1
    assert report["overall"]["completeness_counts"]=={"COMPLETE":1,"PARTIAL":1,"INSUFFICIENT_EVIDENCE":1}
    assert summary["eligible_outcomes"]["component_scores"]["engagement"]["mean"]==0
    boolean=summary["all_outcomes"]["raw_features"]["disconnect_observed"]
    assert (boolean["observed_true"],boolean["observed_false"],boolean["missing_count"])==(1,1,1)
    assert report["overall"]["termination_counts"]["MAX_EVENTS"]==1


def test_determinism_duplicates_conflicts_and_readonly():
    a,b=outcome(0),outcome(2)
    before=deepcopy([a,b])
    report=aggregate([a,b,a],generated_at=t(10))
    shuffled=aggregate([b,a,a],generated_at=t(10))
    assert report==shuffled and [a,b]==before
    assert report["overall"]["outcome_count"]==2
    assert report["unique_manifest_records"]==2
    with pytest.raises(ValueError,match="Conflicting"):
        aggregate([a,{**a,"termination_reason":"MAX_EVENTS"}])
    assert report["retained_outcome_window_range"]=={"earliest_start":t(0),"latest_end":t(10)}
    for key in ("rank","winner","reward","best_strategy","recommended_strategy"):
        assert key not in report


def test_invalid_numeric_and_filters():
    for value in (math.nan,math.inf,-1,True,"2"):
        record=outcome()
        record["raw_features"]["verified_followup_queries"]=value
        with pytest.raises(ValueError): aggregate([record])
    with pytest.raises(ValueError): aggregate([outcome()],filters={"sql":"forbidden"})
    assert aggregate([outcome()],filters={"strategy_version":2})["overall"]["outcome_count"]==0


def test_endpoint_reads_only_persisted_records():
    from types import SimpleNamespace
    from unittest.mock import patch
    import test_evidence_store
    import main
    from strategy_traces import TraceStore
    from test_strategy_traces import RedisDouble
    from test_strategy_trace_endpoint import pair as valid_pair
    p=valid_pair(); p["decision"]["timestamp"]=t(0); p["application"]["timestamp"]=t(0)
    redis=RedisDouble();store=TraceStore(redis,3600)
    for kind in ("decision","application"): store.store(kind,p[kind])
    r=evaluate("s1",[p],[],closed_at=t(10),as_of=t(10))[0]
    store.store("outcome",r)
    before=deepcopy(redis.values)
    with patch.object(main,"require_runtime",return_value=SimpleNamespace(repository=SimpleNamespace(strategy_traces=lambda:store))):
        report=main.aggregate_strategy_outcomes({"outcome_ids":[r["outcome_id"]]})
        assert report["overall"]["outcome_count"]==1
        assert report["coverage_denominator_status"]=="DENOMINATOR_NOT_VERIFIED"
        assert redis.values==before
        with pytest.raises(main.HTTPException) as exc:main.aggregate_strategy_outcomes({"outcome_ids":[str(uuid4())]})
        assert exc.value.status_code==404

from copy import deepcopy
from uuid import uuid4
import pytest
from strategy_outcomes import evaluate
from strategy_traces import TraceStore, event_correlation
from outcome_aggregation import aggregate
from test_strategy_outcomes import pair,event,t


def linked_pair(at=0):
    p=pair(at)
    p["decision"].update(query_execution_id=str(uuid4()),request_started_at=t(at))
    return p


def producing(p,at):
    e=event(at)
    e.update(query_execution_id=p["decision"]["query_execution_id"],decision_id=p["decision"]["decision_id"],application_id=p["application"]["application_id"])
    return e


def followup(at):
    e=event(at)
    e["query_execution_id"]=str(uuid4())
    return e


def test_own_query_excluded_by_identity_and_same_sql_followups_counted():
    p=linked_pair(); own=producing(p,1)
    q2,q3=followup(2),followup(3)
    for e in (own,q2,q3): e["fingerprint"]="identical"
    result=evaluate("s1",[p],[own,q2,q3],closed_at=t(10),as_of=t(10),query_coverage=True,trace_coverage=True)[0]
    assert result["raw_features"]["followup_queries"]==2
    assert result["component_scores"]["engagement"]==2/20
    assert aggregate([result])["feature_observability"]["verified_followup_queries"]["observed_count"]==1


def test_next_application_boundary_and_historical_missing():
    a,b=linked_pair(0),linked_pair(5)
    evidence=[producing(a,1),followup(2),producing(b,6),followup(7)]
    results=evaluate("s1",[a,b],evidence,closed_at=t(10),as_of=t(10),query_coverage=True,trace_coverage=True)
    assert [r["raw_features"]["followup_queries"] for r in results]==[1,1]
    old=event(3)
    assert evaluate("s1",[a],evidence[:2]+[old],closed_at=t(4),as_of=t(10),query_coverage=True,trace_coverage=True)[0]["raw_features"]["followup_queries"] is None


def test_observed_zero_and_conflicting_linkage():
    p=linked_pair(); own=producing(p,1)
    result=evaluate("s1",[p],[own],closed_at=t(3),as_of=t(3),query_coverage=True,trace_coverage=True)[0]
    assert result["raw_features"]["followup_queries"]==0
    summary=aggregate([result])["per_strategy"][0]["all_outcomes"]["raw_features"]["followup_queries"]
    assert summary["mean"]==0 and summary["missing_count"]==0
    bad={**own,"query_execution_id":str(uuid4())}
    with pytest.raises(ValueError,match="correlation conflict"):
        evaluate("s1",[p],[bad],closed_at=t(3),as_of=t(3))


def test_ingestion_retains_without_synchronous_trace_lookup():
    import test_evidence_store
    from main import EvidenceRepository
    from test_evidence_store import MemoryRedis
    repository=EvidenceRepository(MemoryRedis())
    p=linked_pair(); e=producing(p,1)
    payload={**e,"query_raw":"select 1","query_normalized":"select 1","protocol":"postgres"}
    repository.ingest_kafka("pg-query-events",payload,0,1)
    retained=repository.get_session("s1")["queries"][0]
    assert retained["application_id"]==p["application"]["application_id"]
    assert retained["query_execution_id"]==p["decision"]["query_execution_id"]
    assert event_correlation({})=={}


@pytest.mark.parametrize("trace_first",[False,True])
def test_evidence_arrival_order_and_completed_zero(trace_first):
    from types import SimpleNamespace
    from unittest.mock import patch
    import test_evidence_store
    import main
    from test_strategy_trace_endpoint import pair as valid_pair
    from test_strategy_traces import RedisDouble
    p=valid_pair();p["decision"]["timestamp"]=t(0);p["application"]["timestamp"]=t(0)
    p["decision"].update(query_execution_id=str(uuid4()),request_started_at=t(0))
    repository=main.EvidenceRepository(test_evidence_store.MemoryRedis())
    store=TraceStore(RedisDouble(),3600)
    payload=dict(session_id="s1",timestamp=t(1),protocol="postgres",query_raw="select 1",query_normalized="select 1",
        **{k:p["decision"][k] for k in ("query_execution_id","request_started_at","decision_id")},
        application_id=p["application"]["application_id"],outcome_verified=True,success=True,authority="deception")
    def traces():
        for kind in ("decision","application"):store.store(kind,p[kind])
    if trace_first:traces()
    repository.ingest_kafka("pg-query-events",payload,0,1)
    if not trace_first:traces()
    retained=repository.get_session("s1")["queries"]
    snapshot=dict(queries=retained,connection_events=[dict(event_type="session_end",timestamp=t(5),query_count=1)])
    repo=SimpleNamespace(get_session=lambda sid:snapshot,strategy_traces=lambda:store)
    with patch.object(main,"require_runtime",return_value=SimpleNamespace(repository=repo)),patch.object(main,"utc_now",return_value=t(10)):
        result=main.evaluate_strategy_outcomes("s1",{"application_ids":[p["application"]["application_id"]]})
    assert result["outcomes"][0]["raw_features"]["followup_queries"]==0
    assert result["outcomes"][0]["completeness"]=="COMPLETE"

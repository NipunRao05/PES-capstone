from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from strategy_outcomes import evaluate, outcome_id, HORIZON_SECONDS
from strategy_traces import TraceStore, TraceConflict
from test_strategy_traces import RedisDouble

BASE = datetime(2026, 10, 30, tzinfo=timezone.utc)
def t(seconds): return (BASE + timedelta(seconds=seconds)).isoformat()
def pair(at=0, status="APPLIED", provenance="MATCH"):
    d = dict(schema_version=1, decision_id=str(uuid4()), timestamp=t(at), session_id="s1", principal_id=None,
        strategy_id="D2", strategy_version=1, strategy_definition_digest="a"*64,
        experiment_id="deterministic_baseline", experiment_version=1)
    a = dict(application_id=str(uuid4()), decision_id=d["decision_id"], timestamp=t(at), application_status=status, provenance_status=provenance)
    return {"decision": d, "application": a}
def event(at, sid="s1", **extra):
    return dict(event_id=str(uuid4()), session_id=sid, event_type="query", request_started_at=t(at), timestamp=t(at+0.1),
        response={"outcome_verified":True,"success":True,"authority":"deception"}, **extra)


def test_nonoverlap_order_dedupe_session_and_bounds():
    p1,p2=pair(1),pair(5)
    e1,e2=event(2),event(6)
    before=deepcopy([p1,p2,e1,e2])
    result=evaluate("s1",[p2,p1],[e2,e1,e1,event(0),event(3,"s2"),event(5)],closed_at=t(10),as_of=t(10),query_coverage=True,trace_coverage=True)
    assert [r["raw_features"]["followup_queries"] for r in result] == [1,1]
    assert result[0]["window_end"] == t(5)
    assert result[-1]["termination_reason"] == "SESSION_CLOSED"
    assert [p1,p2,e1,e2] == before
    assert result == evaluate("s1",[p1,p2],[e1,e2,event(0)],closed_at=t(10),as_of=t(10),query_coverage=True,trace_coverage=True)


def test_missing_is_not_zero_and_own_query_ambiguity():
    p=pair()
    zero=evaluate("s1",[p],[],closed_at=t(10),as_of=t(10),query_coverage=True,trace_coverage=True)[0]
    missing=evaluate("s1",[p],[],closed_at=t(10),as_of=t(10))[0]
    assert zero["raw_features"]["followup_queries"] == 0
    assert missing["raw_features"]["followup_queries"] is None
    e=event(1); e.pop("request_started_at")
    ambiguous=evaluate("s1",[p],[e],closed_at=t(10),as_of=t(10),query_coverage=True,trace_coverage=True)[0]
    assert ambiguous["component_scores"]["engagement"] is None


@pytest.mark.parametrize("status,provenance,eligible",[("APPLIED","MATCH",True),("BLOCKED","MISMATCH",False),("ERROR","MATCH",False),("APPLIED","MISMATCH",False),("NOT_VERIFIED","NOT_VERIFIED",False)])
def test_application_eligibility(status,provenance,eligible):
    result=evaluate("s1",[pair(status=status,provenance=provenance)],[],closed_at=t(1),as_of=t(1))[0]
    assert result["effectiveness_eligible"] is eligible


def test_verified_trap_and_separate_components():
    visible=event(1,is_trap=True,deception_profile="fake_schema")
    actual=event(2,is_trap=True,deception_profile="high_value_target")
    unverified=event(3,is_trap=True,deception_profile="high_value_target"); unverified["response"]["outcome_verified"]=False
    error=event(4); error["response"]["success"]=False
    r=evaluate("s1",[pair()],[visible,actual,unverified,error],closed_at=t(5),as_of=t(5),query_coverage=True,trace_coverage=True)[0]
    assert r["raw_features"]["verified_trap_interactions"] == 1
    assert r["raw_features"]["verified_errors"] == 1
    assert r["component_scores"]["engagement"] == 3/20
    assert "reward" not in r and r["raw_features"]["new_commitments"] is None


def test_horizon_active_and_profile_identity():
    p=pair()
    assert evaluate("s1",[p],[],as_of=t(10)) == []
    result=evaluate("s1",[p],[],as_of=t(HORIZON_SECONDS))[0]
    assert result["termination_reason"] == "MAX_DURATION" and result["completeness"] == "PARTIAL"
    assert outcome_id(p["application"]["application_id"],2) != result["outcome_id"]


def test_event_bound_and_conflicting_duplicate():
    events=[event(i+1) for i in range(110)]
    result=evaluate("s1",[pair()],events,closed_at=t(200),as_of=t(200),query_coverage=True,trace_coverage=True)[0]
    assert result["termination_reason"] == "MAX_EVENTS"
    assert result["raw_features"]["followup_queries"] <= 100
    assert result["component_scores"]["engagement"] == 1
    duplicate={**events[0],"timestamp":t(99)}
    with pytest.raises(ValueError,match="Conflicting duplicate"):
        evaluate("s1",[pair()],[events[0],duplicate],closed_at=t(200),as_of=t(200))


def test_outcome_storage_replay_and_late_conflict():
    from test_strategy_trace_endpoint import pair as valid_pair
    p=valid_pair(); p["decision"]["timestamp"]=t(0); p["application"]["timestamp"]=t(0)
    store=TraceStore(RedisDouble(),3600)
    for kind in ("decision","application"): store.store(kind,p[kind])
    r=evaluate("s1",[p],[],closed_at=t(5),as_of=t(5))[0]
    assert store.store("outcome",r)=="inserted"
    assert store.store("outcome",r)=="unchanged"
    with pytest.raises(TraceConflict): store.store("outcome",{**r,"termination_reason":"CHANGED"})
    assert store.get("outcome",r["outcome_id"])==r


def test_completed_evidence_endpoint_replay_and_scope():
    from types import SimpleNamespace
    from unittest.mock import patch
    from test_strategy_trace_endpoint import pair as valid_pair
    import main
    p=valid_pair(); p["decision"]["timestamp"]=t(0); p["application"]["timestamp"]=t(0)
    store=TraceStore(RedisDouble(),3600)
    for kind in ("decision","application"): store.store(kind,p[kind])
    repository=SimpleNamespace(strategy_traces=lambda:store,get_session=lambda sid:dict(queries=[],connection_events=[dict(event_type="session_end",timestamp=t(5))]))
    body={"application_ids":[p["application"]["application_id"]]}
    with patch.object(main,"require_runtime",return_value=SimpleNamespace(repository=repository)),patch.object(main,"utc_now",return_value=t(10)):
        first=main.evaluate_strategy_outcomes("s1",body)
        again=main.evaluate_strategy_outcomes("s1",body)
        assert first["records"][0]["stored"]=="inserted"
        assert again["records"][0]["stored"]=="unchanged"
        assert first["outcomes"][0]["completeness"]=="PARTIAL"
        with pytest.raises(main.HTTPException) as exc: main.evaluate_strategy_outcomes("different",body)
        assert exc.value.status_code==422

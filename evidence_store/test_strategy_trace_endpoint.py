from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
import pytest
import test_evidence_store  # Reuse the service suite's optional-dependency stubs.
import main
from strategy_traces import FIELDS, TraceStore
from test_strategy_traces import RedisDouble


def pair():
    d = dict(schema_version=1, decision_id=str(uuid4()), timestamp="2026-10-30T00:00:00+00:00",
        experiment_id="deterministic_baseline", experiment_version=1, mode="deterministic_rule_based",
        active=True, session_id="s1", principal_id=None, protocol="postgres", strategy_id="D0",
        strategy_version=1, strategy_definition_digest="a" * 64, expected_action_binding="baseline_response",
        approval_status="APPROVED", eligibility={"eligible": True, "reason": "APPROVED"},
        reason_code="RULE_D0", state_before=dict(transaction_state="idle", exposure_depth=1,
            commitment_scope="unavailable", commitment_set_digest=None, evaluated_commitments=[]))
    a = dict(schema_version=1, application_id=str(uuid4()), decision_id=d["decision_id"],
        timestamp=d["timestamp"], expected_action_binding="baseline_response", actual_action_binding="baseline_response",
        provenance_status="MATCH", application_status="APPLIED", result_class="fake")
    return {"decision": d, "application": a}


def test_ingestion_order_replay_and_conflict():
    store = TraceStore(RedisDouble(), 3600)
    runtime = SimpleNamespace(repository=SimpleNamespace(strategy_traces=lambda: store))
    data = pair()
    with patch.object(main, "require_runtime", return_value=runtime):
        assert main.store_strategy_trace(data) == {"decision": "inserted", "application": "inserted"}
        assert main.store_strategy_trace(data) == {"decision": "unchanged", "application": "unchanged"}
        data["decision"]["reason_code"] = "CHANGED"
        with pytest.raises(main.HTTPException) as exc:
            main.store_strategy_trace(data)
        assert exc.value.status_code == 409


def test_ingestion_rejects_extra_state_without_writes():
    redis = RedisDouble()
    store = TraceStore(redis, 3600)
    data = pair()
    data["decision"]["state_before"]["sql"] = "not permitted"
    with patch.object(main, "require_runtime", return_value=SimpleNamespace(repository=SimpleNamespace(strategy_traces=lambda: store))):
        with pytest.raises(main.HTTPException) as exc:
            main.store_strategy_trace(data)
    assert exc.value.status_code == 422
    assert redis.values == {}

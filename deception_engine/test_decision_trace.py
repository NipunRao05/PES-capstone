from copy import deepcopy
import pytest
from action_provenance import verify_action
from decision_trace import begin, applied, experiment
from strategy_registry import StrategyRegistry


def decision(registry, record=None):
    return begin(registry, "D2", session_id="session_1", protocol="postgres",
        transaction_state="idle", exposure_depth=3, principal_record=record)


def test_definition_context_and_read_only():
    registry = StrategyRegistry.load()
    before_registry = registry.to_dict()
    record = {"principal_id": "DP-example", "persistent_mutations": {"secret": "excluded"}}
    before = deepcopy(record)
    d = decision(registry, record)
    assert d["strategy_definition_digest"] == registry.get("D2", 1).definition_digest()
    assert d["experiment_id"] == "deterministic_baseline"
    assert "excluded" not in str(d)
    assert record == before and registry.to_dict() == before_registry
    assert decision(registry)["decision_id"] != d["decision_id"]
    assert decision(registry)["state_before"]["commitment_set_digest"] is None


@pytest.mark.parametrize("actual,status", [("backup_asset_read", "APPLIED"),
    ("catalog_response", "APPLIED"), ("policy_rejection", "BLOCKED"),
    ("statement_error", "ERROR"), (None, "NOT_VERIFIED")])
def test_application_keeps_provenance_distinct(actual, status):
    registry = StrategyRegistry.load()
    d = decision(registry)
    provenance = verify_action(registry.get("D2"), actual)
    result = applied(d, provenance, result_mode="fake" if status == "APPLIED" else "block")
    assert result["decision_id"] == d["decision_id"]
    assert result["application_status"] == status
    assert result["provenance_status"] == provenance.status


def test_unknown_experiment_and_unapproved_selection():
    with pytest.raises(ValueError):
        experiment("unknown")
    with pytest.raises(ValueError):
        begin(StrategyRegistry.load(), "D5", session_id="s1", protocol="mysql",
              transaction_state="idle", exposure_depth=1)

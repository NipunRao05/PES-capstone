import copy
import pytest
from strategy_registry import StrategyRegistry, RegistryValidationError
from world_commitments import Commitments, Fact, FIELD


def fixture():
    raw = StrategyRegistry.load().to_dict()
    raw["strategies"][1]["commitment_preconditions"] = [dict(op="requires", namespace="relation", subject="testdb.employees", property="exists", value=True)]
    return raw


def test_registry_versions_approval_and_fallback():
    reg = StrategyRegistry.load()
    assert reg.get("D2", 1).strategy_version == 1
    assert reg.get("D2", 2) is None
    assert reg.eligibility("D999", 1, "postgres", {}) == (False, "UNKNOWN_STRATEGY")
    assert reg.eligibility("D2", 2, "postgres", {}) == (False, "UNKNOWN_VERSION")
    assert reg.eligibility("D5", 1, "postgres", {}) == (False, "NOT_APPROVED")
    assert reg.eligibility("D0", 1, "mysql", {}) == (True, "APPROVED")
    assert reg.resolve("D5").strategy_id == "D0"
    assert reg.strategy_for_asset("hr", "api_keys_backup").strategy_id == "D2"


def test_preconditions_are_read_only_and_survive_roundtrip():
    reg = StrategyRegistry.from_dict(fixture())
    fact = Fact("relation", "testdb.employees", "exists", True)
    for value, expected in [(None, "PRECONDITION_MISSING"), (False, "PRECONDITION_MISMATCH"), (True, "APPROVED")]:
        model = Commitments({})
        if value is not None:
            model.commit(Fact(fact.namespace, fact.subject, fact.property, value), session_id="s1", timestamp="2026-10-28T12:00:00+00:00")
        record = {FIELD: model.serialize()}
        before = copy.deepcopy(record)
        assert reg.eligibility("D1", 1, "postgres", record)[1] == expected
        assert record == before
        assert reg.eligibility("D1", 1, "postgres", copy.deepcopy(record))[1] == expected
    assert reg.eligibility("D1", 1, "postgres", {FIELD: None}) == (False, "INVALID_COMMITMENTS")


def test_legacy_and_invalid_definitions():
    raw = fixture()
    for item in raw["strategies"]:
        for field in ("strategy_version", "implementation", "commitment_preconditions"):
            item.pop(field)
    assert StrategyRegistry.from_dict(raw).get("D1").strategy_version == 1
    raw["strategies"].append(copy.deepcopy(raw["strategies"][0]))
    with pytest.raises(RegistryValidationError):
        StrategyRegistry.from_dict(raw)
    raw = fixture()
    raw["strategies"][1]["commitment_preconditions"][0]["op"] = "eval"
    with pytest.raises(RegistryValidationError):
        StrategyRegistry.from_dict(raw)

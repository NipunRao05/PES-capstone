import asyncio
import json
from dataclasses import replace
from unittest.mock import MagicMock, patch
import pytest
import api
import test_principal_state as lifecycle
from action_provenance import verify_action
from models import DecisionResponse
from strategy_registry import StrategyRegistry


@pytest.fixture
def state():
    fixture = lifecycle.PrincipalLifecycleTests()
    fixture.setUp()
    try:
        fixture.f.redis.hset("exposure:s1", mapping={"depth": 3})
        yield fixture
    finally:
        fixture.doCleanups()


@pytest.mark.parametrize("sql,action", [
    ("select version()", "baseline_response"),
    ("show tables", "catalog_response"),
    ("select id from api_keys_backup", "backup_asset_read"),
    ("select id from prod_credentials", "credential_asset_read"),
    ("select id from employees", "sensitive_asset_read"),
    ("delete from employees where id = 1", "managed_mutation"),
    ("select count(*) from employees", "sensitive_asset_read"),
])
@pytest.mark.parametrize("protocol", ["postgres", "mysql"])
def test_actual_producers(state, sql, action, protocol):
    response = asyncio.run(api.decide(MagicMock(), dict(session_id="s1",
        query_raw=sql, query_normalized=sql, protocol=protocol, database="testdb",
        username="fake_compro1", deception_level=1)))
    assert response.action_provenance.actual == action
    assert response.action_provenance.status == "MATCH"
    payload = json.loads(response.body)
    assert "action_provenance" not in payload and "producer_action" not in payload


def test_consistency_missing_mismatch_and_payload_preservation():
    registry = StrategyRegistry.load()
    expected = registry.get("D2")
    assert verify_action(expected, "backup_asset_read").status == "MATCH"
    assert verify_action(expected, "catalog_response").status == "MISMATCH"
    assert verify_action(expected, None).status == "NOT_VERIFIED"
    assert verify_action(expected, "arbitrary").status == "INVALID_ACTION"
    response = DecisionResponse(mode="fake", rows=[{"id": 1}], strategy_id="D2")
    old = api._json_response(replace(response))
    current = api._json_response(replace(response), producer_action="catalog_response")
    assert old.body == current.body
    assert current.action_provenance.status == "MISMATCH"


def test_denied_read_does_not_claim_lure(state):
    state.f.redis.hset("exposure:s1", mapping={"depth": 1})
    response = asyncio.run(api.decide(MagicMock(), dict(session_id="s1",
        query_raw="select id from api_keys_backup", query_normalized="select id from api_keys_backup",
        protocol="postgres", database="testdb", username="fake_compro1", deception_level=1)))
    assert json.loads(response.body)["mode"] == "block"
    assert response.action_provenance.actual == "policy_rejection"


def test_producer_does_not_copy_expected_binding(state):
    raw = StrategyRegistry.load().to_dict()
    raw["strategies"][2]["action_binding"] = "credential_asset_read"
    with patch.object(api, "_strategy_registry", StrategyRegistry.from_dict(raw)):
        response = asyncio.run(api.decide(MagicMock(), dict(session_id="s1",
            query_raw="select id from api_keys_backup", query_normalized="select id from api_keys_backup",
            protocol="postgres", database="testdb", username="fake_compro1", deception_level=1)))
    assert response.action_provenance.actual == "backup_asset_read"
    assert response.action_provenance.expected == "credential_asset_read"
    assert response.action_provenance.status == "MISMATCH"
    assert json.loads(response.body)["mode"] == "fake"

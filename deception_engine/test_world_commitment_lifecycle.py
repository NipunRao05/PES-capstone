"""Principal integration using actual decision/observe routes and in-memory Redis.

Socket write ordering is tested separately in both proxy protocol packages.
"""
import asyncio
import time
from unittest.mock import patch
import httpx
import pytest
import principal_runtime
import test_principal_state as lifecycle
from principal_registry import PrincipalRegistry
from world_commitments import Commitments, Fact, FIELD


@pytest.fixture
def principal():
    state = lifecycle.PrincipalLifecycleTests()
    state.setUp()
    try:
        yield state
    finally:
        state.doCleanups()


def observe(state, sid, candidates, secret=None):
    async def post():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=state.app), base_url="http://test") as client:
            return await client.post("/principals/observe", json={
                "session_id": sid, "deadline_ms": time.time() * 1000 + 2500,
                "observation_candidates": candidates,
            }, headers={"X-Deceptive-Principal-Key": state.f.secret if secret is None else secret})
    with patch.object(principal_runtime.redis, "Redis", return_value=state.f.redis), \
         patch.object(principal_runtime, "PrincipalRegistry", return_value=state.f.reg):
        return asyncio.run(post())


@pytest.mark.parametrize("protocol", ["postgres", "mysql"])
def test_exposure_receipt_reconnect_and_serialized_reload(principal, protocol):
    sid = principal.prepare(protocol)
    before = principal.record(protocol)
    assert Commitments(before).list() == []
    result = principal.f.q("select id from employees where id = 1", sid)
    assert result["rows"] == [{"id": 1}]
    assert result["observation_candidates"] == ["testdb.employees"]
    assert FIELD not in principal.record(protocol)  # construction is not exposure
    assert observe(principal, sid, result["observation_candidates"]).json() == {
        "status": "ok", "inserted": 1, "conflicts": 0}
    first = principal.record(protocol)[FIELD]
    principal.end(sid)
    principal.login(protocol, "returning")
    assert principal.record(protocol)[FIELD] == first
    again = principal.f.q("select id from employees where id = 1", "returning")
    assert again["rows"] == result["rows"] and again["columns"] == result["columns"]
    assert observe(principal, "returning", again["observation_candidates"]).json()["inserted"] == 0
    assert principal.record(protocol)[FIELD] == first
    reloaded = PrincipalRegistry(principal.f.redis, secret=principal.f.secret).load(principal.f.reg.key(protocol, "fake_compro1"))
    assert Commitments(reloaded).serialize() == first
    after = principal.record(protocol)
    for field in ("principal_id", "principal_key", "verifier", "persistent_permissions", "persistent_mutations", "world_revision"):
        assert after[field] == before[field]


@pytest.mark.parametrize("protocol", ["postgres", "mysql"])
@pytest.mark.parametrize("ending", ["rollback", "commit", "disconnect"])
def test_observation_survives_transaction_end_and_failed_postgres(principal, protocol, ending):
    sid = principal.prepare(protocol)
    q = lambda sql: principal.f.q(sql, sid)
    q("begin")
    q("update employees set salary = 12345 where id = 1")
    response = q("select id from employees where id = 1")
    observe(principal, sid, response["observation_candidates"])
    facts = principal.record(protocol)[FIELD]
    assert principal.record(protocol)["world_revision"] == 0
    if protocol == "postgres":
        assert q("select missing_column from employees")["tx_status"] == "E"
        assert q("select id from employees")["sqlstate"] == "25P02"
    if ending != "disconnect":
        result = q(ending)
        if protocol == "postgres" or ending == "rollback":
            assert result["command_tag"] == "ROLLBACK"
    principal.end(sid)
    principal.login(protocol, "s2")
    assert principal.record(protocol)[FIELD] == facts
    if protocol == "postgres" or ending != "commit":
        assert principal.record(protocol)["persistent_mutations"] == {}


@pytest.mark.parametrize("protocol", ["postgres", "mysql"])
def test_receipt_does_not_invalidate_pending_commit_or_erase_other_facts(principal, protocol):
    sid = principal.prepare(protocol)
    principal.f.q("begin", sid)
    principal.f.q("update employees set salary = 12345 where id = 1", sid)
    principal.login(protocol, "other")
    other = principal.f.q("select id from departments limit 1", "other")
    observe(principal, "other", other["observation_candidates"])
    assert principal.f.q("commit", sid)["command_tag"] == "COMMIT"
    assert Commitments(principal.record(protocol)).has(Fact("relation", "testdb.departments", "exists", True))
    # Existing optimistic row conflict still rejects a stale transaction; the
    # fresh record's observations cannot be lost on that early-return path.
    principal.f.q("begin", sid)
    principal.f.q("update employees set salary = 67890 where id = 1", "other")
    observe(principal, "other", ["testdb.employees"])
    assert principal.f.q("commit", sid)["sqlstate"] == "40001"
    assert len(Commitments(principal.record(protocol)).list()) == 2


def test_contradiction_is_internal_and_does_not_rewrite_response(principal):
    sid = principal.prepare("postgres")
    result = principal.f.q("select id from employees where id = 1", sid)
    observe(principal, sid, result["observation_candidates"])
    model = Commitments(principal.record("postgres"))
    before = model.serialize()
    assert model.commit(Fact("relation", "testdb.employees", "exists", False),
        session_id=sid, timestamp="2026-10-28T12:00:00+00:00") == "conflict"
    assert model.serialize() == before
    again = principal.f.q("select id from employees where id = 1", sid)
    for field in ("rows", "columns", "column_types", "mode", "tx_status"):
        assert again[field] == result[field]


def test_receipt_security_rejections_and_no_candidates_on_errors(principal):
    sid = principal.prepare("postgres")
    assert observe(principal, sid, ["testdb.employees"], secret="wrong").status_code == 403
    for candidates in ([], ["testdb.unknown"], ["testdb.employees"] * 9):
        assert observe(principal, sid, candidates).json()["mode"] == "block"
    assert FIELD not in principal.record("postgres")
    for sql in ("select missing_column from employees", "select id from unknown_table", "begin", "rollback"):
        assert "observation_candidates" not in principal.f.q(sql, sid)


def test_protocol_principal_isolation(principal):
    mysql_sid = principal.prepare("mysql")
    pg_sid = principal.prepare("postgres")
    observe(principal, mysql_sid, principal.f.q("select id from employees", mysql_sid)["observation_candidates"])
    assert Commitments(principal.record("mysql")).list()
    assert Commitments(principal.record("postgres")).list() == []


def test_empty_result_exposes_table_but_receipt_storage_failure_is_internal(principal):
    sid = principal.prepare("postgres")
    response = principal.f.q("select id from employees where id = 999999", sid)
    assert response["rows"] == [] and response["observation_candidates"] == ["testdb.employees"]
    with patch.object(principal.f.reg, "save", side_effect=RuntimeError("unavailable")):
        assert observe(principal, sid, response["observation_candidates"]).status_code == 503
    assert FIELD not in principal.record("postgres")
    assert principal.f.q("select id from employees", sid)["tx_status"] == "I"
    assert not principal.binding(sid)["failed"]

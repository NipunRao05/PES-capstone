"""Pass 3: PostgreSQL statement-error transitions, using Pass 2 fixtures."""
import asyncio
from unittest.mock import MagicMock
from unittest.mock import patch, AsyncMock

import pytest

import principal_runtime
import test_principal_state as lifecycle
from fastapi import HTTPException
from principal_registry import PrincipalError


@pytest.fixture
def principal():
    state = lifecycle.PrincipalLifecycleTests()
    state.setUp()
    try:
        yield state
    finally:
        state.doCleanups()


@pytest.mark.parametrize("active", [False, True], ids=["idle", "active"])
@pytest.mark.parametrize("sql,code", [
    ("select missing_column from employees", "42703"),
    ("select id from api_keys_backup", "42P01"),
    ("update employees set salary = 1", "42601"),
    ("create table denied (id int)", "42501"),
    ("select id from unknown_table", "0A000"),
    ("select id from employees; select 1", "42601"),
])
def test_postgres_statement_error_state(principal, active, sql, code):
    sid = principal.prepare("postgres")
    f = principal.f
    if active:
        f.q("begin", sid)
    before = principal.record("postgres")
    result = f.q(sql, sid)
    assert (result["mode"], result["sqlstate"]) == ("block", code)
    assert result["tx_status"] == ("E" if active else "I")
    assert principal.binding(sid)["failed"] is active
    assert principal.record("postgres")["persistent_mutations"] == before["persistent_mutations"]
    assert principal.record("postgres")["world_revision"] == before["world_revision"]


@pytest.mark.parametrize("ending", ["commit", "rollback", "disconnect"])
@pytest.mark.parametrize("invalid", ["select missing_column from employees",
                                    "select id from employees; select 1"])
def test_pending_failure_finalization_and_fresh_session(principal, ending, invalid):
    sid = principal.prepare("postgres")
    f = principal.f
    baseline = f.q("select salary from employees where id = 1", sid)["rows"]
    committed = principal.record("postgres")["persistent_mutations"]
    f.q("begin", sid)
    f.q("update employees set salary = 12345 where id = 1", sid)
    assert f.q(invalid, sid)["tx_status"] == "E"
    assert principal.binding(sid)["mutation_keys"]
    assert f.q("select id from employees", sid)["sqlstate"] == "25P02"
    if ending != "disconnect":
        result = f.q(ending, sid)
        assert (result["command_tag"], result["tx_status"]) == ("ROLLBACK", "I")
        assert principal.binding(sid)["mutation_keys"] == []
        assert not principal.binding(sid)["failed"]
        assert f.redis.get("mutation-tx:" + sid) is None
        f.q("begin", sid)
        assert principal.binding(sid)["tx"]
        f.q("rollback", sid)
    principal.end(sid)
    assert principal.record("postgres")["persistent_mutations"] == committed
    principal.login("postgres", "fresh")
    assert f.q("select salary from employees where id = 1", "fresh")["rows"] == baseline
    assert not principal.binding("fresh")["failed"]


def test_proxy_observed_failure_prevents_principal_commit(principal):
    """A local proxy error can precede a healthy Redis binding (e.g. Parse reject)."""
    sid = principal.prepare("postgres")
    f = principal.f
    f.q("begin", sid)
    f.q("update employees set salary = 12345 where id = 1", sid)
    result = asyncio.run(principal_runtime.query(f.reg, lifecycle.api, MagicMock(), {
        "session_id": sid, "sql": "COMMIT", "transaction_state": "failed_transaction",
    }))
    assert (result["command_tag"], result["tx_status"]) == ("ROLLBACK", "I")
    assert principal.record("postgres")["persistent_mutations"] == {}


def test_mysql_malformed_statement_preserves_existing_active_state(principal):
    sid = principal.prepare("mysql")
    f = principal.f
    f.q("begin", sid)
    with pytest.raises(PrincipalError):
        f.q("select id from employees; select 1", sid)
    assert not principal.binding(sid)["failed"]
    assert f.q("select id from employees", sid)["tx_status"] == "T"
    result = asyncio.run(principal_runtime.query(f.reg, lifecycle.api, MagicMock(), {
        "session_id": sid, "sql": "select id from employees", "transaction_state": "failed_transaction",
    }))
    assert result["tx_status"] == "T"
    assert not principal.binding(sid)["failed"]


def test_postgres_decision_http_failure_marks_existing_transaction_failed(principal):
    sid = principal.prepare("postgres")
    f = principal.f
    f.q("begin", sid)
    f.q("update employees set salary = 12345 where id = 1", sid)
    with patch.object(lifecycle.api, "decide", new=AsyncMock(side_effect=HTTPException(429, "limited"))):
        with pytest.raises(HTTPException):
            f.q("select id from employees", sid)
    assert principal.binding(sid)["failed"]
    assert f.q("commit", sid)["command_tag"] == "ROLLBACK"
    assert principal.record("postgres")["persistent_mutations"] == {}


def test_postgres_overlay_limit_failure_cannot_be_retried_as_commit(principal):
    sid = principal.prepare("postgres")
    f = principal.f
    f.q("begin", sid)
    lifecycle.api._mutations.record_insert(sid, "employees", {"payload": "x" * (1024 * 1024)}, transaction_active=True)
    with pytest.raises(PrincipalError) as failure:
        f.q("commit", sid)
    assert failure.value.state == "54000"
    assert principal.binding(sid)["failed"]
    assert principal.record("postgres")["persistent_mutations"] == {}
    assert f.q("commit", sid)["command_tag"] == "ROLLBACK"

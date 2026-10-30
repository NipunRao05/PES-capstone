import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from trace_outbox import Outbox, ENQUEUE, UPDATE, PRUNE, RETENTION, MAX_ATTEMPTS
from decision_trace import begin, applied
from action_provenance import verify_action
from strategy_registry import StrategyRegistry
from test_live_trace import storage, RedisDouble
from test_action_provenance import state


class RedisModel:
    """Atomic-script contract double; not a Redis/Lua execution test."""
    def __init__(self): self.entries, self.due, self.expiry = {}, {}, {}
    def hget(self, key, identity): return self.entries.get(identity)
    def zrangebyscore(self, key, low, high, start, num):
        return sorted([i for i, score in self.due.items() if score <= high], key=self.due.get)[start:start+num]
    def eval(self, script, count, *args):
        a = args[3:]
        if script in {PRUNE, ENQUEUE}:
            expired = [i for i, when in self.expiry.items() if when <= a[0]]
            for i in expired:
                self.entries.pop(i, None); self.due.pop(i, None); self.expiry.pop(i, None)
            if script == PRUNE: return len(expired)
            now, identity, raw, expires, capacity = a
            if identity in self.entries: return self.entries[identity]
            if len(self.entries) >= capacity: return "FULL"
            self.entries[identity], self.due[identity], self.expiry[identity] = raw, now, expires
            return "INSERTED"
        assert script == UPDATE
        identity, old, status, raw, when = a
        if self.entries.get(identity) != old: return 0
        if status == "DELIVERED":
            self.entries.pop(identity); self.due.pop(identity, None); self.expiry.pop(identity, None)
        else:
            self.entries[identity] = raw
            if status == "RETRY_PENDING": self.due[identity] = when
            else: self.due.pop(identity, None)
        return 1


def pair():
    registry = StrategyRegistry.load()
    decision = begin(registry, "D0", session_id="s1", protocol="postgres", transaction_state="idle", exposure_depth=1)
    return {"decision": decision, "application": applied(decision, verify_action(registry.get("D0"), "baseline_response"), result_mode="fake")}


def ack(code=200, result="inserted"):
    return SimpleNamespace(status_code=code, json=lambda: {"decision": result, "application": result})


def test_durable_before_send_recreation_and_capacity():
    redis = RedisModel()
    box = Outbox(redis, clock=lambda: 0, capacity=1)
    p = pair()
    assert box.enqueue(p) == "DURABLE_PENDING"
    assert json.loads(next(iter(redis.entries.values())))["pair"] == p
    assert box.enqueue(pair()) == "FULL"
    assert box.enqueue(deepcopy(p)) == "DURABLE_PENDING"
    recovered = Outbox(redis, clock=lambda: 0)
    def send(value):
        assert redis.entries and value == p
        return ack()
    assert recovered.step(send) == "DELIVERED"
    assert not redis.entries


@pytest.mark.parametrize("code,expected", [(500,"RETRY_PENDING"), (429,"RETRY_PENDING"),
    (400,"PERMANENT_FAILURE"), (422,"PERMANENT_FAILURE"), (409,"CONFLICT")])
def test_classification(code, expected):
    redis = RedisModel(); now = [0]
    box = Outbox(redis, clock=lambda: now[0]); box.enqueue(pair())
    assert box.step(lambda _: ack(code)) == expected
    record = json.loads(next(iter(redis.entries.values())))
    assert record["attempt_count"] == 1
    if expected == "RETRY_PENDING":
        assert box.step(lambda _: pytest.fail("tight retry")) == "IDLE"
        now[0] = 2
        assert box.step(lambda _: ack(result="unchanged")) == "DELIVERED"
    else: assert not redis.due


@pytest.mark.parametrize("partial", [False, True])
def test_lost_ack_and_partial_pair_recover_without_new_ids(partial):
    redis = RedisModel(); now = [0]
    box = Outbox(redis, clock=lambda: now[0]); p = pair(); original = deepcopy(p)
    receiver = storage.TraceStore(RedisDouble(), 3600)
    box.enqueue(p)
    def failed_send(value):
        receiver.store("decision", value["decision"])
        if not partial: receiver.store("application", value["application"])
        raise TimeoutError()
    assert box.step(failed_send) == "RETRY_PENDING"
    now[0] = 2
    def retry(value):
        assert value == original
        result = {kind: receiver.store(kind, value[kind]) for kind in ("decision", "application")}
        assert result["decision"] == "unchanged"
        return SimpleNamespace(status_code=200, json=lambda: result)
    assert Outbox(redis, clock=lambda: now[0]).step(retry) == "DELIVERED"
    assert receiver.get("application", p["application"]["application_id"]) == p["application"]


def test_terminal_capacity_expiry_and_no_overwrite():
    redis = RedisModel(); now = [0]
    box = Outbox(redis, clock=lambda: now[0], capacity=1)
    p = pair(); box.enqueue(p)
    changed = deepcopy(p); changed["decision"]["reason_code"] = "changed"
    assert box.enqueue(changed) == "CONFLICT"
    box.step(lambda _: ack(409))
    assert box.enqueue(p) == "CONFLICT"
    assert box.enqueue(pair()) == "FULL"
    now[0] = RETENTION
    assert box.step(lambda _: pytest.fail("expired entry sent")) == "IDLE"
    assert not redis.entries


def test_shutdown_leaves_pending_for_next_worker():
    from live_trace import Emitter
    redis = RedisModel(); box = Outbox(redis)
    with patch.object(Emitter, "run", lambda self: self.stopped.wait(1)):
        emitter = Emitter(box)
        p = pair()
        assert emitter.submit(p) == "DURABLE_PENDING"
        emitter.close()
        assert emitter.submit(pair()) == "STOPPED"
    assert Outbox(redis).step(lambda _: ack()) == "DELIVERED"


def test_stale_worker_cannot_resurrect_acknowledged_entry():
    redis = RedisModel(); box = Outbox(redis, clock=lambda: 0)
    box.enqueue(pair())
    def competing_send(value):
        assert Outbox(redis, clock=lambda: 0).step(lambda _: ack()) == "DELIVERED"
        return ack(500)
    assert box.step(competing_send) == "STALE"
    assert not redis.entries and not redis.due


def test_retry_limit_retains_terminal_diagnostics():
    redis = RedisModel(); now = [0]
    box = Outbox(redis, clock=lambda: now[0]); box.enqueue(pair())
    for i in range(MAX_ATTEMPTS):
        status = box.step(lambda _: ack(503))
        now[0] += 300
    assert status == "EXHAUSTED"
    assert json.loads(next(iter(redis.entries.values())))["attempt_count"] == MAX_ATTEMPTS
    assert not redis.due


@pytest.mark.parametrize("failure", ["full", "unavailable"])
def test_outbox_failure_preserves_sql_and_state(state, failure):
    import api
    import live_trace
    from test_live_trace import query, Sink
    before = deepcopy(state.f.redis.values)
    with patch.object(api, "_latency", return_value=7), patch.object(live_trace, "sink", Sink()):
        expected = query("select version()")
    box = Outbox(RedisModel(), capacity=0)
    if failure == "unavailable":
        box.enqueue = lambda _: (_ for _ in ()).throw(ConnectionError())
    with patch.object(live_trace.Emitter, "run", lambda self: self.stopped.wait(1)):
        emitter = live_trace.Emitter(box)
        with patch.object(api, "_latency", return_value=7), patch.object(live_trace, "sink", emitter):
            actual = query("select version()")
        emitter.close()
    assert actual.body == expected.body
    assert actual.trace_emission_status == ("FULL" if failure == "full" else "FAILED")
    assert state.f.redis.values == before

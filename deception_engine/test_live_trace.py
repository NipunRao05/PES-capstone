import asyncio
import importlib.util
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch
import pytest
import api
import live_trace
from test_action_provenance import state

spec = importlib.util.spec_from_file_location("trace_storage", Path(__file__).parents[1] / "evidence_store" / "strategy_traces.py")
sys.path.insert(0, str(Path(__file__).parents[1] / "evidence_store"))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)
from test_strategy_traces import RedisDouble


class Sink:
    def __init__(self, failure=None):
        self.store = storage.TraceStore(RedisDouble(), 3600)
        self.pairs = []
        self.failure = failure
    def submit(self, pair):
        self.pairs.append(pair)
        if self.failure: raise self.failure()
        self.store.store("decision", pair["decision"])
        self.store.store("application", pair["application"])
        return "STORED"


def query(sql):
    return asyncio.run(api.decide(MagicMock(), dict(session_id="s1", query_raw=sql,
        query_normalized=sql, protocol="postgres", database="testdb", username="fake_compro1", deception_level=1)))


@pytest.mark.parametrize("sql,sid", [("select version()", "D0"), ("show tables", "D1"),
    ("select datname from pg_database", "D1"),
    ("select id from api_keys_backup", "D2"), ("select id from prod_credentials", "D3"),
    ("select id from employees", "D4"), ("delete from employees where id = 1", "D6")])
def test_live_producers_link_exact_decision(state, sql, sid):
    sink = Sink()
    with patch.object(live_trace, "sink", sink): response = query(sql)
    assert len(sink.pairs) == 1
    pair = sink.pairs[0]
    assert pair["decision"]["strategy_id"] == sid
    assert pair["decision"]["experiment_id"] == "deterministic_baseline"
    assert pair["application"]["decision_id"] == pair["decision"]["decision_id"]
    assert pair["application"]["provenance_status"] == "MATCH"
    assert sink.store.get("application", pair["application"]["application_id"]) == pair["application"]
    storage.validate_ingestion(pair)


def test_decision_precedes_generation_and_depth_is_before(state):
    events = []
    sink = Sink()
    original_begin = live_trace.begin
    original_generate = api._generator.generate_count
    def begin(*a, **kw):
        record = original_begin(*a, **kw)
        events.append(("decision", record["strategy_id"]))
        return record
    def generate(*a, **kw):
        assert live_trace.current.get().record["state_before"]["exposure_depth"] == 1
        events.append(("producer", None))
        return original_generate(*a, **kw)
    state.f.redis.hset("exposure:s1", mapping={"depth": 1})
    with patch.object(live_trace, "sink", sink), patch.object(live_trace, "begin", begin), patch.object(api._generator, "generate_count", generate):
        response = query("select id from employees")
    assert events.index(("decision", "D4")) < events.index(("producer", None))
    assert response.strategy_trace["decision"]["state_before"]["exposure_depth"] == 1
    assert api._exposure.get_depth("s1") == 2


@pytest.mark.parametrize("failure", [ConnectionError, storage.TraceConflict])
def test_failure_does_not_change_response(state, failure):
    with patch.object(live_trace, "sink", Sink()):
        baseline = query("select version()")
    with patch.object(live_trace, "sink", Sink(failure)), patch.object(api, "_latency", return_value=7):
        failed = query("select version()")
    with patch.object(live_trace, "sink", Sink()), patch.object(api, "_latency", return_value=7):
        healthy = query("select version()")
    assert failed.body == healthy.body
    assert failed.trace_emission_status == "FAILED"


def test_keyword_request_and_ingestion_validation(state):
    sink = Sink()
    with patch.object(live_trace, "sink", sink):
        response = asyncio.run(api.decide(request=MagicMock(), body=dict(session_id="s1",
            query_raw="show tables", query_normalized="show tables", protocol="postgres",
            database="testdb", username="fake_compro1", deception_level=1)))
    assert response.strategy_trace["decision"]["strategy_id"] == "D1"
    response.strategy_trace["decision"]["state_before"]["sql"] = "forbidden"
    with pytest.raises(ValueError):
        storage.validate_ingestion(response.strategy_trace)


def test_application_write_failure_keeps_decision_and_response(state):
    class ApplicationFailure(Sink):
        def submit(self, pair):
            self.pairs.append(pair)
            self.store.store("decision", pair["decision"])
            raise ConnectionError()
    sink = ApplicationFailure()
    with patch.object(live_trace, "sink", sink), patch.object(api, "_latency", return_value=7):
        failed = query("select version()")
    with patch.object(live_trace, "sink", Sink()), patch.object(api, "_latency", return_value=7):
        healthy = query("select version()")
    assert failed.body == healthy.body
    pair = sink.pairs[0]
    assert sink.store.get("decision", pair["decision"]["decision_id"]) is not None
    assert sink.store.get("application", pair["application"]["application_id"]) is None
    assert failed.trace_emission_status == "FAILED"

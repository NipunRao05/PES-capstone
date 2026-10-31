from copy import deepcopy

import pytest

from strategy_traces import TraceConflict, TraceStore, event_correlation, validate_ingestion
from test_strategy_trace_endpoint import pair
from test_strategy_traces import RedisDouble


def test_legacy_and_world_trace_roundtrip():
    store = TraceStore(RedisDouble(), 3600)
    validate_ingestion(pair())
    data = pair()
    for record in data.values():
        record.update(world_id="hr_base_v1", world_version=1)
    validate_ingestion(data)
    for kind, record in data.items():
        assert store.store(kind, record) == "inserted"
        assert store.get(kind, record[kind + "_id"])["world_id"] == "hr_base_v1"
    changed = deepcopy(data["application"])
    changed["world_id"] = "another_world"
    with pytest.raises((ValueError, TraceConflict)):
        store.store("application", changed)
    data["application"]["world_version"] = 2
    with pytest.raises(ValueError, match="World identity mismatch"):
        validate_ingestion(data)


def test_world_event_fields_are_private_optional_and_bounded():
    assert event_correlation({}) == {}
    assert event_correlation({"world_id":""}) == {}
    assert event_correlation({"world_id":"hr_base_v1", "world_version":1}) == {"world_id":"hr_base_v1", "world_version":1}
    assert event_correlation({"world_id":"../invalid", "world_version":1}) == {"correlation_status":"INVALID"}

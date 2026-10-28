"""Pure model tests: no database or services."""
import json
import pytest
from world_commitments import Commitments, Fact, FIELD, MAX_FACTS

TIME = "2026-10-28T12:00:00+00:00"
FACT = Fact("relation", "testdb.employees", "exists", True)


def commit(model, fact=FACT, sid="s1"):
    return model.commit(fact, session_id=sid, timestamp=TIME)


def test_first_idempotent_conflicting_and_independent_facts():
    model = Commitments({})
    assert not model.has(FACT) and model.check(FACT) == "unobserved"
    assert commit(model) == "inserted"
    first = model.get(FACT)
    assert first["first_session_id"] == "s1" and first["first_committed_at"] == TIME
    assert commit(model, sid="s2") == "unchanged"
    assert model.commit(FACT, session_id="s3", timestamp="2026-10-29T12:00:00+00:00") == "unchanged"
    assert model.get(FACT) == first
    conflict = Fact("relation", "testdb.employees", "exists", False)
    assert model.check(conflict) == "conflict" and commit(model, conflict) == "conflict"
    assert model.get(FACT) == first
    assert commit(model, Fact("relation", "testdb.departments", "exists", True)) == "inserted"
    assert commit(model, Fact("relation", "testdb.employees", "kind", "table")) == "inserted"
    assert len(model.list()) == 3


def test_old_record_roundtrip_and_read_snapshots():
    old = {"principal_id": "p", "persistent_mutations": {}}
    model = Commitments(old)
    assert model.serialize() == {} and FIELD not in old
    commit(model)
    saved = json.loads(json.dumps({**old, FIELD: model.serialize()}))
    restored = Commitments(saved)
    assert restored.list() == model.list()
    restored.get(FACT)["value"] = False
    restored.list()[0]["value"] = False
    restored.serialize()[FACT.key]["value"] = False
    saved[FIELD][FACT.key]["value"] = False
    assert restored.get(FACT)["value"] is True


@pytest.mark.parametrize("subject,prop,value", [
    ("testdb.Employees", "exists", True), ("testdb.employee;drop", "exists", True),
    ("testdb.employees", "exists", 1), ("testdb.employees", "exists", "true"),
    ("testdb.employees", "sql", "select secret"),
    ("testdb.employees", "kind", "arbitrary"),
])
def test_noncanonical_values_and_unbounded_payloads_rejected(subject, prop, value):
    with pytest.raises(ValueError):
        Fact("relation", subject, prop, value)


def test_capacity_does_not_evict_prior_facts_and_idempotence_still_works():
    model = Commitments({})
    for i in range(MAX_FACTS):
        assert commit(model, Fact("relation", f"testdb.t{i}", "exists", True)) == "inserted"
    before = model.serialize()
    with pytest.raises(ValueError, match="limit"):
        commit(model)
    assert model.serialize() == before
    assert commit(model, Fact("relation", "testdb.t0", "exists", True)) == "unchanged"


def test_corruption_is_not_treated_as_missing():
    with pytest.raises(ValueError):
        Commitments({FIELD: None})
    model = Commitments({})
    with pytest.raises(ValueError):
        model.commit(FACT, session_id="s1", timestamp="2026-10-28T12:00:00")
    assert not model.has(FACT)

import asyncio
import json
import sys
import unittest
from dataclasses import asdict
from unittest.mock import MagicMock

sys.modules.setdefault("redis", MagicMock())

import api
from generator import DataGenerator
from models import DecisionRequest
from mutation_store import MutationStore
from schema_loader import SchemaLoader


class RedisMemory:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def setex(self, key, _ttl, value):
        self.values[key] = value

    def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)

    def exists(self, key):
        return int(key in self.values)

    def scan_iter(self, pattern, count=200):
        prefix = pattern.rstrip("*")
        return iter([key for key in self.values if key.startswith(prefix)])


class TestStatefulPostgresCRUD(unittest.TestCase):
    def setUp(self):
        self.old = (api._schema_loader, api._generator, api._exposure, api._mutations)
        self.old_rate_limit = api.DECIDE_RATE_LIMIT_ENABLED
        api._schema_loader = SchemaLoader()
        api._generator = DataGenerator()
        api._exposure = MagicMock()
        api._exposure.get_depth.return_value = 1
        api._mutations = MutationStore(RedisMemory())
        api.DECIDE_RATE_LIMIT_ENABLED = False

    def tearDown(self):
        api._schema_loader, api._generator, api._exposure, api._mutations = self.old
        api.DECIDE_RATE_LIMIT_ENABLED = self.old_rate_limit

    def request(self, query, session="crud-a", transaction_state="idle"):
        req = DecisionRequest(
            session_id=session,
            query_normalized=query,
            fingerprint=query,
            event_type="query",
            phase="data_discovery",
            username="postgres",
            database="testdb",
            protocol="postgres",
            table="",
            deception_level=1,
            risk_score=0.0,
            transaction_state=transaction_state,
        )
        response = asyncio.run(api.decide(MagicMock(), asdict(req)))
        return json.loads(response.body.decode("utf-8"))

    def transaction(self, action, session="crud-a"):
        return asyncio.run(api.transaction_action(action, {"session_id": session}))

    def test_qualified_and_unqualified_select_apply_id_predicate(self):
        unqualified = self.request("select * from employees where id = 1")
        qualified = self.request("select * from public.employees where id = 1")
        self.assertEqual(len(unqualified["rows"]), 1)
        self.assertEqual(len(qualified["rows"]), 1)
        self.assertEqual(unqualified["rows"][0]["id"], 1)
        self.assertEqual(unqualified["rows"], qualified["rows"])

    def test_update_qualified_and_unqualified_changes_only_target(self):
        baseline_one = self.request("select id, salary from employees where id = 1")["rows"][0]
        baseline_two = self.request("select id, salary from employees where id = 2")["rows"][0]
        update = self.request("update public.employees set salary = salary + 100 where id = 1")
        changed_one = self.request("select id, salary from public.employees where id = 1")["rows"][0]
        unchanged_two = self.request("select id, salary from employees where id = 2")["rows"][0]

        self.assertEqual(update["mode"], "fake")
        self.assertEqual(update["affected_rows"], 1)
        self.assertEqual(changed_one, {"id": 1, "salary": baseline_one["salary"] + 100})
        self.assertEqual(unchanged_two, baseline_two)

        second = self.request("update employees set salary = salary + 50 where id = 1")
        self.assertEqual(second["affected_rows"], 1)
        self.assertEqual(
            self.request("select id, salary from employees where id = 1")["rows"][0]["salary"],
            baseline_one["salary"] + 150,
        )

    def test_rollback_restores_and_commit_preserves_same_session(self):
        baseline = self.request("select id, salary from employees where id = 1")["rows"][0]
        self.request(
            "update public.employees set salary = salary + 100 where id = 1",
            transaction_state="in_transaction",
        )
        inside = self.request(
            "select id, salary from employees where id = 1",
            transaction_state="in_transaction",
        )["rows"][0]
        self.assertEqual(inside["salary"], baseline["salary"] + 100)
        self.assertEqual(self.transaction("rollback")["status"], "ok")
        self.assertEqual(self.request("select id, salary from employees where id = 1")["rows"][0], baseline)

        self.request(
            "update employees set salary = salary + 75 where id = 1",
            transaction_state="in_transaction",
        )
        self.assertEqual(self.transaction("commit")["status"], "ok")
        self.assertEqual(
            self.request("select id, salary from employees where id = 1")["rows"][0]["salary"],
            baseline["salary"] + 75,
        )

    def test_transaction_mutation_is_isolated_between_sessions(self):
        baseline_a = self.request("select id, salary from employees where id = 1", session="session-a")["rows"][0]
        baseline_b = self.request("select id, salary from employees where id = 1", session="session-b")["rows"][0]
        self.request(
            "update public.employees set salary = salary + 100 where id = 1",
            session="session-a",
            transaction_state="in_transaction",
        )
        inside_a = self.request(
            "select id, salary from employees where id = 1",
            session="session-a",
            transaction_state="in_transaction",
        )["rows"][0]
        self.assertEqual(inside_a["salary"], baseline_a["salary"] + 100)
        self.assertEqual(
            self.request("select id, salary from employees where id = 1", session="session-b")["rows"][0],
            baseline_b,
        )
        self.transaction("rollback", session="session-a")
        self.assertEqual(
            self.request("select id, salary from employees where id = 1", session="session-a")["rows"][0],
            baseline_a,
        )

    def test_qualified_insert_and_delete_use_deceptive_path(self):
        inserted = self.request("insert into public.employees (id) values (9999)")
        deleted = self.request("delete from public.employees where id = 1")
        self.assertEqual(inserted["mode"], "fake")
        self.assertEqual(inserted["affected_rows"], 1)
        self.assertEqual(deleted["mode"], "fake")
        self.assertEqual(deleted["affected_rows"], 1)
        self.assertEqual(self.request("select * from public.employees where id = 1")["rows"], [])


if __name__ == "__main__":
    unittest.main()

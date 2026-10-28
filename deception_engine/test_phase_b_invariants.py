"""Focused state-transition checks; no services, secrets or wall-clock waits."""
import asyncio
import json
import unittest
from unittest.mock import MagicMock

import api
from exposure import ExposureTracker
from generator import DataGenerator
from mutation_store import MutationStore
from principal_registry import PREFIX, SESSION_TTL, PrincipalError
from schema_loader import SchemaLoader
import test_principal_registry as principal_fixtures


class OrdinaryTransactionTests(unittest.TestCase):
    def setUp(self):
        self.old = {name: getattr(api, name) for name in (
            "_schema_loader", "_generator", "_exposure", "_mutations", "DECIDE_RATE_LIMIT_ENABLED")}
        self.redis = principal_fixtures.MemoryRedis()
        api._schema_loader = SchemaLoader()
        api._generator = DataGenerator()
        api._exposure = ExposureTracker(self.redis)
        api._mutations = MutationStore(self.redis)
        api.DECIDE_RATE_LIMIT_ENABLED = False

    def tearDown(self):
        for name, value in self.old.items():
            setattr(api, name, value)

    def query(self, sql, protocol, session, tx=False):
        body = dict(session_id=session, query_normalized=sql, query_raw=sql,
                    protocol=protocol, database="testdb", username="seeded",
                    deception_level=1, transaction_state="in_transaction" if tx else "idle")
        return json.loads(asyncio.run(api.decide(MagicMock(), body)).body)

    def test_crud_rollback_commit_and_next_transaction_for_both_protocols(self):
        for protocol in ("mysql", "postgres"):
            with self.subTest(protocol=protocol):
                sid = protocol + "-ordinary"
                q = lambda sql, tx=False: self.query(sql, protocol, sid, tx)
                baseline = q("select id, salary from employees where id = 1")["rows"]
                baseline_two = q("select id from employees where id = 2")["rows"]
                count = q("select count(*) from employees")["count"]
                for action in ("rollback", "commit"):
                    self.assertEqual(q("insert into employees (id) values (9999)", True)["affected_rows"], 1)
                    # Existing INSERT simulates a generated row, not literal VALUES.
                    # Check its transaction lifetime without certifying that SQL gap.
                    inserted_id = q("select id from employees limit 1", True)["rows"][0]["id"]
                    self.assertEqual(q("update employees set salary = 12345 where id = 1", True)["affected_rows"], 1)
                    self.assertEqual(q("delete from employees where id = 2", True)["affected_rows"], 1)
                    self.assertEqual(q("select salary from employees where id = 1", True)["rows"], [{"salary": 12345}])
                    self.assertEqual(q("select id from employees where id = 2", True)["rows"], [])
                    asyncio.run(api.transaction_action(action, {"session_id": sid}))
                    self.assertEqual(q("select count(*) from employees")["count"], count)
                    if action == "rollback":
                        self.assertEqual(q("select id, salary from employees where id = 1")["rows"], baseline)
                        self.assertEqual(q("select id from employees where id = 2")["rows"], baseline_two)
                        self.assertEqual(q(f"select id from employees where id = {inserted_id}")["rows"], [])
                    else:
                        self.assertEqual(q("select salary from employees where id = 1")["rows"], [{"salary": 12345}])
                        self.assertEqual(q(f"select id from employees where id = {inserted_id}")["rows"], [{"id": inserted_id}])
                q("update employees set salary = 54321 where id = 1", True)
                asyncio.run(api.transaction_action("rollback", {"session_id": sid}))
                self.assertEqual(q("select salary from employees where id = 1")["rows"], [{"salary": 12345}])

    def test_cleanup_discards_open_transaction_without_affecting_other_session(self):
        for sid in ("closed", "other"):
            self.query("insert into employees (id) values (9999)", "mysql", sid, True)
        other_id = self.query("select id from employees limit 1", "mysql", "other", True)["rows"][0]["id"]
        asyncio.run(api.session_end({"session_id": "closed"}))
        asyncio.run(api.session_end({"session_id": "closed"}))
        self.assertEqual(api._mutations.get_inserted_rows("closed", "employees"), [])
        self.assertEqual(self.query(f"select id from employees where id = {other_id}", "mysql", "other", True)["rows"], [{"id": other_id}])
        self.assertNotIn("mutation-tx:closed", self.redis.values)
        self.assertIn("mutation-tx:other", self.redis.values)

    def test_observed_exposure_does_not_rollback_with_rows(self):
        sid = "exposure"
        self.query("select id from employees", "mysql", sid, True)
        self.query("select id from api_keys", "mysql", sid, True)
        self.assertEqual(api._exposure.get_depth(sid), 3)
        asyncio.run(api.transaction_action("rollback", {"session_id": sid}))
        self.assertEqual(api._exposure.get_depth(sid), 3)
        self.assertEqual(self.query("select id from api_keys_backup", "mysql", sid)["mode"], "fake")


class PrincipalLifetimeTests(unittest.TestCase):
    # Reuse fixture helpers, without inheriting/collecting the historical suite.
    def setUp(self):
        self.fixture = principal_fixtures.PersistentStateTests(methodName="test_disconnect_discards_uncommitted_state")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def test_expired_binding_rejects_queries_and_keeps_committed_identity(self):
        f = self.fixture
        f.q("update employees set salary = 12345 where id = 1")
        key = f.reg.key("mysql", "fake_compro1")
        f.q("begin")
        f.q("update employees set salary = 54321 where id = 1")
        before_expiry = f.reg.load(key)
        # Model Redis expiry of the binding; no four-hour sleep is necessary.
        f.redis.delete(PREFIX + "session:s1")
        with self.assertRaises(PrincipalError):
            f.q("commit")
        self.assertEqual(f.reg.load(key), before_expiry)
        f.native("s2")
        self.assertEqual(f.q("select salary from employees where id = 1", "s2")["rows"], [{"salary": 12345}])

    def test_disabled_identity_rejects_existing_session_and_retains_tombstone(self):
        f = self.fixture
        f.command("DROP USER fake_compro1", "mysql")
        with self.assertRaises(PrincipalError):
            f.q("select id from employees")
        with self.assertRaises(PrincipalError):
            f.create("mysql")
        self.assertFalse(f.reg.load(f.reg.key("mysql", "fake_compro1"))["enabled"])

    def test_expired_working_overlay_cannot_erase_committed_state(self):
        f = self.fixture
        f.q("update employees set salary = 12345 where id = 1")
        key = f.reg.key("mysql", "fake_compro1")
        committed = f.reg.load(key)["persistent_mutations"]
        f.q("begin")
        f.q("update employees set salary = 54321 where id = 1")
        f.redis.delete("mutation:s1:employees")
        with self.assertRaises(PrincipalError):
            f.q("commit")
        self.assertEqual(f.reg.load(key)["persistent_mutations"], committed)
        with self.assertRaises(PrincipalError):
            f.q("select id from employees")
        f.native("s2")
        self.assertEqual(f.q("select salary from employees where id = 1", "s2")["rows"], [{"salary": 12345}])

    def test_principal_exposure_survives_rollback_and_return(self):
        f = self.fixture
        f.q("begin")
        f.q("select id from employees")
        f.q("select id from api_keys")
        f.q("rollback")
        f.native("s2")
        self.assertEqual(f.q("select id from api_keys_backup", "s2")["mode"], "fake")

    def test_active_transaction_refreshes_working_state_with_binding(self):
        f = self.fixture
        f.q("begin")
        f.q("update employees set salary = 12345 where id = 1")
        keys = ["mutation:s1:employees", "mutation-tx:s1", "exposure:s1", PREFIX + "session:s1"]
        for key in keys:
            f.redis.expiry[key] = 1
        f.q("select id from employees where id = 1")
        for key in keys:
            self.assertEqual(f.redis.expiry[key], SESSION_TTL)

    def test_postgres_abort_rollback_and_expiry_guard(self):
        f = self.fixture
        f.create("postgres")
        f.command("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fake_compro1")
        body, _ = f.scram_body(sid="pg1")
        f.reg.finish_scram(body)
        q = lambda sql: f.q(sql, "pg1")
        original = q("select salary from employees where id = 1")["rows"]
        q("begin")
        q("update employees set salary = 12345 where id = 1")
        self.assertEqual(q("create table denied (id int)")["tx_status"], "E")
        self.assertEqual(q("select id from employees")["sqlstate"], "25P02")
        self.assertEqual(q("rollback")["tx_status"], "I")
        self.assertEqual(q("select salary from employees where id = 1")["rows"], original)
        q("begin")
        q("update employees set salary = 54321 where id = 1")
        f.redis.delete("mutation:pg1:employees")
        with self.assertRaises(PrincipalError):
            q("commit")
        self.assertEqual(f.reg.load(f.reg.key("postgres", "fake_compro1"))["persistent_mutations"], {})


if __name__ == "__main__":
    unittest.main()

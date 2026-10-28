"""Focused lifecycle tests using the existing in-memory principal fixtures."""
import asyncio
import copy
import json
import time
import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI

import api
import principal_runtime
import test_principal_registry as fixtures
from principal_registry import PREFIX, PrincipalError
from principal_state import (
    PrincipalTransactionConflict, PrincipalTransactionContext, PrincipalTransactionState,
)


class TransactionContextTests(unittest.TestCase):
    def test_initial_and_legacy_binding_shapes_are_unchanged(self):
        initial = {"key": "principal", "tx": False, "failed": False, "revision": 7}
        context = PrincipalTransactionContext.new("principal", 7)
        self.assertEqual(context.binding, initial)
        self.assertEqual(context.state, PrincipalTransactionState.IDLE)
        self.assertIsNone(context.expected_mutation_keys)
        for tx, failed, status in ((False, False, "I"), (True, False, "T"),
                                   (True, True, "E"), (False, True, "E")):
            binding = {**initial, "tx": tx, "failed": failed, "unknown_legacy_field": 1}
            before = json.dumps(binding)
            context = PrincipalTransactionContext(binding)
            self.assertEqual(context.state.value, status)
            self.assertEqual(json.dumps(context.binding), before)

    def test_begin_and_repeated_begin_preserve_baseline_and_pending_keys(self):
        context = PrincipalTransactionContext.new("principal", 7)
        context.begin()
        context.track_working_keys(["mutation:s:employees"])
        before = copy.deepcopy(context.binding)
        context.begin()
        self.assertEqual(context.state, PrincipalTransactionState.ACTIVE)
        self.assertEqual(context.binding, before)

    def test_commit_rollback_and_failed_commit_order(self):
        for command, failed, expected in (("commit", False, "COMMIT"),
                                          ("rollback", False, "ROLLBACK"),
                                          ("commit", True, "ROLLBACK")):
            with self.subTest(command=command, failed=failed):
                context = PrincipalTransactionContext.new("principal", 7)
                context.begin()
                if failed:
                    context.abort()
                calls = []
                discard = lambda: calls.append(("discard", context.state.value))
                restore = lambda: calls.append(("restore", context.state.value))
                if command == "commit":
                    tag = context.commit(7, lambda: calls.append(("promote", context.state.value)), discard, restore)
                else:
                    tag = context.rollback(discard, restore)
                wanted = [] if failed or command == "rollback" else [("promote", "T")]
                self.assertEqual(calls, wanted + [("discard", "I"), ("restore", "I")])
                self.assertEqual(tag, expected)
                self.assertEqual(context.state, PrincipalTransactionState.IDLE)

    def test_stale_commit_preserves_pending_state_and_requires_rollback(self):
        context = PrincipalTransactionContext.new("principal", 7)
        context.begin()
        context.track_working_keys(["mutation:s:employees"])
        calls = []
        with self.assertRaises(PrincipalTransactionConflict):
            context.commit(8, lambda: calls.append("promote"),
                           lambda: calls.append("discard"), lambda: calls.append("restore"))
        self.assertEqual(calls, [])
        self.assertEqual(context.state, PrincipalTransactionState.FAILED)
        self.assertEqual(context.expected_mutation_keys, ["mutation:s:employees"])
        self.assertEqual(context.binding["revision"], 7)

    def test_failed_promotion_does_not_finalize(self):
        context = PrincipalTransactionContext.new("principal", 7)
        context.begin()
        def unavailable():
            raise ConnectionError("unavailable")
        calls = []
        with self.assertRaises(ConnectionError):
            context.commit(7, unavailable, lambda: calls.append("discard"), lambda: calls.append("restore"))
        self.assertEqual(calls, [])
        self.assertEqual(context.state, PrincipalTransactionState.ACTIVE)


class PrincipalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.PersistentStateTests(methodName="test_disconnect_discards_uncommitted_state")
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.app = FastAPI()
        principal_runtime.install(self.app, api)

    def prepare(self, protocol):
        if protocol == "mysql":
            return "s1"
        self.f.create("postgres")
        self.f.command("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fake_compro1")
        self.login(protocol, "pg1")
        return "pg1"

    def login(self, protocol, sid):
        if protocol == "mysql":
            return self.f.native(sid)
        body, _ = self.f.scram_body(sid=sid)
        return self.f.reg.finish_scram(body)

    def record(self, protocol):
        return self.f.reg.load(self.f.reg.key(protocol, "fake_compro1"))

    def binding(self, sid):
        return json.loads(self.f.redis.get(PREFIX + "session:" + sid))

    def end(self, sid):
        # Exercise the actual registered /principals/end route, including its
        # dispatch/auth/deadline checks, without service startup or live Redis.
        async def post():
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.post("/principals/end", json={
                    "session_id": sid, "deadline_ms": time.time() * 1000 + 2500,
                }, headers={"X-Deceptive-Principal-Key": self.f.secret})
        with patch.object(principal_runtime.redis, "Redis", return_value=self.f.redis), \
             patch.object(principal_runtime, "PrincipalRegistry", return_value=self.f.reg):
            response = asyncio.run(post())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_pending_commit_rollback_and_autocommit_for_both_protocols(self):
        for protocol in ("postgres", "mysql"):
            with self.subTest(protocol=protocol):
                sid = self.prepare(protocol)
                q = lambda sql: self.f.q(sql, sid)
                initial = self.record(protocol)
                self.assertEqual(self.binding(sid), {
                    "key": self.f.reg.key(protocol, "fake_compro1"),
                    "tx": False, "failed": False, "revision": 0,
                })
                self.assertEqual(q("begin")["tx_status"], "T")
                self.assertEqual(self.binding(sid)["mutation_keys"], [])
                self.assertEqual(self.record(protocol)["persistent_mutations"], {})
                q("update employees set salary = 12345 where id = 1")
                self.assertEqual(q("select salary from employees where id = 1")["rows"], [{"salary": 12345}])
                self.assertEqual(self.binding(sid)["mutation_keys"], ["mutation:" + sid + ":employees"])
                self.assertEqual(self.record(protocol)["persistent_mutations"], {})
                self.assertEqual(self.record(protocol)["world_revision"], 0)
                # Repeated BEGIN keeps this implementation's pending state.
                q("begin")
                self.assertEqual(q("commit")["tx_status"], "I")
                committed = self.record(protocol)
                self.assertTrue(committed["persistent_mutations"])
                self.assertEqual(committed["world_revision"], 1)
                self.assertEqual(self.binding(sid)["mutation_keys"], [])
                self.assertIsNone(self.f.redis.get("mutation-tx:" + sid))
                q("begin")
                q("update employees set salary = 54321 where id = 1")
                q("rollback")
                self.assertEqual(self.record(protocol)["persistent_mutations"], committed["persistent_mutations"])
                self.assertEqual(self.record(protocol)["world_revision"], 1)
                self.assertEqual(q("select salary from employees where id = 1")["rows"], [{"salary": 12345}])
                self.assertEqual(self.binding(sid)["mutation_keys"], [])
                # A mutation after finalization must still autocommit.
                q("update employees set salary = 67890 where id = 1")
                self.assertEqual(self.record(protocol)["world_revision"], 2)
                self.assertEqual(self.binding(sid)["tx"], False)
                self.assertEqual(self.record(protocol)["persistent_permissions"], initial["persistent_permissions"])

    def test_empty_and_repeated_finalization_for_both_protocols(self):
        for protocol in ("postgres", "mysql"):
            with self.subTest(protocol=protocol):
                sid = self.prepare(protocol)
                q = lambda sql: self.f.q(sql, sid)
                # Idle finalization is a no-op for durable mutations/revision.
                for sql in ("commit", "commit", "rollback", "rollback", "commit"):
                    result = q(sql)
                    self.assertEqual(result["tx_status"], "I")
                    self.assertEqual(self.record(protocol)["world_revision"], 0)
                q("begin")
                q("rollback")
                self.assertEqual(self.record(protocol)["world_revision"], 0)
                q("start transaction")
                q("commit")
                # Existing empty ACTIVE commit increments revision, preserved.
                self.assertEqual(self.record(protocol)["world_revision"], 1)
                self.assertEqual(self.record(protocol)["persistent_mutations"], {})
                self.assertEqual(self.binding(sid)["mutation_keys"], [])

    def test_end_route_and_reconnect_for_pending_committed_and_rolled_back_state(self):
        for protocol in ("postgres", "mysql"):
            sid = self.prepare(protocol)
            for ending in ("pending", "commit", "rollback"):
                with self.subTest(protocol=protocol, ending=ending):
                    q = lambda sql: self.f.q(sql, sid)
                    prior_rows = q("select salary from employees where id = 1")["rows"]
                    q("begin")
                    q("update employees set salary = 31415 where id = 1")
                    if ending != "pending":
                        q(ending)
                    key = self.f.reg.key(protocol, "fake_compro1")
                    durable_before_end = self.f.redis.get(key)
                    self.end(sid)
                    self.end(sid)
                    self.assertEqual(self.f.redis.get(key), durable_before_end)
                    self.assertIsNone(self.f.redis.get(PREFIX + "session:" + sid))
                    self.assertEqual(list(self.f.redis.scan_iter("mutation:" + sid + ":*")), [])
                    self.assertIsNone(self.f.redis.get("mutation-tx:" + sid))
                    self.assertIsNone(self.f.redis.hget("exposure:" + sid, "depth"))
                    with self.assertRaises(PrincipalError):
                        q("commit")
                    sid = protocol + "-after-" + ending
                    self.login(protocol, sid)
                    rows = self.f.q("select salary from employees where id = 1", sid)["rows"]
                    self.assertEqual(rows, [{"salary": 31415}] if ending == "commit" else prior_rows)

    def test_postgres_failed_commit_restores_but_mysql_statement_error_stays_active(self):
        for protocol in ("postgres", "mysql"):
            with self.subTest(protocol=protocol):
                sid = self.prepare(protocol)
                q = lambda sql: self.f.q(sql, sid)
                baseline = q("select salary from employees where id = 1")["rows"]
                q("begin")
                q("update employees set salary = 12345 where id = 1")
                result = q("create table denied (id int)")
                self.assertEqual(result["tx_status"], "E" if protocol == "postgres" else "T")
                result = q("commit")
                self.assertEqual(result["command_tag"], "ROLLBACK" if protocol == "postgres" else "COMMIT")
                self.assertEqual(result["tx_status"], "I")
                rows = q("select salary from employees where id = 1")["rows"]
                self.assertEqual(rows, baseline if protocol == "postgres" else [{"salary": 12345}])

    def test_permissions_and_observed_depth_are_not_rolled_back_for_both_protocols(self):
        for protocol in ("postgres", "mysql"):
            with self.subTest(protocol=protocol):
                sid = self.prepare(protocol)
                q = lambda sql: self.f.q(sql, sid)
                q("begin")
                q("select id from employees")
                q("select id from api_keys")
                # Admin GRANT is a separate immediate registry operation; it is
                # not part of the returning principal's pending row transaction.
                scope = "ALL TABLES IN SCHEMA public" if protocol == "postgres" else "testdb.*"
                self.f.command("GRANT SELECT ON " + scope + " TO fake_compro1", protocol)
                q("rollback")
                record = self.record(protocol)
                self.assertEqual(record["persistent_permissions"], ["SELECT"])
                self.assertEqual(record["visible_role"], "reader")
                self.assertEqual(record["exposure_depth"], 3)
                self.assertEqual(record["persistent_mutations"], {})
                self.end(sid)
                returned = protocol + "-observed"
                self.login(protocol, returned)
                self.assertEqual(self.f.q("select id from api_keys_backup", returned)["mode"], "fake")
                denied = self.f.q("update employees set salary = 12345 where id = 1", returned)
                self.assertEqual(denied["mode"], "block")
                self.assertEqual(denied["tx_status"], "I")

    def test_revision_conflict_never_promotes_for_both_protocols(self):
        for protocol in ("postgres", "mysql"):
            with self.subTest(protocol=protocol):
                sid = self.prepare(protocol)
                self.f.q("begin", sid)
                self.f.q("update employees set salary = 12345 where id = 1", sid)
                other = protocol + "-concurrent"
                self.login(protocol, other)
                self.f.q("update employees set salary = 54321 where id = 1", other)
                committed = self.record(protocol)["persistent_mutations"]
                conflict = self.f.q("commit", sid)
                self.assertEqual((conflict["sqlstate"], conflict["tx_status"]), ("40001", "E"))
                self.assertEqual(self.record(protocol)["persistent_mutations"], committed)
                self.assertTrue(self.binding(sid)["mutation_keys"])
                self.f.q("rollback", sid)
                self.assertEqual(self.binding(sid)["mutation_keys"], [])
                self.assertEqual(self.f.q("select salary from employees where id = 1", sid)["rows"], [{"salary": 54321}])


if __name__ == "__main__":
    unittest.main()

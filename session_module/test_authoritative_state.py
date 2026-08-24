import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from authoritative_state import AuthoritativeStateStore, start_state_api


REQUIRED_FIELDS = {
    "session_id", "protocol", "persona_id", "strategy_id", "schema_version",
    "database", "user", "role", "permissions", "transaction_state",
    "visible_databases", "visible_tables", "visible_columns", "created_objects",
    "modified_objects", "dropped_objects", "discovered_objects", "triggered_traps",
    "mitre_stage", "risk_score", "query_count", "session_depth",
    "strategy_history",
}


def event(session_id="s-1", sql="", *, success=True, authority="backend",
          transaction_state="idle", verified=True, protocol="postgres"):
    return {
        "event_type": "query",
        "session_id": session_id,
        "timestamp": "2026-08-24T10:00:00Z",
        "protocol": protocol,
        "username": "decoy_user",
        "database": "decoy",
        "query_normalized": sql,
        "fingerprint": f"fp-{abs(hash(sql))}",
        "outcome_verified": verified,
        "success": success,
        "authority": authority,
        "transaction_state": transaction_state,
        "error_code": "" if success else "42P01",
    }


class AuthoritativeStateTests(unittest.TestCase):
    def setUp(self):
        self.store = AuthoritativeStateStore(max_sessions=20)

    def state(self, session_id="s-1"):
        result = self.store.get(session_id)
        self.assertIsNotNone(result)
        return result

    def test_required_state_contract_and_lifecycle(self):
        self.store.apply_proxy_event({
            "event_type": "session_start",
            "session_id": "s-1",
            "timestamp": "2026-08-24T09:59:00Z",
            "protocol": "postgres",
            "username": "decoy_user",
            "database": "decoy",
        })
        state = self.state()
        self.assertTrue(REQUIRED_FIELDS.issubset(state))
        self.assertEqual(state["visible_databases"], ["decoy"])
        self.assertEqual(state["role"], "decoy_user")
        self.assertEqual(state["strategy_history"], ["D0"])

        self.store.apply_proxy_event({
            "event_type": "session_end", "session_id": "s-1",
            "timestamp": "2026-08-24T10:01:00Z",
        })
        self.assertTrue(self.state()["closed"])

    def test_unverified_intent_cannot_mutate_state(self):
        self.store.apply_proxy_event(event(
            sql="create table should_not_exist (id integer)", verified=False,
        ))
        state = self.state()
        self.assertEqual(state["created_objects"], [])
        self.assertEqual(state["unverified_query_count"], 1)
        self.assertEqual(state["outcome_verified_count"], 0)

    def test_create_insert_update_select_drop_and_failed_select(self):
        queries = (
            "create table phase2_items (id integer, name text)",
            "insert into phase2_items values (?)",
            "update phase2_items set name = ? where id = ?",
            "select id, name from phase2_items",
        )
        for sql in queries:
            self.store.apply_proxy_event(event(sql=sql))

        state = self.state()
        self.assertIn("phase2_items", state["created_objects"])
        self.assertIn("phase2_items", state["modified_objects"])
        self.assertIn("phase2_items", state["visible_tables"])
        self.assertIn("phase2_items.id", state["visible_columns"])
        self.assertIn("phase2_items", state["discovered_objects"])

        self.store.apply_proxy_event(event(sql="drop table phase2_items"))
        self.store.apply_proxy_event(event(
            sql="select * from phase2_items", success=False,
        ))
        state = self.state()
        self.assertNotIn("phase2_items", state["visible_tables"])
        self.assertIn("phase2_items", state["dropped_objects"])
        self.assertEqual(state["failed_query_count"], 1)
        self.assertEqual(state["last_error_code"], "42P01")

    def test_transaction_rollback_restores_projected_objects(self):
        self.store.apply_proxy_event(event(
            sql="begin", transaction_state="in_transaction",
        ))
        self.store.apply_proxy_event(event(
            sql="create table rolled_back (id integer)",
            transaction_state="in_transaction",
        ))
        self.assertIn("rolled_back", self.state()["created_objects"])

        self.store.apply_proxy_event(event(sql="rollback", transaction_state="idle"))
        state = self.state()
        self.assertNotIn("rolled_back", state["created_objects"])
        self.assertNotIn("rolled_back", state["visible_tables"])
        self.assertEqual(state["transaction_state"], "idle")

    def test_out_of_order_session_end_rolls_back_open_transaction(self):
        self.store.apply_proxy_event({
            "event_type": "session_end",
            "session_id": "late-events",
            "timestamp": "2026-08-24T10:05:00Z",
            "protocol": "postgres",
            "username": "decoy_user",
            "database": "decoy",
            "query_count": 2,
        })
        self.store.apply_proxy_event(event(
            session_id="late-events",
            sql="begin",
            transaction_state="in_transaction",
        ))
        self.store.apply_proxy_event(event(
            session_id="late-events",
            sql="create table implicit_rollback (id integer)",
            transaction_state="in_transaction",
        ))
        state = self.state("late-events")
        self.assertTrue(state["closed"])
        self.assertEqual(state["query_count"], 2)
        self.assertNotIn("implicit_rollback", state["created_objects"])
        self.assertNotIn("implicit_rollback", state["visible_tables"])
        self.assertEqual(state["transaction_state"], "idle")

    def test_role_permission_discovery_trap_and_mitre_projection(self):
        self.store.apply_proxy_event(event(sql="set role analyst"))
        self.store.apply_proxy_event(event(
            sql="grant select on phase2_items to analyst",
        ))
        self.store.apply_proxy_event(event(
            sql="select * from information_schema.tables",
        ))
        self.store.apply_proxy_event(event(
            sql="select * from prod_credentials", authority="deception",
        ))
        self.store.apply_mitre_event({
            "session_id": "s-1",
            "timestamp": "2026-08-24T10:02:00Z",
            "phase": "collection",
            "risk_score": 18.5,
            "is_trap_triggered": True,
            "rule_id": "R-TRAP",
        })
        state = self.state()
        self.assertEqual(state["role"], "analyst")
        self.assertTrue(state["permissions"])
        self.assertNotIn("analyst", state["visible_tables"])
        self.assertIn("information_schema.tables", state["discovered_objects"])
        self.assertIn("prod_credentials", state["triggered_traps"])
        self.assertIn("R-TRAP", state["triggered_traps"])
        self.assertEqual(state["mitre_stage"], "collection")
        self.assertEqual(state["risk_score"], 18.5)

    def test_untrusted_state_inputs_are_bounded(self):
        for index in range(600):
            self.store.apply_proxy_event(event(
                sql=f"select * from bounded_object_{index}",
            ))
        self.store.apply_mitre_event({
            "session_id": "s-1",
            "risk_score": float("nan"),
            "is_trap_triggered": True,
            "rule_id": "x" * 1000,
        })
        state = self.state()
        self.assertLessEqual(len(state["visible_tables"]), 512)
        self.assertLessEqual(len(state["discovered_objects"]), 512)
        self.assertLessEqual(max(map(len, state["triggered_traps"])), 256)
        self.assertEqual(state["risk_score"], 0.0)

    def test_same_confirmed_sequence_is_deterministic(self):
        sequence = [
            event(session_id="a", sql="create table stable_state (id integer)"),
            event(session_id="a", sql="insert into stable_state values (?)"),
            event(session_id="a", sql="select * from stable_state"),
        ]
        mirror = [{**item, "session_id": "b"} for item in sequence]
        for item in sequence + mirror:
            self.store.apply_proxy_event(item)
        a = self.state("a")
        b = self.state("b")
        for field in (
            "schema_version", "visible_tables", "visible_columns",
            "created_objects", "modified_objects", "discovered_objects",
            "query_count", "transaction_state",
        ):
            self.assertEqual(a[field], b[field], field)

    def test_loopback_state_api(self):
        self.store.apply_proxy_event(event(sql="select * from api_keys_backup", authority="deception"))
        self.store.ready = True
        server = start_state_api(self.store, "127.0.0.1", 0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]

        with urlopen(f"http://127.0.0.1:{port}/readyz", timeout=2) as response:
            self.assertEqual(json.load(response), {"ready": True})
        with urlopen(f"http://127.0.0.1:{port}/state/session/s-1", timeout=2) as response:
            payload = json.load(response)
        self.assertEqual(payload["session_id"], "s-1")
        self.assertIn("api_keys_backup", payload["triggered_traps"])

        with self.assertRaises(HTTPError) as missing:
            urlopen(f"http://127.0.0.1:{port}/state/session/missing", timeout=2)
        self.assertEqual(missing.exception.code, 404)


if __name__ == "__main__":
    unittest.main()

import json
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from authoritative_state import AuthoritativeStateStore, start_state_api


def query(session_id, sql, timestamp, *, success=True, authority="deception"):
    return {
        "session_id": session_id,
        "event_type": "query",
        "timestamp": timestamp,
        "protocol": "mysql",
        "database": "fictional_hr",
        "username": "decoy_guest",
        "query_normalized": sql,
        "fingerprint": "not-retained",
        "outcome_verified": True,
        "success": success,
        "authority": authority,
        "error_code": "" if success else "synthetic-error",
    }


def response(strategy_id="D1"):
    return {
        "strategy_id": strategy_id,
        "confidence": 1.0,
        "selector_type": "rule",
        "policy_version": "rule-v1",
        "allowed_actions": ["D0", strategy_id],
        "rule_default_action": strategy_id,
    }


class StrategyTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.store = AuthoritativeStateStore(max_sessions=20)

    def record(self, session_id="telemetry-1"):
        snapshot = self.store.get_adaptation_snapshot(session_id)
        self.assertIsNotNone(snapshot)
        record = self.store.record_strategy_decision(
            snapshot,
            response(),
            latency_ms=2.5,
            cpu_cost_ms=0.25,
            memory_cost_bytes=512,
        )
        self.assertIsNotNone(record)
        return record

    def test_decision_links_to_structured_subsequent_outcome(self):
        session_id = "telemetry-1"
        self.store.apply_proxy_event(query(
            session_id, "show databases", "2026-01-01T00:00:00Z"
        ), "MySQL")
        decision = self.record(session_id)

        self.store.apply_proxy_event(query(
            session_id,
            "select * from prod_credentials",
            "2026-01-01T00:00:10Z",
        ), "MySQL")
        self.store.apply_proxy_event(query(
            session_id,
            "select * from missing_table",
            "2026-01-01T00:00:12Z",
            success=False,
            authority="backend",
        ), "MySQL")
        self.store.apply_mitre_event({
            "session_id": session_id,
            "timestamp": "2026-01-01T00:00:15Z",
            "phase": "collection",
            "risk_score": 9.0,
            "technique_id": "T1213.006",
        })
        self.store.apply_proxy_event({
            "session_id": session_id,
            "event_type": "session_end",
            "timestamp": "2026-01-01T00:00:20Z",
            "query_count": 3,
        }, "MySQL")
        final_snapshot = self.store.get_adaptation_snapshot(session_id)
        self.assertEqual(self.store.observe_strategy_outcomes(final_snapshot), 1)

        linked = self.store.get_strategy_telemetry(decision["decision_id"])
        self.assertEqual(linked["decision"]["decision_id"], linked["outcome"]["decision_id"])
        required_decision = {
            "decision_id", "session_id", "timestamp", "state_before",
            "allowed_actions", "rule_default_action", "selected_action",
            "selector_type", "confidence", "policy_version",
        }
        required_outcome = {
            "queries_after_decision", "session_duration_after_decision",
            "new_query_families", "new_tables_accessed",
            "new_MITRE_techniques", "trap_interactions",
            "attacker_progression", "disconnect_time", "errors",
            "latency", "CPU_cost", "memory_cost",
        }
        self.assertTrue(required_decision.issubset(linked["decision"]))
        self.assertTrue(required_outcome.issubset(linked["outcome"]))
        self.assertEqual(linked["outcome"]["queries_after_decision"], 2)
        self.assertGreater(linked["outcome"]["session_duration_after_decision"], 0)
        self.assertGreater(linked["outcome"]["new_query_families"], 0)
        self.assertGreater(linked["outcome"]["new_tables_accessed"], 0)
        self.assertEqual(linked["outcome"]["new_MITRE_techniques"], 1)
        self.assertEqual(linked["outcome"]["trap_interactions"], 1)
        self.assertTrue(linked["outcome"]["attacker_progression"]["advanced"])
        self.assertEqual(linked["outcome"]["disconnect_time"], "2026-01-01T00:00:20Z")
        self.assertEqual(linked["outcome"]["errors"], 1)
        self.assertEqual(linked["outcome"]["latency"], 2.5)
        self.assertEqual(linked["outcome"]["CPU_cost"], 0.25)
        self.assertEqual(linked["outcome"]["memory_cost"], 512)
        self.assertTrue(linked["outcome"]["final"])
        encoded = json.dumps(linked)
        self.assertNotIn("query_normalized", encoded)
        self.assertNotIn("not-retained", encoded)

    def test_each_accepted_decision_has_a_unique_linked_outcome(self):
        session_id = "multiple"
        self.store.apply_proxy_event(query(
            session_id, "show databases", "2026-01-01T00:00:00Z"
        ), "MySQL")
        first = self.record(session_id)
        second = self.record(session_id)
        records = self.store.get_session_strategy_telemetry(session_id)["records"]
        self.assertEqual(len(records), 2)
        self.assertNotEqual(first["decision_id"], second["decision_id"])
        for record in records:
            self.assertEqual(
                record["decision"]["decision_id"],
                record["outcome"]["decision_id"],
            )

    def test_forged_or_unapproved_action_space_is_not_recorded(self):
        self.store.apply_proxy_event(query(
            "invalid", "show databases", "2026-01-01T00:00:00Z"
        ), "MySQL")
        snapshot = self.store.get_adaptation_snapshot("invalid")
        forged = response("D1")
        forged["allowed_actions"] = ["D5"]
        forged["rule_default_action"] = "D5"
        self.assertIsNone(self.store.record_strategy_decision(snapshot, forged))
        self.assertEqual(
            self.store.get_session_strategy_telemetry("invalid")["records"], []
        )

    def test_read_only_telemetry_api(self):
        session_id = "api-telemetry"
        self.store.apply_proxy_event(query(
            session_id, "show databases", "2026-01-01T00:00:00Z"
        ), "MySQL")
        decision = self.record(session_id)
        self.store.ready = True
        server = start_state_api(self.store, "127.0.0.1", 0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"

        with urlopen(f"{base}/telemetry/decision/{decision['decision_id']}", timeout=2) as result:
            linked = json.load(result)
        self.assertEqual(linked["decision"]["session_id"], session_id)
        with urlopen(f"{base}/telemetry/session/{session_id}", timeout=2) as result:
            by_session = json.load(result)
        self.assertEqual(len(by_session["records"]), 1)
        with urlopen(f"{base}/telemetry/decisions?limit=1", timeout=2) as result:
            listing = json.load(result)
        self.assertEqual(len(listing["records"]), 1)
        with self.assertRaises(HTTPError) as missing:
            urlopen(f"{base}/telemetry/decision/missing", timeout=2)
        self.assertEqual(missing.exception.code, 404)


if __name__ == "__main__":
    unittest.main()

import threading
import time
import unittest

from async_adaptation import AsyncStrategyAdapter
from authoritative_state import AuthoritativeStateStore


def query(session_id, sql="show databases", timestamp="2026-01-01T00:00:00Z"):
    return {
        "session_id": session_id,
        "event_type": "query",
        "timestamp": timestamp,
        "protocol": "mysql",
        "database": "hr_production",
        "username": "guest",
        "query_normalized": sql,
        "outcome_verified": True,
        "success": True,
        "authority": "deception",
    }


def rule_decision(strategy_id="D1", allowed=None, default=None):
    allowed = allowed or ["D0", strategy_id]
    return {
        "strategy_id": strategy_id,
        "confidence": 1.0,
        "selector_type": "rule",
        "policy_version": "rule-v1",
        "allowed_actions": allowed,
        "rule_default_action": default or strategy_id,
    }


class AsyncStrategyAdapterTests(unittest.TestCase):
    def setUp(self):
        self.store = AuthoritativeStateStore(max_sessions=20)

    def wait_until(self, predicate, timeout=1.5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def test_successful_slow_path_stores_next_without_changing_current(self):
        captured = {}

        def request(payload, _timeout):
            captured.update(payload)
            return rule_decision("D1")

        self.store.apply_proxy_event(query("success"), "MySQL")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused", request_fn=request
        )
        try:
            self.assertTrue(adapter.schedule("success"))
            self.assertTrue(self.wait_until(
                lambda: self.store.get("success")["next_strategy_ready"]
            ))
            state = self.store.get("success")
            self.assertEqual(state["strategy_id"], "D0")
            self.assertEqual(state["next_strategy_id"], "D1")
            self.assertEqual(state["next_strategy_query_count"], 1)
            telemetry = self.store.get_session_strategy_telemetry("success")
            self.assertEqual(len(telemetry["records"]), 1)
            record = telemetry["records"][0]
            self.assertEqual(record["decision"]["selected_action"], "D1")
            self.assertEqual(record["decision"]["allowed_actions"], ["D0", "D1"])
            self.assertEqual(record["outcome"]["decision_id"], record["decision"]["decision_id"])
            encoded = str(captured)
            for forbidden in (
                "query_normalized", "fingerprint", "client_ip", "source_ip", "raw_sql"
            ):
                self.assertNotIn(forbidden, encoded)
        finally:
            adapter.stop()

    def test_schedule_never_waits_for_slow_request(self):
        entered = threading.Event()
        release = threading.Event()

        def slow_request(_payload, _timeout):
            entered.set()
            release.wait(1)
            return rule_decision("D1")

        self.store.apply_proxy_event(query("slow"), "MySQL")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused", request_fn=slow_request
        )
        try:
            started = time.monotonic()
            self.assertTrue(adapter.schedule("slow"))
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.05)
            self.assertTrue(entered.wait(0.5))
            self.assertEqual(self.store.get("slow")["strategy_id"], "D0")
        finally:
            release.set()
            adapter.stop()

    def test_request_failure_preserves_fallback_state(self):
        def failing_request(_payload, _timeout):
            raise TimeoutError("simulated")

        self.store.apply_proxy_event(query("failure"), "MySQL")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused", request_fn=failing_request
        )
        try:
            self.assertTrue(adapter.schedule("failure"))
            self.assertTrue(self.wait_until(
                lambda: adapter.stats()["failed"] == 1
            ))
            state = self.store.get("failure")
            self.assertEqual(state["strategy_id"], "D0")
            self.assertFalse(state["next_strategy_ready"])
        finally:
            adapter.stop()

    def test_stale_response_cannot_overwrite_newer_session_state(self):
        entered = threading.Event()
        release = threading.Event()

        def delayed_request(_payload, _timeout):
            entered.set()
            release.wait(1)
            return rule_decision("D1")

        self.store.apply_proxy_event(query("stale"), "MySQL")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused", request_fn=delayed_request
        )
        try:
            adapter.schedule("stale")
            self.assertTrue(entered.wait(0.5))
            self.store.apply_proxy_event(query(
                "stale", "select * from employees", "2026-01-01T00:00:01Z"
            ), "MySQL")
            release.set()
            self.assertTrue(self.wait_until(
                lambda: adapter.stats()["stale"] == 1
            ))
            self.assertFalse(self.store.get("stale")["next_strategy_ready"])
        finally:
            release.set()
            adapter.stop()

    def test_invalid_or_unapproved_decision_is_rejected(self):
        self.store.apply_proxy_event(query("invalid"), "MySQL")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused",
            request_fn=lambda _payload, _timeout: rule_decision("D5"),
        )
        try:
            adapter.schedule("invalid")
            self.assertTrue(self.wait_until(
                lambda: adapter.stats()["stale"] == 1
            ))
            self.assertFalse(self.store.get("invalid")["next_strategy_ready"])
        finally:
            adapter.stop()

    def test_missing_action_space_evidence_is_rejected(self):
        self.store.apply_proxy_event(query("missing-evidence"), "MySQL")
        incomplete = rule_decision("D1")
        incomplete.pop("allowed_actions")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused",
            request_fn=lambda _payload, _timeout: incomplete,
        )
        try:
            adapter.schedule("missing-evidence")
            self.assertTrue(self.wait_until(
                lambda: adapter.stats()["stale"] == 1
            ))
            self.assertFalse(
                self.store.get("missing-evidence")["next_strategy_ready"]
            )
            self.assertEqual(
                self.store.get_session_strategy_telemetry("missing-evidence")["records"],
                [],
            )
        finally:
            adapter.stop()

    def test_rule_selection_must_equal_guard_default(self):
        self.store.apply_proxy_event(query("forged-default"), "MySQL")
        forged = rule_decision("D1", allowed=["D0", "D1"], default="D0")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused",
            request_fn=lambda _payload, _timeout: forged,
        )
        try:
            adapter.schedule("forged-default")
            self.assertTrue(self.wait_until(
                lambda: adapter.stats()["stale"] == 1
            ))
            self.assertFalse(self.store.get("forged-default")["next_strategy_ready"])
            self.assertEqual(
                self.store.get_session_strategy_telemetry("forged-default")["records"],
                [],
            )
        finally:
            adapter.stop()

    def test_bounded_queue_drops_immediately_when_full(self):
        self.store.apply_proxy_event(query("one"), "MySQL")
        self.store.apply_proxy_event(query("two"), "MySQL")
        adapter = AsyncStrategyAdapter(
            self.store, "http://unused", queue_size=1,
            request_fn=lambda _payload, _timeout: rule_decision(),
            autostart=False,
        )
        try:
            self.assertTrue(adapter.schedule("one"))
            started = time.monotonic()
            self.assertFalse(adapter.schedule("two"))
            self.assertLess(time.monotonic() - started, 0.05)
            self.assertEqual(adapter.stats()["dropped"], 1)
        finally:
            adapter.stop(timeout=0)

    def test_snapshot_is_minimized_and_placeholder_persona_becomes_unknown(self):
        self.store.apply_proxy_event(query("snapshot"), "MySQL")
        snapshot = self.store.get_adaptation_snapshot("snapshot")
        self.assertEqual(snapshot["session_state"]["persona_id"], "unknown")
        self.assertEqual(snapshot["query_count"], 1)
        self.assertNotIn("last_query_fingerprint", snapshot["session_state"])
        self.assertNotIn("query_normalized", str(snapshot))

    def test_closed_or_missing_sessions_are_not_updated(self):
        self.assertIsNone(self.store.get_adaptation_snapshot("missing"))
        self.store.apply_proxy_event(query("closed"), "MySQL")
        self.store.apply_proxy_event({
            "session_id": "closed", "event_type": "session_end",
            "timestamp": "2026-01-01T00:00:01Z", "query_count": 1,
        }, "MySQL")
        self.assertFalse(self.store.set_next_strategy(
            "closed", rule_decision("D1"), 1
        ))


if __name__ == "__main__":
    unittest.main()

import json
import math
import time
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from async_adaptation import AsyncStrategyAdapter
from authoritative_state import AuthoritativeStateStore, start_state_api
from shadow_bandit import CONTEXT_VERSION, MODEL_VERSION, ContextEncoder, ShadowLinUCB


def snapshot(session_id="shadow-1", **behavior_changes):
    behavior = {
        "session_id": session_id,
        "protocol": "mysql",
        "risk_score": 0.5,
        "mitre_stage": "enumeration",
        "catalog_query_count": 2,
        "metadata_query_count": 1,
        "credential_keyword_count": 0,
        "backup_keyword_count": 1,
        "sensitive_table_interest": 0,
        "role_enumeration_count": 0,
        "privilege_escalation_attempts": 0,
        "destructive_query_count": 0,
        "trap_trigger_count": 0,
        "unique_table_count": 2,
        "unique_query_family_count": 3,
        "mitre_technique_count": 1,
        "session_depth": 4,
        "current_strategy": "D0",
    }
    behavior.update(behavior_changes)
    return {
        "session_state": {
            "session_id": session_id,
            "protocol": "mysql",
            "strategy_id": "D0",
        },
        "behavior_state": behavior,
        "mitre_state": {
            "session_id": session_id,
            "phase": behavior["mitre_stage"],
            "risk_score": 6.0,
        },
        "query_count": 4,
        "observed_at": "2026-01-01T00:00:04Z",
        "closed": False,
    }


def query(session_id, sql="show databases", timestamp="2026-01-01T00:00:00Z"):
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
        "success": True,
        "authority": "deception",
    }


def rule_response(strategy_id="D2"):
    return {
        "strategy_id": strategy_id,
        "confidence": 1.0,
        "selector_type": "rule",
        "policy_version": "rule-v1",
        "allowed_actions": ["D0", strategy_id],
        "rule_default_action": strategy_id,
    }


class ShadowBanditTests(unittest.TestCase):
    def test_context_is_deterministic_bounded_and_structured_only(self):
        first_vector, first_features = ContextEncoder.encode(snapshot())
        second_vector, second_features = ContextEncoder.encode(snapshot())
        self.assertEqual(first_vector, second_vector)
        self.assertEqual(first_features, second_features)
        self.assertEqual(len(first_vector), len(ContextEncoder.feature_names))
        self.assertTrue(all(0.0 <= value <= 1.0 for value in first_vector))
        hostile = snapshot()
        hostile["behavior_state"]["query_normalized"] = "drop table anything"
        with self.assertRaises(ValueError):
            ContextEncoder.encode(hostile)
        invalid = snapshot(risk_score=float("nan"))
        with self.assertRaises(ValueError):
            ContextEncoder.encode(invalid)

    def test_recommendation_is_allowed_shadow_only_and_never_execution(self):
        model = ShadowLinUCB(alpha=0.5)
        result = model.recommend(snapshot(), ["D0", "D2"], "D2")
        self.assertEqual(result["model_version"], MODEL_VERSION)
        self.assertEqual(result["context_version"], CONTEXT_VERSION)
        self.assertIn(result["model_recommended"], ["D0", "D2"])
        self.assertEqual(result["rule_selected"], "D2")
        self.assertEqual(result["actual_execution"], "D2")
        self.assertTrue(result["shadow_only"])
        self.assertFalse(result["controls_execution"])
        self.assertEqual(result["execution_source"], "rule-v1")
        self.assertEqual(set(result["scores"]), {"D0", "D2"})

    def test_calibrated_fixture_updates_can_change_recommendation(self):
        model = ShadowLinUCB(alpha=0.1)
        context = snapshot()
        for _index in range(12):
            model.update(
                "D2", context, 1.0,
                calibration_status="CALIBRATED",
                reward_profile_version="test-fixture-v1",
            )
            model.update(
                "D0", context, 0.0,
                calibration_status="CALIBRATED",
                reward_profile_version="test-fixture-v1",
            )
        recommendation = model.recommend(context, ["D0", "D2"], "D0")
        self.assertEqual(recommendation["model_recommended"], "D2")
        self.assertGreater(recommendation["confidence"], 0)
        self.assertEqual(model.stats()["updates"], 24)

    def test_uncalibrated_invalid_or_unsafe_updates_fail_closed(self):
        model = ShadowLinUCB()
        with self.assertRaises(ValueError):
            model.update(
                "D2", snapshot(), 0.5,
                calibration_status="REQUIRES_PHASE_10_CALIBRATION",
                reward_profile_version="",
            )
        with self.assertRaises(ValueError):
            model.update(
                "D5", snapshot(), 0.5,
                calibration_status="CALIBRATED",
                reward_profile_version="test-v1",
            )
        with self.assertRaises(ValueError):
            model.update(
                "D2", snapshot(), math.inf,
                calibration_status="CALIBRATED",
                reward_profile_version="test-v1",
            )
        self.assertEqual(model.stats()["updates"], 0)


class ShadowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.store = AuthoritativeStateStore(max_sessions=20)

    @staticmethod
    def wait_until(predicate, timeout=1.5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def completed_shadow(self, session_id="shadow-live"):
        self.store.apply_proxy_event(query(session_id), "MySQL")
        adapter = AsyncStrategyAdapter(
            self.store,
            "http://unused",
            request_fn=lambda _payload, _timeout: rule_response("D2"),
        )
        self.addCleanup(adapter.stop)
        adapter.schedule(session_id)
        self.assertTrue(self.wait_until(
            lambda: self.store.get(session_id)["next_strategy_ready"]
        ))
        self.store.apply_proxy_event({
            "session_id": session_id,
            "event_type": "session_end",
            "timestamp": "2026-01-01T00:00:05Z",
            "query_count": 1,
        }, "MySQL")
        adapter.schedule(session_id)
        self.assertTrue(self.wait_until(
            lambda: self.store.get_shadow_session(session_id)["status"] == "COMPLETE"
        ))
        return adapter

    def test_shadow_recommendation_cannot_change_rule_state_or_execution(self):
        adapter = self.completed_shadow()
        state = self.store.get("shadow-live")
        self.assertEqual(state["strategy_id"], "D0")
        self.assertEqual(state["next_strategy_id"], "D2")
        shadow = self.store.get_shadow_session("shadow-live")
        self.assertTrue(shadow["shadow_only"])
        self.assertFalse(shadow["controls_execution"])
        self.assertEqual(shadow["decision_count"], 1)
        record = shadow["records"][0]
        self.assertEqual(record["rule_selected"], "D2")
        self.assertEqual(record["actual_execution"], "D2")
        self.assertIn(record["model_recommended"], ["D0", "D2"])
        self.assertEqual(record["observed_actual_reward"]["status"], "COMPLETE")
        self.assertFalse(shadow["counterfactual_performance_claimed"])
        self.assertEqual(adapter.stats()["completed"], 1)
        self.assertEqual(self.store.get_shadow_model_stats()["updates"], 0)

    def test_invalid_shadow_metadata_is_discarded_without_losing_rule_telemetry(self):
        self.store.apply_proxy_event(query("forged-shadow"), "MySQL")
        snapshot_value = self.store.get_adaptation_snapshot("forged-shadow")
        forged = {
            "status": "AVAILABLE",
            "shadow_only": True,
            "controls_execution": True,
            "session_id": "forged-shadow",
            "rule_selected": "D2",
            "model_recommended": "D5",
            "actual_execution": "D5",
            "execution_source": "model",
        }
        decision = self.store.record_strategy_decision(
            snapshot_value, rule_response("D2"), shadow_evaluation=forged,
        )
        linked = self.store.get_strategy_telemetry(decision["decision_id"])
        self.assertNotIn("shadow_evaluation", linked["decision"])
        self.assertEqual(linked["decision"]["selected_action"], "D2")

    def test_read_only_shadow_endpoints_evaluate_rule_baseline(self):
        self.completed_shadow("shadow-api")
        telemetry = self.store.get_session_strategy_telemetry("shadow-api")
        decision_id = telemetry["records"][0]["decision"]["decision_id"]
        self.store.ready = True
        server = start_state_api(self.store, "127.0.0.1", 0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urlopen(f"{base}/shadow/decision/{decision_id}", timeout=2) as response:
            decision = json.load(response)
        with urlopen(f"{base}/shadow/session/shadow-api", timeout=2) as response:
            session = json.load(response)
        with urlopen(f"{base}/shadow/model", timeout=2) as response:
            model = json.load(response)
        self.assertEqual(decision["actual_execution"], "D2")
        self.assertEqual(session["decision_count"], 1)
        self.assertTrue(model["shadow_only"])
        self.assertFalse(model["controls_execution"])
        self.assertEqual(model["updates"], 0)
        with self.assertRaises(HTTPError) as missing:
            urlopen(f"{base}/shadow/decision/missing", timeout=2)
        self.assertEqual(missing.exception.code, 404)


if __name__ == "__main__":
    unittest.main()

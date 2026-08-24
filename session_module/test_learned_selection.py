import json
import time
import unittest
from urllib.request import urlopen

from async_adaptation import AsyncStrategyAdapter
from authoritative_state import AuthoritativeStateStore, start_state_api
from learned_selection import (
    BoundedLearnedSelector,
    LEARNED_OPERATOR_MODE,
    LEARNED_POLICY_VERSION,
    SELECTION_VERSION,
    validate_executable_decision,
)
from shadow_bandit import CONTEXT_VERSION, MODEL_VERSION, ShadowLinUCB


def rule_decision(default="D0"):
    return {
        "strategy_id": default,
        "confidence": 1.0,
        "selector_type": "rule",
        "policy_version": "rule-v1",
        "allowed_actions": ["D0", "D2"],
        "rule_default_action": default,
    }


def model_evaluation(**changes):
    payload = {
        "status": "AVAILABLE",
        "session_id": "unit-session",
        "shadow_only": True,
        "controls_execution": False,
        "model_version": MODEL_VERSION,
        "context_version": CONTEXT_VERSION,
        "allowed_actions": ["D0", "D2"],
        "rule_selected": "D0",
        "model_recommended": "D2",
        "actual_execution": "D0",
        "execution_source": "rule-v1",
        "confidence": 0.9,
        "scores": {"D0": 0.0, "D2": 9.0},
        "context_features": {"bias": 1.0},
        "training_updates": 20,
        "calibration_status": "CALIBRATED",
        "reward_profile_version": "controlled-calibration-v1",
    }
    payload.update(changes)
    return payload


def query(session_id, timestamp="2026-01-01T00:00:00Z"):
    return {
        "session_id": session_id,
        "event_type": "query",
        "timestamp": timestamp,
        "protocol": "mysql",
        "database": "fictional_hr",
        "username": "decoy_guest",
        "query_normalized": "show databases",
        "outcome_verified": True,
        "success": True,
        "authority": "deception",
    }


class BoundedLearnedSelectorTests(unittest.TestCase):
    def setUp(self):
        self.selector = BoundedLearnedSelector(0.75, 20)

    def test_calibrated_confident_model_can_select_only_an_allowed_action(self):
        selected = self.selector.select(
            rule_decision(), model_evaluation(), LEARNED_OPERATOR_MODE
        )
        self.assertEqual(selected["strategy_id"], "D2")
        self.assertEqual(selected["selector_type"], "learned")
        self.assertEqual(selected["policy_version"], LEARNED_POLICY_VERSION)
        self.assertTrue(selected["learned_control"])
        self.assertTrue(validate_executable_decision(
            selected,
            expected_confidence_threshold=0.75,
            expected_minimum_updates=20,
        ))

    def test_rule_mode_unavailable_low_confidence_and_uncalibrated_fall_back(self):
        cases = (
            ("RULE_ADAPTIVE", model_evaluation(), "operator_mode_rule"),
            (LEARNED_OPERATOR_MODE, None, "model_unavailable"),
            (
                LEARNED_OPERATOR_MODE,
                model_evaluation(
                    confidence=0.74,
                    scores={"D0": 0.0, "D2": 2.846153846},
                ),
                "low_confidence",
            ),
            (
                LEARNED_OPERATOR_MODE,
                model_evaluation(calibration_status="UNCALIBRATED"),
                "model_uncalibrated",
            ),
            (
                LEARNED_OPERATOR_MODE,
                model_evaluation(training_updates=19),
                "model_uncalibrated",
            ),
        )
        for mode, evaluation, reason in cases:
            with self.subTest(reason=reason):
                selected = self.selector.select(rule_decision(), evaluation, mode)
                self.assertEqual(selected["strategy_id"], "D0")
                self.assertEqual(selected["selector_type"], "rule")
                self.assertFalse(selected["learned_control"])
                self.assertEqual(selected["selection_reason"], reason)

    def test_invalid_or_action_space_expanding_model_fails_closed(self):
        for forged in (
            model_evaluation(model_recommended="D5"),
            model_evaluation(allowed_actions=["D0", "D2", "D5"]),
            model_evaluation(controls_execution=True),
            model_evaluation(model_version="forged"),
            model_evaluation(confidence=float("nan")),
        ):
            with self.subTest(forged=forged):
                selected = self.selector.select(
                    rule_decision(), forged, LEARNED_OPERATOR_MODE
                )
                self.assertEqual(selected["strategy_id"], "D0")
                self.assertEqual(selected["selection_reason"], "invalid_model_output")
        cross_session = self.selector.select(
            rule_decision(),
            model_evaluation(session_id="other-session"),
            LEARNED_OPERATOR_MODE,
            expected_session_id="unit-session",
        )
        self.assertEqual(cross_session["strategy_id"], "D0")
        self.assertEqual(cross_session["selection_reason"], "invalid_model_output")

    def test_forged_executable_learned_evidence_is_rejected(self):
        valid = self.selector.select(
            rule_decision(), model_evaluation(), LEARNED_OPERATOR_MODE
        )
        for field, value in (
            ("strategy_id", "D5"),
            ("confidence", 0.5),
            ("training_updates", 1),
            ("calibration_status", "UNCALIBRATED"),
            ("learned_control", False),
        ):
            forged = dict(valid)
            forged[field] = value
            self.assertFalse(validate_executable_decision(
                forged,
                expected_confidence_threshold=0.75,
                expected_minimum_updates=20,
            ))


class BoundedLearnedIntegrationTests(unittest.TestCase):
    @staticmethod
    def wait_until(predicate, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def trained_store(self, session_id, *, operator_mode=LEARNED_OPERATOR_MODE):
        bandit = ShadowLinUCB(alpha=0.05)
        store = AuthoritativeStateStore(
            max_sessions=20,
            shadow_bandit=bandit,
            learned_confidence_threshold=0.01,
            learned_minimum_updates=10,
        )
        store.apply_proxy_event(query(session_id), "MySQL")
        snapshot = store.get_adaptation_snapshot(session_id)
        for _index in range(12):
            bandit.update(
                "D2", snapshot, 1.0,
                calibration_status="CALIBRATED",
                reward_profile_version="controlled-calibration-v1",
            )
            bandit.update(
                "D0", snapshot, 0.0,
                calibration_status="CALIBRATED",
                reward_profile_version="controlled-calibration-v1",
            )
        adapter = AsyncStrategyAdapter(
            store,
            "http://unused",
            operator_mode=operator_mode,
            request_fn=lambda _payload, _timeout: rule_decision(),
        )
        self.addCleanup(adapter.stop)
        return store, adapter

    def test_learned_choice_changes_only_next_strategy_and_is_traceable(self):
        store, adapter = self.trained_store("learned-live")
        adapter.schedule("learned-live")
        self.assertTrue(self.wait_until(
            lambda: store.get("learned-live")["next_strategy_ready"]
        ))
        state = store.get("learned-live")
        self.assertEqual(state["strategy_id"], "D0")
        self.assertEqual(state["next_strategy_id"], "D2")
        self.assertEqual(state["next_strategy_selector_type"], "learned")
        self.assertEqual(
            state["next_strategy_policy_version"], LEARNED_POLICY_VERSION
        )
        telemetry = store.get_session_strategy_telemetry("learned-live")
        decision = telemetry["records"][0]["decision"]
        self.assertEqual(decision["rule_default_action"], "D0")
        self.assertEqual(decision["selected_action"], "D2")
        self.assertEqual(decision["selection_version"], SELECTION_VERSION)
        self.assertTrue(decision["learned_control"])
        self.assertEqual(adapter.stats()["learned_selected"], 1)

        store.apply_proxy_event({
            "session_id": "learned-live",
            "event_type": "session_end",
            "timestamp": "2026-01-01T00:00:05Z",
            "query_count": 1,
        }, "MySQL")
        adapter.schedule("learned-live")
        self.assertTrue(self.wait_until(
            lambda: store.get_decision_reward(decision["decision_id"])["status"]
            == "COMPLETE"
        ))
        reward = store.get_decision_reward(decision["decision_id"])
        self.assertEqual(reward["dimensions"]["safety_penalty"]["count"], 0)
        self.assertNotIn("query_normalized", json.dumps(telemetry))

    def test_rule_mode_ignores_trained_model(self):
        store, adapter = self.trained_store(
            "rule-live", operator_mode="RULE_ADAPTIVE"
        )
        adapter.schedule("rule-live")
        self.assertTrue(self.wait_until(
            lambda: store.get("rule-live")["next_strategy_ready"]
        ))
        state = store.get("rule-live")
        self.assertEqual(state["next_strategy_id"], "D0")
        self.assertEqual(state["next_strategy_selector_type"], "rule")
        self.assertEqual(adapter.stats()["learned_selected"], 0)
        self.assertEqual(adapter.stats()["rule_fallback"], 1)

    def test_uncalibrated_runtime_model_falls_back_and_policy_is_read_only(self):
        store = AuthoritativeStateStore(max_sessions=20)
        store.apply_proxy_event(query("uncalibrated"), "MySQL")
        adapter = AsyncStrategyAdapter(
            store,
            "http://unused",
            operator_mode=LEARNED_OPERATOR_MODE,
            request_fn=lambda _payload, _timeout: rule_decision("D2"),
        )
        self.addCleanup(adapter.stop)
        adapter.schedule("uncalibrated")
        self.assertTrue(self.wait_until(
            lambda: store.get("uncalibrated")["next_strategy_ready"]
        ))
        self.assertEqual(store.get("uncalibrated")["next_strategy_id"], "D2")
        self.assertEqual(
            store.get("uncalibrated")["next_strategy_selector_type"], "rule"
        )
        record = store.get_session_strategy_telemetry("uncalibrated")["records"][0]
        self.assertEqual(
            record["decision"]["selection_reason"], "model_uncalibrated"
        )

        store.ready = True
        server = start_state_api(store, "127.0.0.1", 0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urlopen(f"{base}/selection/policy", timeout=2) as response:
            policy = json.load(response)
        self.assertEqual(policy["selection_version"], SELECTION_VERSION)
        self.assertEqual(policy["fallback"], "rule_default")
        self.assertEqual(policy["model"]["calibration_status"], "UNCALIBRATED")


if __name__ == "__main__":
    unittest.main()

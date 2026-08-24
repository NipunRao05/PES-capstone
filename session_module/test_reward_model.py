import copy
import json
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from authoritative_state import AuthoritativeStateStore, start_state_api
from reward_model import CALIBRATION_STATUS, REWARD_VERSION, DeceptionRewardModel


def linked_record(decision_id="SD-test-1", *, final=True):
    return {
        "decision": {
            "decision_id": decision_id,
            "session_id": "reward-session",
            "selected_action": "D2",
            "allowed_actions": ["D0", "D2"],
            "rule_default_action": "D2",
            "selector_type": "rule",
            "confidence": 1.0,
            "policy_version": "rule-v1",
        },
        "outcome": {
            "decision_id": decision_id,
            "session_id": "reward-session",
            "queries_after_decision": 4,
            "session_duration_after_decision": 30.5,
            "new_query_families": 3,
            "new_tables_accessed": 2,
            "new_MITRE_techniques": 1,
            "trap_interactions": 1,
            "attacker_progression": {
                "from_stage": "enumeration",
                "to_stage": "collection",
                "advanced": True,
            },
            "errors": 2,
            "protocol_errors": 1,
            "state_inconsistencies": 0,
            "latency": 4.25,
            "CPU_cost": 1.5,
            "memory_cost": 768,
            "final": final,
        },
    }


def query(session_id, sql, timestamp, *, verified=True):
    return {
        "session_id": session_id,
        "event_type": "query",
        "timestamp": timestamp,
        "protocol": "mysql",
        "database": "fictional_hr",
        "username": "decoy_guest",
        "query_normalized": sql,
        "fingerprint": "must-not-reach-reward",
        "outcome_verified": verified,
        "success": True,
        "authority": "deception",
    }


def response():
    return {
        "strategy_id": "D1",
        "confidence": 1.0,
        "selector_type": "rule",
        "policy_version": "rule-v1",
        "allowed_actions": ["D0", "D1"],
        "rule_default_action": "D1",
    }


class DeceptionRewardModelTests(unittest.TestCase):
    def setUp(self):
        self.model = DeceptionRewardModel()

    def test_completed_decision_produces_all_unweighted_dimensions(self):
        first = self.model.decision(linked_record())
        second = self.model.decision(linked_record())
        self.assertEqual(first, second)
        self.assertEqual(first["reward_version"], REWARD_VERSION)
        self.assertEqual(first["status"], "COMPLETE")
        self.assertEqual(first["calibration_status"], CALIBRATION_STATUS)
        self.assertIsNone(first["weight_profile"])
        self.assertIsNone(first["composite_reward"])
        self.assertEqual(set(first["dimensions"]), {
            "engagement", "intelligence_gain", "behavior_novelty",
            "MITRE_progression", "meaningful_trap_interaction",
            "latency_penalty", "resource_penalty",
            "protocol_error_penalty", "state_inconsistency_penalty",
            "safety_penalty",
        })
        self.assertEqual(
            first["dimensions"]["engagement"]["queries_after_decision"], 4
        )
        self.assertEqual(
            first["dimensions"]["meaningful_trap_interaction"]["interactions"], 1
        )
        self.assertEqual(
            first["dimensions"]["protocol_error_penalty"]["count"], 1
        )
        self.assertEqual(first["dimensions"]["safety_penalty"]["count"], 0)

    def test_session_reward_is_reproducible_mean_of_decision_vectors(self):
        first = linked_record("SD-one")
        second = linked_record("SD-two")
        second["outcome"]["queries_after_decision"] = 2
        second["outcome"]["latency"] = 6.25
        session = {
            "session_id": "reward-session",
            "records": [first, second],
        }
        reward = self.model.session(session)
        self.assertEqual(reward, self.model.session(copy.deepcopy(session)))
        self.assertEqual(reward["status"], "COMPLETE")
        self.assertEqual(reward["decision_count"], 2)
        self.assertEqual(
            reward["aggregate_dimensions"]["engagement"]["queries_after_decision"],
            3.0,
        )
        self.assertEqual(
            reward["aggregate_dimensions"]["latency_penalty"]["milliseconds"],
            5.25,
        )
        self.assertIsNone(reward["composite_reward"])

    def test_open_decision_and_session_remain_pending(self):
        pending = linked_record(final=False)
        decision = self.model.decision(pending)
        session = self.model.session({
            "session_id": "reward-session", "records": [pending],
        })
        self.assertEqual(decision["status"], "PENDING")
        self.assertIsNone(decision["dimensions"])
        self.assertEqual(session["status"], "PENDING")
        self.assertIsNone(session["aggregate_dimensions"])

    def test_invalid_linkage_and_nonfinite_values_fail_closed(self):
        mismatched = linked_record()
        mismatched["outcome"]["decision_id"] = "other"
        with self.assertRaises(ValueError):
            self.model.decision(mismatched)
        invalid = linked_record()
        invalid["outcome"]["latency"] = float("nan")
        with self.assertRaises(ValueError):
            self.model.decision(invalid)
        negative = linked_record()
        negative["outcome"]["trap_interactions"] = -1
        with self.assertRaises(ValueError):
            self.model.decision(negative)

    def test_forged_selection_receives_safety_penalty(self):
        forged = linked_record()
        forged["decision"]["selected_action"] = "D5"
        self.assertEqual(
            self.model.decision(forged)["dimensions"]["safety_penalty"]["count"],
            1,
        )
        forged["decision"]["rule_default_action"] = "D5"
        forged["decision"]["allowed_actions"] = ["D5"]
        self.assertEqual(
            self.model.decision(forged)["dimensions"]["safety_penalty"]["count"],
            1,
        )

    def test_missing_penalty_evidence_and_cross_session_records_fail_closed(self):
        missing = linked_record()
        missing["outcome"].pop("protocol_errors")
        with self.assertRaises(ValueError):
            self.model.decision(missing)
        cross_session = linked_record()
        cross_session["decision"]["session_id"] = "other-session"
        cross_session["outcome"]["session_id"] = "other-session"
        with self.assertRaises(ValueError):
            self.model.session({
                "session_id": "reward-session", "records": [cross_session],
            })
        duplicate = linked_record()
        with self.assertRaises(ValueError):
            self.model.session({
                "session_id": "reward-session",
                "records": [duplicate, copy.deepcopy(duplicate)],
            })


class RewardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.store = AuthoritativeStateStore(max_sessions=20)

    def completed_reward(self, session_id="reward-live"):
        self.store.apply_proxy_event(query(
            session_id, "show databases", "2026-01-01T00:00:00Z"
        ), "MySQL")
        snapshot = self.store.get_adaptation_snapshot(session_id)
        self.assertTrue(self.store.set_next_strategy(session_id, response(), 1))
        decision = self.store.record_strategy_decision(
            snapshot, response(), latency_ms=2, cpu_cost_ms=1,
            memory_cost_bytes=256,
        )
        self.store.apply_proxy_event(query(
            session_id,
            "select * from backup_catalog",
            "2026-01-01T00:00:05Z",
            verified=False,
        ), "MySQL")
        self.store.apply_proxy_event({
            "session_id": session_id,
            "event_type": "session_end",
            "timestamp": "2026-01-01T00:00:10Z",
            "query_count": 2,
        }, "MySQL")
        self.store.observe_strategy_outcomes(
            self.store.get_adaptation_snapshot(session_id)
        )
        return decision

    def test_completed_projected_session_produces_decision_and_session_rewards(self):
        decision = self.completed_reward()
        reward = self.store.get_decision_reward(decision["decision_id"])
        session_reward = self.store.get_session_reward("reward-live")
        self.assertEqual(reward["status"], "COMPLETE")
        self.assertEqual(session_reward["status"], "COMPLETE")
        self.assertEqual(
            reward["dimensions"]["protocol_error_penalty"]["count"], 1
        )
        self.assertEqual(
            reward["dimensions"]["state_inconsistency_penalty"]["count"], 0
        )
        self.assertEqual(reward["dimensions"]["safety_penalty"]["count"], 0)
        encoded = json.dumps({"reward": reward, "session": session_reward})
        self.assertNotIn("query_normalized", encoded)
        self.assertNotIn("must-not-reach-reward", encoded)

    def test_read_only_reward_endpoints(self):
        decision = self.completed_reward("reward-api")
        self.store.ready = True
        server = start_state_api(self.store, "127.0.0.1", 0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urlopen(
            f"{base}/reward/decision/{decision['decision_id']}", timeout=2
        ) as response_body:
            decision_reward = json.load(response_body)
        with urlopen(f"{base}/reward/session/reward-api", timeout=2) as response_body:
            session_reward = json.load(response_body)
        self.assertEqual(decision_reward["status"], "COMPLETE")
        self.assertEqual(session_reward["status"], "COMPLETE")
        with self.assertRaises(HTTPError) as missing:
            urlopen(f"{base}/reward/decision/missing", timeout=2)
        self.assertEqual(missing.exception.code, 404)


if __name__ == "__main__":
    unittest.main()

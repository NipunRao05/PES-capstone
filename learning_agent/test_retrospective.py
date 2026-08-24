import copy
import json
import unittest

from client import SafeInternalEvidenceClient
from retrospective import ANALYSIS_VERSION, RetrospectiveLearningAgent


def registry():
    return {
        "registry_version": "strategy-registry-v1",
        "degraded": False,
        "approved_strategy_ids": ["D0", "D1", "D2"],
        "strategies": [
            {
                "strategy_id": "D0", "name": "BASELINE",
                "validation_version": "phase3-v1", "approval_status": "APPROVED",
            },
            {
                "strategy_id": "D1", "name": "CATALOG_RECON_LURE",
                "validation_version": "phase3-v1", "approval_status": "APPROVED",
            },
            {
                "strategy_id": "D2", "name": "BACKUP_LURE",
                "validation_version": "phase3-v1", "approval_status": "APPROVED",
            },
            {
                "strategy_id": "D5", "name": "PRIVILEGE_LURE",
                "validation_version": "phase3-v1",
                "approval_status": "REQUIRES_REVIEW",
            },
        ],
    }


def dimensions(*, traps=0, techniques=0, safety=0):
    return {
        "engagement": {"queries_after_decision": 2, "duration_seconds": 4.0},
        "intelligence_gain": {"new_tables": 1, "new_MITRE_techniques": techniques},
        "behavior_novelty": {"new_query_families": 1},
        "MITRE_progression": {
            "advanced": 1 if techniques else 0,
            "from_stage": "enumeration", "to_stage": "collection",
        },
        "meaningful_trap_interaction": {"interactions": traps},
        "latency_penalty": {"milliseconds": 2.0},
        "resource_penalty": {"CPU_milliseconds": 0.2, "serialized_bytes": 512},
        "protocol_error_penalty": {"count": 0},
        "state_inconsistency_penalty": {"count": 0},
        "safety_penalty": {"count": safety},
    }


def decision(decision_id, selected, allowed, timestamp, *, trap=0, techniques=0):
    return {
        "decision": {
            "telemetry_version": "strategy-telemetry-v1",
            "decision_id": decision_id,
            "session_id": "session-13",
            "timestamp": timestamp,
            "allowed_actions": allowed,
            "rule_default_action": selected,
            "selected_action": selected,
            "selector_type": "rule",
            "confidence": 1.0,
            "policy_version": "rule-v1",
            "state_before": {
                "session_state": {
                    "session_id": "session-13", "protocol": "mysql",
                    "persona_id": "unknown", "strategy_id": "D0",
                },
                "behavior_state": {
                    "session_id": "session-13", "protocol": "mysql",
                    "risk_score": 0.7, "session_depth": 3,
                },
                "mitre_state": {"session_id": "session-13", "phase": "enumeration"},
            },
            "shadow_evaluation": {
                "status": "AVAILABLE", "agreement": False,
                "calibration_status": "UNCALIBRATED", "model_recommended": "D0",
            },
        },
        "outcome": {
            "telemetry_version": "strategy-telemetry-v1",
            "decision_id": decision_id,
            "session_id": "session-13",
            "queries_after_decision": 2,
            "session_duration_after_decision": 4.0,
            "new_query_families": 1,
            "new_tables_accessed": 1,
            "new_MITRE_techniques": techniques,
            "trap_interactions": trap,
            "attacker_progression": {
                "from_stage": "enumeration", "to_stage": "collection",
                "advanced": bool(techniques),
            },
            "disconnect_time": "2026-01-01T00:00:10Z",
            "errors": 0, "protocol_errors": 0, "state_inconsistencies": 0,
            "latency": 2.0, "CPU_cost": 0.2, "memory_cost": 512,
            "final": True,
        },
    }


def evidence():
    first = decision(
        "SD-first", "D1", ["D0", "D1"], "2026-01-01T00:00:01Z",
        trap=1, techniques=1,
    )
    second = decision(
        "SD-second", "D0", ["D0", "D1", "D2"], "2026-01-01T00:00:05Z"
    )
    telemetry = {"session_id": "session-13", "records": [first, second]}
    rewards = []
    for item, values in ((first, dimensions(traps=1, techniques=1)), (second, dimensions())):
        rewards.append({
            "reward_version": "deception-reward-v1", "status": "COMPLETE",
            "decision_id": item["decision"]["decision_id"],
            "session_id": "session-13",
            "selected_action": item["decision"]["selected_action"],
            "calibration_status": "REQUIRES_PHASE_10_CALIBRATION",
            "weight_profile": None, "composite_reward": None,
            "dimensions": values,
        })
    reward = {
        "reward_version": "deception-reward-v1", "status": "COMPLETE",
        "session_id": "session-13", "decision_count": 2,
        "calibration_status": "REQUIRES_PHASE_10_CALIBRATION",
        "weight_profile": None, "composite_reward": None,
        "aggregation": "per-decision-arithmetic-mean",
        "per_decision": rewards,
        "aggregate_dimensions": {"engagement": {"queries_after_decision": 2.0}},
    }
    return telemetry, reward, registry()


class RetrospectiveLearningAgentTests(unittest.TestCase):
    def setUp(self):
        self.agent = RetrospectiveLearningAgent()

    def test_complete_analysis_is_deterministic_and_evidence_linked(self):
        inputs = evidence()
        first = self.agent.analyze(*copy.deepcopy(inputs))
        second = self.agent.analyze(*copy.deepcopy(inputs))
        self.assertEqual(first, second)
        self.assertEqual(first["analysis_version"], ANALYSIS_VERSION)
        self.assertTrue(first["analysis_id"].startswith("LA-"))
        self.assertEqual(len(first["evidence"]["input_sha256"]), 64)
        self.assertEqual(first["evidence"]["decision_ids"], ["SD-first", "SD-second"])
        self.assertEqual(first["session_reconstruction"]["protocol"], "mysql")
        self.assertEqual(first["session_reconstruction"]["decision_count"], 2)

    def test_every_decision_is_evaluated_and_important_decisions_are_identified(self):
        report = self.agent.analyze(*evidence())
        self.assertEqual(len(report["decision_evaluations"]), 2)
        first = report["decision_evaluations"][0]
        self.assertTrue(first["important"])
        self.assertIn("trap_interaction", first["importance_reasons"])
        self.assertIn("mitre_progression", first["importance_reasons"])
        self.assertEqual(
            report["session_reconstruction"]["important_decision_ids"],
            ["SD-first", "SD-second"],
        )

    def test_alternatives_are_only_approved_and_ranked_by_evidence_availability(self):
        report = self.agent.analyze(*evidence())
        first_alternatives = report["decision_evaluations"][0][
            "approved_alternative_ranking"
        ]["alternatives"]
        self.assertEqual([item["strategy_id"] for item in first_alternatives], ["D0"])
        self.assertEqual(first_alternatives[0]["observed_in_same_session"], 1)
        self.assertEqual(first_alternatives[0]["supporting_decision_ids"], ["SD-second"])
        second_alternatives = report["decision_evaluations"][1][
            "approved_alternative_ranking"
        ]["alternatives"]
        self.assertEqual([item["strategy_id"] for item in second_alternatives], ["D1", "D2"])
        self.assertTrue(all(item["estimated_performance"] is None for item in second_alternatives))

    def test_later_phase_work_is_explicitly_deferred_and_authority_is_zero(self):
        report = self.agent.analyze(*evidence())
        evaluation = report["decision_evaluations"][0]
        self.assertEqual(evaluation["similar_session_comparison"]["status"], "DEFERRED_PHASE_14")
        self.assertEqual(evaluation["counterfactual_estimate"]["status"], "DEFERRED_PHASE_14")
        self.assertIsNone(evaluation["counterfactual_estimate"]["claim"])
        self.assertEqual(evaluation["coverage_gap_assessment"]["status"], "DEFERRED_PHASE_15")
        self.assertTrue(report["authority"]["read_only"])
        self.assertFalse(report["authority"]["live_policy_mutation"])
        self.assertFalse(report["authority"]["model_training"])
        self.assertFalse(report["authority"]["strategy_activation"])

    def test_raw_incomplete_mismatched_duplicate_and_unapproved_evidence_is_rejected(self):
        mutations = []
        telemetry, reward, strategies = evidence()
        raw = copy.deepcopy(telemetry)
        raw["records"][0]["decision"]["query_normalized"] = "select secret"
        mutations.append((raw, reward, strategies))
        incomplete = copy.deepcopy(telemetry)
        incomplete["records"][0]["outcome"]["final"] = False
        mutations.append((incomplete, reward, strategies))
        mismatch_reward = copy.deepcopy(reward)
        mismatch_reward["per_decision"][0]["session_id"] = "other"
        mutations.append((telemetry, mismatch_reward, strategies))
        duplicate = copy.deepcopy(telemetry)
        duplicate["records"][1] = copy.deepcopy(duplicate["records"][0])
        mutations.append((duplicate, reward, strategies))
        unapproved = copy.deepcopy(telemetry)
        unapproved["records"][0]["decision"]["allowed_actions"].append("D5")
        mutations.append((unapproved, reward, strategies))
        forged_version = copy.deepcopy(telemetry)
        forged_version["records"][0]["decision"]["telemetry_version"] = "forged"
        mutations.append((forged_version, reward, strategies))
        duplicate_action = copy.deepcopy(telemetry)
        duplicate_action["records"][0]["decision"]["allowed_actions"].append("D0")
        mutations.append((duplicate_action, reward, strategies))
        forged_reward = copy.deepcopy(reward)
        forged_reward["per_decision"][0]["dimensions"]["engagement"][
            "queries_after_decision"
        ] = 999
        mutations.append((telemetry, forged_reward, strategies))
        fractional_count = copy.deepcopy(reward)
        fractional_count["per_decision"][0]["dimensions"]["engagement"][
            "queries_after_decision"
        ] = 0.5
        mutations.append((telemetry, fractional_count, strategies))
        malformed_action = copy.deepcopy(telemetry)
        malformed_action["records"][0]["decision"]["allowed_actions"] = [{}]
        mutations.append((malformed_action, reward, strategies))
        for values in mutations:
            with self.subTest():
                with self.assertRaises(ValueError):
                    self.agent.analyze(*copy.deepcopy(values))

    def test_output_excludes_raw_text_and_unbounded_identity_fields(self):
        report = self.agent.analyze(*evidence())
        encoded = json.dumps(report)
        for forbidden in (
            "query_normalized", "source_ip", "client_ip", "fingerprint",
            "username", "database",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(report["evidence"]["raw_attacker_text_used"])


class SafeInternalEvidenceClientTests(unittest.TestCase):
    def test_only_fixed_internal_http_endpoints_are_allowed(self):
        valid = SafeInternalEvidenceClient(
            "http://127.0.0.1:8003", "http://deception-engine:8001"
        )
        self.assertEqual(valid.session_base_url, "http://127.0.0.1:8003")
        for session_url, registry_url in (
            ("https://127.0.0.1:8003", "http://deception-engine:8001"),
            ("http://example.com:8003", "http://deception-engine:8001"),
            ("http://user:pass@127.0.0.1:8003", "http://deception-engine:8001"),
            ("http://127.0.0.1:9000", "http://deception-engine:8001"),
            ("http://127.0.0.1:8003?x=1", "http://deception-engine:8001"),
        ):
            with self.subTest(session_url=session_url):
                with self.assertRaises(ValueError):
                    SafeInternalEvidenceClient(session_url, registry_url)

    def test_session_identifier_is_strictly_bounded_before_network_use(self):
        client = SafeInternalEvidenceClient()
        for session_id in ("", "../escape", "value?query", "a" * 257):
            with self.subTest(session_id=session_id):
                with self.assertRaises(ValueError):
                    client.load_session(session_id)


if __name__ == "__main__":
    unittest.main()

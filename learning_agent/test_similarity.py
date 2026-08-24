import copy
import json
import unittest

from client import SafeInternalEvidenceClient
from similarity import (
    CONTEXT_VERSION,
    COUNTERFACTUAL_VERSION,
    ContextNormalizer,
    SimilarSessionEvaluator,
)
from test_retrospective import dimensions, evidence, registry


def bundle(
    session_id,
    selected,
    *,
    decision_id=None,
    protocol="mysql",
    risk=0.7,
    stage="enumeration",
    traps=0,
    techniques=0,
):
    telemetry, reward, _strategies = evidence()
    linked = copy.deepcopy(telemetry["records"][0])
    decision_id = decision_id or f"SD-{session_id}"
    linked["decision"]["decision_id"] = decision_id
    linked["decision"]["session_id"] = session_id
    linked["decision"]["selected_action"] = selected
    linked["decision"]["rule_default_action"] = selected
    linked["decision"]["allowed_actions"] = ["D0", "D1", "D2"]
    linked["decision"]["shadow_evaluation"]["model_recommended"] = "D0"
    states = linked["decision"]["state_before"]
    states["session_state"]["session_id"] = session_id
    states["session_state"]["protocol"] = protocol
    states["behavior_state"].update({
        "session_id": session_id,
        "protocol": protocol,
        "risk_score": risk,
        "mitre_stage": stage,
        "catalog_query_count": 2,
        "metadata_query_count": 3,
        "unique_query_family_count": 2,
        "current_strategy": "D0",
    })
    states["mitre_state"].update({"session_id": session_id, "phase": stage})
    linked["outcome"].update({
        "decision_id": decision_id,
        "session_id": session_id,
        "queries_after_decision": 2,
        "session_duration_after_decision": 4.0,
        "new_query_families": 1,
        "new_tables_accessed": 1,
        "new_MITRE_techniques": techniques,
        "trap_interactions": traps,
        "attacker_progression": {
            "from_stage": "enumeration", "to_stage": "collection",
            "advanced": bool(techniques),
        },
        "latency": 2.0,
        "CPU_cost": 0.2,
        "memory_cost": 512,
        "protocol_errors": 0,
        "state_inconsistencies": 0,
        "final": True,
    })
    values = dimensions(traps=traps, techniques=techniques)
    reward_item = {
        "reward_version": "deception-reward-v1",
        "status": "COMPLETE",
        "decision_id": decision_id,
        "session_id": session_id,
        "selected_action": selected,
        "calibration_status": "REQUIRES_PHASE_10_CALIBRATION",
        "weight_profile": None,
        "composite_reward": None,
        "dimensions": values,
    }
    return {
        "telemetry": {"session_id": session_id, "records": [linked]},
        "reward": {
            "reward_version": "deception-reward-v1",
            "status": "COMPLETE",
            "session_id": session_id,
            "decision_count": 1,
            "calibration_status": "REQUIRES_PHASE_10_CALIBRATION",
            "weight_profile": None,
            "composite_reward": None,
            "aggregation": "per-decision-arithmetic-mean",
            "per_decision": [reward_item],
            "aggregate_dimensions": values,
        },
    }


class ContextNormalizerTests(unittest.TestCase):
    def test_context_is_deterministic_bounded_and_structured_only(self):
        target = bundle("normalization", "D0")
        state = target["telemetry"]["records"][0]["decision"]["state_before"]
        first = ContextNormalizer.normalize(copy.deepcopy(state))
        second = ContextNormalizer.normalize(copy.deepcopy(state))
        self.assertEqual(first, second)
        self.assertEqual(first["context_version"], CONTEXT_VERSION)
        self.assertTrue(all(0.0 <= value <= 1.0 for value in first["vector"]))
        encoded = json.dumps(first)
        self.assertNotIn("select secret", encoded)
        self.assertNotIn("database", first)
        self.assertNotIn("user", first)
        for forbidden in ("query", "query_raw", "raw_sql", "source_ip"):
            self.assertNotIn(forbidden, first["features"])

    def test_invalid_protocol_risk_and_current_strategy_are_rejected(self):
        target = bundle("invalid-context", "D0")
        state = target["telemetry"]["records"][0]["decision"]["state_before"]
        for mutation in (
            ("session_state", "protocol", "oracle"),
            ("behavior_state", "risk_score", 1.1),
            ("behavior_state", "current_strategy", "D5"),
        ):
            invalid = copy.deepcopy(state)
            invalid[mutation[0]][mutation[1]] = mutation[2]
            if mutation[1] == "protocol":
                invalid["behavior_state"]["protocol"] = mutation[2]
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    ContextNormalizer.normalize(invalid)


class SimilarSessionEvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.target = bundle("target-14", "D1", decision_id="SD-target")
        self.history = [
            bundle("history-a", "D0", risk=0.69, traps=1),
            bundle("history-b", "D0", risk=0.72, techniques=1),
            bundle("history-c", "D1", risk=0.71),
        ]
        self.agent = SimilarSessionEvaluator(neighbor_limit=5, max_distance=0.65)

    def analyze(self, history=None):
        history = self.history if history is None else history
        return self.agent.analyze(
            self.target["telemetry"], self.target["reward"], history, registry()
        )

    def test_analysis_is_deterministic_evidence_linked_and_read_only(self):
        first = self.analyze()
        second = self.analyze(copy.deepcopy(self.history))
        self.assertEqual(first, second)
        self.assertEqual(first["analysis_version"], COUNTERFACTUAL_VERSION)
        self.assertTrue(first["analysis_id"].startswith("CF-"))
        self.assertEqual(first["evidence"]["historical_session_ids"], [
            "history-a", "history-b", "history-c"
        ])
        self.assertTrue(first["authority"]["read_only"])
        self.assertFalse(first["authority"]["live_policy_mutation"])
        self.assertFalse(first["authority"]["strategy_activation"])
        self.assertFalse(first["authority"]["proposal_creation"])

    def test_estimate_has_uncertainty_confidence_and_supporting_ids(self):
        report = self.analyze()
        analysis = report["decision_analyses"][0]
        estimates = {item["strategy_id"]: item for item in analysis["counterfactual_estimates"]}
        d0 = estimates["D0"]
        self.assertEqual(d0["status"], "ESTIMATED_FROM_SIMILAR_CONTEXTS")
        self.assertEqual(d0["support_count"], 2)
        self.assertEqual(d0["supporting_session_ids"], ["history-a", "history-b"])
        self.assertEqual(len(d0["supporting_decision_ids"]), 2)
        self.assertGreater(d0["confidence"], 0)
        self.assertIn(d0["confidence_label"], {"LOW", "MEDIUM", "HIGH"})
        metric = d0["estimated_reward_dimensions"]["trap_interactions"]
        self.assertIn("uncertainty", metric)
        self.assertEqual(len(metric["uncertainty"]["approximate_95_percent_interval"]), 2)

    def test_claims_are_estimates_not_certainty_or_composite_rankings(self):
        report = self.analyze()
        d0 = report["decision_analyses"][0]["counterfactual_estimates"][0]
        self.assertIn("is estimated", d0["claim"])
        self.assertNotIn("definitely", d0["claim"].lower())
        self.assertIn("no overall better/worse claim", d0["claim"])
        self.assertFalse(report["method_limits"]["causal_claims"])
        self.assertFalse(report["method_limits"]["composite_reward_ranking"])

    def test_only_target_allowed_alternatives_are_estimated(self):
        report = self.analyze()
        estimates = report["decision_analyses"][0]["counterfactual_estimates"]
        self.assertEqual([item["strategy_id"] for item in estimates], ["D0", "D2"])
        d2 = estimates[1]
        self.assertEqual(d2["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(d2["confidence"], 0.0)
        self.assertEqual(d2["supporting_session_ids"], [])
        self.assertIsNone(d2["estimated_reward_dimensions"])

    def test_cross_protocol_history_is_excluded(self):
        postgres = bundle("history-postgres", "D0", protocol="postgres")
        report = self.analyze([postgres])
        analysis = report["decision_analyses"][0]
        self.assertEqual(analysis["similar_session_retrieval"]["neighbors"], [])
        self.assertTrue(all(
            item["status"] == "INSUFFICIENT_EVIDENCE"
            for item in analysis["counterfactual_estimates"]
        ))

    def test_target_session_is_excluded_and_duplicate_history_is_rejected(self):
        same_target = copy.deepcopy(self.target)
        report = self.analyze([same_target, self.history[0]])
        self.assertEqual(report["evidence"]["historical_session_ids"], ["history-a"])
        with self.assertRaises(ValueError):
            self.analyze([self.history[0], copy.deepcopy(self.history[0])])

    def test_forged_historical_reward_is_rejected(self):
        forged = copy.deepcopy(self.history[0])
        forged["reward"]["per_decision"][0]["dimensions"]["engagement"][
            "queries_after_decision"
        ] = 999
        with self.assertRaises(ValueError):
            self.analyze([forged])

    def test_malformed_target_is_rejected(self):
        malformed = copy.deepcopy(self.target)
        malformed["telemetry"]["records"][0]["decision"]["query_raw"] = "select secret"
        with self.assertRaises(ValueError):
            self.agent.analyze(
                malformed["telemetry"], malformed["reward"], self.history, registry()
            )

    def test_phase_15_remains_deferred(self):
        report = self.analyze()
        self.assertEqual(report["later_phase_boundaries"]["coverage_gap_detection"], "PHASE_15")
        self.assertTrue(all(
            item["coverage_gap_assessment"] == {
                "status": "DEFERRED_PHASE_15", "proposal_created": False
            }
            for item in report["decision_analyses"]
        ))


class HistoryClientBoundsTests(unittest.TestCase):
    def test_history_limits_are_strictly_bounded_before_network_use(self):
        client = SafeInternalEvidenceClient()
        for decision_limit, history_limit in ((0, 1), (251, 1), (1, 0), (1, 51), (True, 1)):
            with self.subTest(values=(decision_limit, history_limit)):
                with self.assertRaises(ValueError):
                    client.load_session_with_history(
                        "session-14", decision_limit=decision_limit,
                        history_limit=history_limit,
                    )

    def test_incomplete_history_is_reported_and_excluded(self):
        class FixtureClient(SafeInternalEvidenceClient):
            def _get(self, url):
                if "/telemetry/decisions?" in url:
                    return {"records": [
                        {"decision": {"session_id": "history-complete"}},
                        {"decision": {"session_id": "history-pending"}},
                    ]}
                if "/telemetry/session/" in url:
                    return {"session_id": url.rsplit("/", 1)[-1], "records": []}
                if "/reward/session/history-complete" in url:
                    return {"session_id": "history-complete", "status": "COMPLETE"}
                if "/reward/session/history-pending" in url:
                    return {"session_id": "history-pending", "status": "PENDING"}
                if "/reward/session/session-14" in url:
                    return {"session_id": "session-14", "status": "COMPLETE"}
                if url.endswith("/strategies"):
                    return registry()
                raise AssertionError(url)

        _telemetry, _reward, history, _registry, summary = (
            FixtureClient().load_session_with_history(
                "session-14", decision_limit=10, history_limit=10
            )
        )
        self.assertEqual(len(history), 1)
        self.assertEqual(summary["loaded_session_count"], 1)
        self.assertEqual(summary["incomplete_session_ids"], ["history-pending"])


if __name__ == "__main__":
    unittest.main()

import copy
import unittest

from gap_detection import (
    GAP_DETECTION_VERSION,
    PROPOSAL_SCHEMA_VERSION,
    ActionSpaceGapDetector,
)
from test_similarity import bundle, registry


def gap_bundle(
    session_id,
    selected,
    *,
    risk=0.8,
    known_backup_theme=False,
    coherent=True,
    weak=True,
):
    item = bundle(
        session_id,
        selected,
        decision_id=f"SD-{session_id}",
        risk=risk,
        stage="collection",
    )
    linked = item["telemetry"]["records"][0]
    behavior = linked["decision"]["state_before"]["behavior_state"]
    behavior.update({
        "catalog_query_count": 0,
        "metadata_query_count": 0,
        "credential_keyword_count": 0,
        "backup_keyword_count": 3 if known_backup_theme else 0,
        "sensitive_table_interest": 0,
        "role_enumeration_count": 0,
        "privilege_escalation_attempts": 0,
        "destructive_query_count": 0,
        "unique_query_family_count": 6 if coherent else 1,
        "unique_table_count": 0,
        "trap_trigger_count": 0,
        "mitre_technique_count": 0,
    })
    dimensions = item["reward"]["per_decision"][0]["dimensions"]
    outcome = linked["outcome"]
    if weak:
        outcome.update({
            "queries_after_decision": 0,
            "session_duration_after_decision": 0.5,
            "new_query_families": 0,
            "new_tables_accessed": 0,
            "new_MITRE_techniques": 0,
            "trap_interactions": 0,
            "attacker_progression": {
                "from_stage": "collection", "to_stage": "collection", "advanced": False,
            },
        })
        dimensions["engagement"] = {
            "queries_after_decision": 0, "duration_seconds": 0.5,
        }
        dimensions["intelligence_gain"] = {
            "new_tables": 0, "new_MITRE_techniques": 0,
        }
        dimensions["behavior_novelty"] = {"new_query_families": 0}
        dimensions["MITRE_progression"] = {
            "advanced": 0, "from_stage": "collection", "to_stage": "collection",
        }
        dimensions["meaningful_trap_interaction"] = {"interactions": 0}
    item["reward"]["aggregate_dimensions"] = copy.deepcopy(dimensions)
    return item


class ActionSpaceGapDetectorTests(unittest.TestCase):
    def setUp(self):
        self.agent = ActionSpaceGapDetector(max_distance=0.35)
        self.target = gap_bundle("gap-target", "D0", risk=0.80)
        self.positive_history = [
            gap_bundle("gap-history-a", "D0", risk=0.79),
            gap_bundle("gap-history-b", "D1", risk=0.81),
            gap_bundle("gap-history-c", "D2", risk=0.82),
        ]

    def analyze(self, target=None, history=None, exclusions=None):
        target = target or self.target
        history = self.positive_history if history is None else history
        return self.agent.analyze(
            target["telemetry"],
            target["reward"],
            history,
            registry(),
            historical_exclusions=exclusions,
        )

    def test_positive_gap_creates_structured_review_only_proposal(self):
        result = self.analyze()
        self.assertEqual(result["gap_detection_version"], GAP_DETECTION_VERSION)
        self.assertEqual(result["classification"], "ACTION_SPACE_GAP")
        self.assertEqual(len(result["proposals"]), 1)
        proposal = result["proposals"][0]
        self.assertEqual(proposal["proposal_schema_version"], PROPOSAL_SCHEMA_VERSION)
        self.assertTrue(proposal["proposal_id"].startswith("P-"))
        self.assertEqual(proposal["status"], "REQUIRES_REVIEW")
        self.assertEqual(proposal["proposal_type"], "ACTION_SPACE_GAP")
        self.assertEqual(proposal["name"], "UNMODELED_RECURRING_BEHAVIOR_LURE")
        self.assertEqual(len(proposal["supporting_session_ids"]), 4)
        self.assertEqual(len(proposal["supporting_decision_ids"]), 4)
        self.assertEqual(proposal["observed_behavior"]["weak_strategy_ids"], [
            "D0", "D1", "D2"
        ])
        self.assertIsNone(proposal["estimated_benefit"])
        self.assertGreater(proposal["confidence"], 0)
        self.assertLessEqual(proposal["confidence"], 0.69)

    def test_known_strategy_theme_returns_no_gap(self):
        covered = gap_bundle(
            "covered-target", "D2", known_backup_theme=True, coherent=True
        )
        result = self.analyze(target=covered, history=[])
        self.assertEqual(result["classification"], "NO_GAP_DETECTED")
        self.assertEqual(result["proposals"], [])
        themes = result["decision_results"][0]["behavior_gap_signal"][
            "active_known_themes"
        ]
        self.assertEqual(themes[0]["strategy_id"], "D2")

    def test_one_weak_session_does_not_create_a_gap(self):
        result = self.analyze(history=[])
        self.assertEqual(result["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["proposals"], [])

    def test_insufficient_alternative_strategy_evidence_is_not_a_gap(self):
        same_strategy = [
            gap_bundle("same-a", "D0", risk=0.79),
            gap_bundle("same-b", "D0", risk=0.81),
            gap_bundle("same-c", "D0", risk=0.82),
        ]
        result = self.analyze(history=same_strategy)
        self.assertEqual(result["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["proposals"], [])

    def test_recurring_pattern_with_strong_outcome_returns_no_gap(self):
        strong = gap_bundle("strong-target", "D0", weak=False)
        result = self.analyze(target=strong)
        self.assertEqual(result["classification"], "NO_GAP_DETECTED")
        self.assertEqual(result["proposals"], [])

    def test_incomplete_history_is_excluded_and_reported(self):
        incomplete = gap_bundle("incomplete-history", "D1")
        incomplete["reward"]["status"] = "PENDING"
        result = self.analyze(history=[incomplete])
        self.assertEqual(result["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["evidence"]["historical_exclusions"], [{
            "session_id": "incomplete-history", "reason": "INCOMPLETE_EVIDENCE"
        }])
        self.assertNotIn(
            "incomplete-history", result["evidence"]["completed_historical_session_ids"]
        )

    def test_malformed_target_and_malformed_complete_history_are_rejected(self):
        malformed_target = copy.deepcopy(self.target)
        malformed_target["telemetry"]["records"][0]["decision"][
            "query_raw"
        ] = "select secret"
        with self.assertRaises(ValueError):
            self.analyze(target=malformed_target)

        malformed_history = copy.deepcopy(self.positive_history[0])
        malformed_history["telemetry"]["records"][0]["decision"][
            "query_raw"
        ] = "select secret"
        with self.assertRaises(ValueError):
            self.analyze(history=[malformed_history])

    def test_repeat_is_deterministic_even_when_history_order_changes(self):
        first = self.analyze()
        second = self.analyze(history=list(reversed(copy.deepcopy(self.positive_history))))
        self.assertEqual(first, second)
        self.assertEqual(
            first["proposals"][0]["proposal_id"], second["proposals"][0]["proposal_id"]
        )
        self.assertEqual(
            first["proposals"][0]["supporting_session_ids"],
            second["proposals"][0]["supporting_session_ids"],
        )

    def test_authority_is_zero_and_phase_16_is_not_implemented(self):
        result = self.analyze()
        authority = result["authority"]
        self.assertTrue(authority["read_only"])
        self.assertTrue(authority["recommendation_only"])
        self.assertTrue(authority["requires_human_review"])
        self.assertFalse(authority["deployable"])
        self.assertFalse(authority["registry_mutation"])
        self.assertFalse(authority["policy_mutation"])
        self.assertFalse(authority["strategy_activation"])
        self.assertFalse(authority["live_response_generation"])
        proposal_authority = result["proposals"][0]["authority"]
        self.assertFalse(proposal_authority["deployable"])
        self.assertTrue(proposal_authority["requires_human_review"])
        self.assertEqual(result["phase_16_boundary"], {
            "review_workflow": "NOT_IMPLEMENTED",
            "review_queue_write": False,
            "review_decision": None,
            "approval_state_change": False,
        })

    def test_external_exclusion_is_deterministic_and_bounded(self):
        result = self.analyze(
            history=[],
            exclusions=[{
                "session_id": "history-not-ready", "reason": "INCOMPLETE_EVIDENCE"
            }],
        )
        self.assertEqual(result["evidence"]["historical_exclusions"], [{
            "session_id": "history-not-ready", "reason": "INCOMPLETE_EVIDENCE"
        }])
        with self.assertRaises(ValueError):
            self.analyze(history=[], exclusions=[{
                "session_id": "../escape", "reason": "INCOMPLETE_EVIDENCE"
            }])


if __name__ == "__main__":
    unittest.main()

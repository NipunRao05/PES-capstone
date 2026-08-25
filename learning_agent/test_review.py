import copy
import hashlib
import unittest
from pathlib import Path

from gap_detection import ActionSpaceGapDetector
from review import (
    REVIEW_SCHEMA_VERSION,
    BlueTeamReviewStore,
    ReviewNotApplicable,
    extract_reviewable_proposal,
    validate_proposal,
)
from test_gap_detection import gap_bundle
from test_similarity import registry


FIXED_TIME = "2026-08-25T10:00:00+05:30"


def valid_gap_result():
    target = gap_bundle("review-target", "D0", risk=0.80)
    history = [
        gap_bundle("review-history-a", "D0", risk=0.79),
        gap_bundle("review-history-b", "D1", risk=0.81),
        gap_bundle("review-history-c", "D2", risk=0.82),
    ]
    return ActionSpaceGapDetector().analyze(
        target["telemetry"], target["reward"], history, registry()
    )


def valid_proposal():
    return copy.deepcopy(valid_gap_result()["proposals"][0])


class BlueTeamReviewTests(unittest.TestCase):
    def setUp(self):
        self.proposal = valid_proposal()

    def review(self, decision, **kwargs):
        return BlueTeamReviewStore().review(
            self.proposal,
            reviewer=kwargs.pop("reviewer", "blue-team-local"),
            decision=decision,
            reason=kwargs.pop("reason", "Evidence supports this human review decision."),
            timestamp=kwargs.pop("timestamp", FIXED_TIME),
            **kwargs,
        )

    def test_approve_means_approved_for_validation_only(self):
        review = self.review("APPROVE")
        self.assertEqual(review["review_schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertEqual(review["resulting_status"], "APPROVED_FOR_VALIDATION")
        self.assertTrue(review["can_proceed_to_validation"])
        self.assertEqual(review["next_phase"], "PHASE_17")
        self.assertFalse(review["authority"]["deployable"])
        self.assertFalse(review["authority"]["strategy_registry_approved"])
        self.assertTrue(review["authority"]["requires_phase_17_validation"])
        self.assertFalse(review["authority"]["validation_started"])
        self.assertTrue(review["validation_handoff"]["eligible"])
        self.assertFalse(review["validation_handoff"]["validation_started"])

    def test_reject_is_terminal_and_cannot_proceed(self):
        review = self.review("REJECT", reason="The evidence does not justify the risk.")
        self.assertEqual(review["resulting_status"], "REJECTED")
        self.assertFalse(review["can_proceed_to_validation"])
        self.assertIsNone(review["next_phase"])
        self.assertFalse(review["authority"]["requires_phase_17_validation"])

    def test_modify_records_request_without_mutating_original(self):
        original = copy.deepcopy(self.proposal)
        modifications = [{
            "field": "name",
            "instruction": "Use a narrower candidate name tied to the evidenced behavior.",
        }]
        review = self.review("MODIFY", modifications=modifications)
        self.assertEqual(review["resulting_status"], "MODIFICATION_REQUESTED")
        self.assertEqual(review["modifications"], modifications)
        self.assertFalse(review["can_proceed_to_validation"])
        self.assertEqual(self.proposal, original)

    def test_request_more_evidence_records_bounded_categories(self):
        requests = ["MORE_COMPARABLE_SESSIONS", "ADDITIONAL_PROTOCOL_EVIDENCE"]
        review = self.review("REQUEST_MORE_EVIDENCE", requested_evidence=requests)
        self.assertEqual(review["resulting_status"], "MORE_EVIDENCE_REQUIRED")
        self.assertEqual(review["requested_evidence"], requests)
        self.assertFalse(review["can_proceed_to_validation"])

    def test_explicit_human_reviewer_is_required_and_agent_self_review_is_rejected(self):
        for reviewer in (None, "", "agent-self-review", "learning-agent", "learning-agent-v1", "system"):
            with self.subTest(reviewer=reviewer):
                with self.assertRaises(ValueError):
                    self.review("APPROVE", reviewer=reviewer)

    def test_malformed_and_forged_proposals_fail_closed(self):
        mutations = []
        for field, value in (
            ("proposal_id", "bad"),
            ("proposal_type", "OTHER"),
            ("status", "APPROVED"),
            ("confidence", float("nan")),
            ("supporting_session_ids", []),
            ("supporting_decision_ids", []),
        ):
            forged = copy.deepcopy(self.proposal)
            forged[field] = value
            mutations.append(forged)
        deployable = copy.deepcopy(self.proposal)
        deployable["authority"]["deployable"] = True
        mutations.append(deployable)
        self_review = copy.deepcopy(self.proposal)
        self_review["authority"]["requires_human_review"] = False
        mutations.append(self_review)
        executable = copy.deepcopy(self.proposal)
        executable["command"] = "never execute"
        mutations.append(executable)
        for proposal in mutations:
            with self.subTest():
                with self.assertRaises(ValueError):
                    validate_proposal(proposal)

    def test_no_gap_and_insufficient_results_cannot_enter_review(self):
        for classification in ("NO_GAP_DETECTED", "INSUFFICIENT_EVIDENCE"):
            with self.subTest(classification=classification):
                with self.assertRaises(ReviewNotApplicable):
                    extract_reviewable_proposal({
                        "classification": classification, "proposals": []
                    })
        with self.assertRaises(ValueError):
            extract_reviewable_proposal({
                "classification": "NO_GAP_DETECTED", "proposals": [self.proposal]
            })

    def test_original_proposal_snapshot_and_audit_trail_are_immutable_copies(self):
        store = BlueTeamReviewStore()
        original = copy.deepcopy(self.proposal)
        review = store.review(
            self.proposal,
            reviewer="researcher-01",
            decision="REJECT",
            reason="Keep the candidate out of validation.",
            timestamp=FIXED_TIME,
        )
        self.proposal["name"] = "CALLER_MUTATION"
        trail = store.audit_trail(original["proposal_id"])
        self.assertEqual(trail["proposal"], original)
        self.assertEqual(trail["reviews"], [review])
        self.assertTrue(review["audit"]["original_proposal_preserved"])
        trail["proposal"]["name"] = "RETURN_VALUE_MUTATION"
        self.assertEqual(store.audit_trail(original["proposal_id"])["proposal"], original)

    def test_review_identity_is_deterministic_and_duplicate_submit_is_idempotent(self):
        first_store = BlueTeamReviewStore()
        second_store = BlueTeamReviewStore()
        inputs = dict(
            reviewer="operator-test",
            decision="APPROVE",
            reason="Send this proposal to bounded technical validation.",
            timestamp=FIXED_TIME,
        )
        first = first_store.review(self.proposal, **inputs)
        repeated = first_store.review(copy.deepcopy(self.proposal), **inputs)
        second = second_store.review(copy.deepcopy(self.proposal), **inputs)
        self.assertEqual(first, repeated)
        self.assertEqual(first, second)
        self.assertTrue(first["review_id"].startswith("RV-"))
        self.assertEqual(len(first["audit"]["stable_review_input_sha256"]), 64)

    def test_reviewed_state_rejects_a_different_transition_without_revision(self):
        store = BlueTeamReviewStore()
        store.review(
            self.proposal,
            reviewer="blue-team-local",
            decision="APPROVE",
            reason="Proceed to validation.",
            timestamp=FIXED_TIME,
        )
        with self.assertRaises(ValueError):
            store.review(
                self.proposal,
                reviewer="blue-team-local",
                decision="REJECT",
                reason="Attempt a conflicting second transition.",
                timestamp=FIXED_TIME,
            )

    def test_action_specific_fields_and_sizes_are_enforced(self):
        with self.assertRaises(ValueError):
            self.review("MODIFY", modifications=[])
        with self.assertRaises(ValueError):
            self.review("REQUEST_MORE_EVIDENCE", requested_evidence=[])
        with self.assertRaises(ValueError):
            self.review("APPROVE", modifications=[{
                "field": "name", "instruction": "Unexpected for APPROVE"
            }])
        with self.assertRaises(ValueError):
            self.review("MODIFY", modifications=[{
                "field": "strategy_registry", "instruction": "Forbidden target"
            }])
        with self.assertRaises(ValueError):
            self.review("REJECT", reason="x" * 2049)

    def test_authority_boundary_and_phase_17_absence_preserve_live_files(self):
        protected = [
            Path("deception_engine/strategies/registry.yaml"),
            Path("deception_engine/policy_guard.py"),
        ]
        before = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in protected
        }
        review = self.review("APPROVE")
        after = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in protected
        }
        self.assertEqual(before, after)
        for field in (
            "deployable", "strategy_registry_approved", "validation_started",
            "registry_mutation", "policy_mutation", "strategy_activation", "asset_deployment",
        ):
            self.assertFalse(review["authority"][field])
        self.assertEqual(review["validation_handoff"]["phase"], "PHASE_17")
        self.assertFalse(review["validation_handoff"]["validation_started"])


if __name__ == "__main__":
    unittest.main()

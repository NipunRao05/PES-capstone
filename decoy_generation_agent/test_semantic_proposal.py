import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEARNING = ROOT / "learning_agent"
if str(LEARNING) not in sys.path:
    sys.path.insert(0, str(LEARNING))

from review import BlueTeamReviewStore
from test_review import FIXED_TIME, valid_proposal
from test_similarity import registry

from decoy_generation_agent.semantic_proposal import (
    SEMANTIC_AUTHORITY, SEMANTIC_REQUEST_VERSION, SemanticProposalAgent,
    validate_semantic_request,
)
from decoy_generation_agent.semantic_live_validation import benchmark_cases


def approved_bundle():
    proposal = valid_proposal()
    review = BlueTeamReviewStore().review(
        proposal, reviewer="blue-team-local", decision="APPROVE",
        reason="Evidence supports bounded semantic validation.", timestamp=FIXED_TIME,
    )
    return proposal, review


def semantic_request():
    proposal, review = approved_bundle()
    return {
        "request_version": SEMANTIC_REQUEST_VERSION,
        "fictional_persona_summary": {
            "company_name": "Northstar Parcel Labs", "industry": "fictional logistics research",
            "environment_label": "decoy_lab", "fictional": True,
        },
        "proposal": proposal, "review": review,
        "strategy_requirements": {
            "strategy_id": "D8", "name": "UNMODELED_RECURRING_BEHAVIOR_LURE",
            "required_state": ["session_id", "protocol"], "forbidden_state": [],
            "activation_conditions": ["reviewed recurring behavior gap is present"],
            "compatible_personas": ["script", "automated_tool", "human_attacker"],
            "risk_level": "medium", "resource_cost": "low",
        },
        "supported_protocol": "mysql",
        "existing_semantic_themes": ["routine shipment tracking"],
        "synthetic_schema_summary": [{"table": "shipment_index", "columns": ["shipment_id", "status_label"]}],
    }


def semantic_output():
    return {
        "proposal_name": "Archived Route Reconciliation",
        "theme": "retired route reconciliation",
        "narrative": "A fictional reconciliation workflow links retired routing batches to review notes and intentionally recorded access clues.",
        "entities": [
            {"name": "Route Archive", "role": "historical batch index", "description": "Indexes fictional route batches retained for internal reconciliation review."},
            {"name": "Review Ledger", "role": "review history", "description": "Records fictional review outcomes for archived route batches."},
        ],
        "relationships": [{
            "source_entity": "Route Archive", "target_entity": "Review Ledger",
            "relationship": "reviewed through", "description": "Each fictional archive batch references its bounded review history.",
        }],
        "clues_traps": [{
            "name": "Reconciliation Marker", "kind": "recorded_trap",
            "description": "A synthetic marker records interest in the retired reconciliation trail.",
            "interaction_signal": "archive reconciliation interest",
        }],
        "expected_attacker_interests": ["historical routing metadata", "review history"],
        "rationale": "The theme addresses the reviewed unmodeled pattern while remaining metadata only and distinct from routine shipment tracking.",
    }


class FakeSemanticLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate_structured(self, prompt):
        self.calls.append(prompt)
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(response, dict):
            return copy.deepcopy(response)
        return {
            "status": "OK", "text": response, "request_id": f"SLLMREQ-{len(self.calls)}",
            "schema_constraint_active": True, "reasoning_discarded": False,
            "latency_ms": 1.0, "prompt_tokens": 100, "generated_tokens": 120,
            "model_version": "ornith-1.5:9b", "runtime_version": "0.32.5",
            "contract_version": "local-llm-semantic-client-v1",
            "schema_version": "semantic-proposal-output-v1", "trusted": False,
        }


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class SemanticProposalTests(unittest.TestCase):
    def run_agent(self, responses, request=None, registry_value=None):
        client = FakeSemanticLLM(responses)
        result = SemanticProposalAgent(client, registry_value or registry()).propose(request or semantic_request())
        return result, client

    def test_valid_metadata_candidate_completes_phase15_to_phase17_chain(self):
        result, client = self.run_agent([encoded(semantic_output())])
        self.assertEqual(result["status"], "SEMANTIC_CANDIDATE_READY")
        self.assertEqual(result["candidate_status"], "NONDEPLOYABLE")
        self.assertEqual(result["registry_status"], "REGISTRY_UNAPPROVED")
        self.assertEqual(result["phase17_handoff"]["status"], "VALIDATED")
        self.assertEqual(result["phase17_handoff"]["database_asset_count"], 0)
        self.assertFalse(result["phase17_handoff"]["database_execution"])
        self.assertEqual(result["authority"], SEMANTIC_AUTHORITY)
        self.assertEqual(len(client.calls), 1)
        self.assertTrue(all("entity_id" in item for item in result["semantic_proposal"]["entities"]))

    def test_fixed_benchmark_has_exactly_ten_valid_bounded_cases(self):
        cases = benchmark_cases()
        self.assertEqual(len(cases), 10)
        self.assertEqual(len({item["label"] for item in cases}), 10)
        for item in cases:
            validate_semantic_request(item["request"])

    def test_schema_constraint_must_be_active(self):
        response = {"status": "OK", "text": encoded(semantic_output()), "schema_constraint_active": False}
        result, client = self.run_agent([response, response])
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(len(client.calls), 2)

    def test_one_fresh_repair_does_not_include_invalid_output(self):
        invalid = "not-json-secret-marker"
        result, client = self.run_agent([invalid, encoded(semantic_output())])
        self.assertEqual(result["status"], "SEMANTIC_CANDIDATE_READY")
        self.assertEqual(result["repair_count"], 1)
        self.assertNotIn(invalid, client.calls[1])

    def test_reasoning_markers_external_links_and_secret_like_values_are_rejected(self):
        mutations = []
        for field, value in (
            ("narrative", "<think>private chain</think> This fictional narrative must never persist reasoning text."),
            ("rationale", "This proposal calls an external service at https://example.com and is therefore unsafe."),
            ("rationale", "This proposal embeds key AKIA1234567890ABCDEF and is therefore unsafe."),
        ):
            candidate = semantic_output()
            candidate[field] = value
            mutations.append(candidate)
        for index, candidate in enumerate(mutations):
            with self.subTest(mutation=index):
                result, _ = self.run_agent([encoded(candidate), encoded(candidate)])
                self.assertEqual(result["status"], "REJECTED")
                self.assertIsNone(result["semantic_proposal"])

    def test_invalid_relationship_and_duplicate_theme_fail_closed(self):
        broken = semantic_output()
        broken["relationships"][0]["target_entity"] = "Missing Entity"
        duplicate = semantic_output()
        request = semantic_request()
        request["existing_semantic_themes"] = [duplicate["theme"]]
        self.assertEqual(self.run_agent([encoded(broken), encoded(broken)])[0]["status"], "REJECTED")
        self.assertEqual(self.run_agent([encoded(duplicate), encoded(duplicate)], request=request)[0]["status"], "REJECTED")

    def test_invalid_review_and_nonfictional_persona_stop_before_inference(self):
        for mutation in ("review", "persona"):
            request = semantic_request()
            if mutation == "review":
                request["review"]["resulting_status"] = "REJECTED"
            else:
                request["fictional_persona_summary"]["fictional"] = False
            result, client = self.run_agent([encoded(semantic_output())], request=request)
            self.assertEqual(result["status"], "REJECTED")
            self.assertEqual(client.calls, [])

    def test_unavailable_model_fails_without_repair(self):
        response = {"status": "UNAVAILABLE", "error": {"code": "UNAVAILABLE"}}
        result, client = self.run_agent([response])
        self.assertEqual(result["status"], "GENERATION_FAILED")
        self.assertEqual(len(client.calls), 1)

    def test_reasoning_content_and_prompts_are_not_persisted(self):
        response = {
            "status": "OK", "text": encoded(semantic_output()), "request_id": "SLLMREQ-1",
            "schema_constraint_active": True, "reasoning_discarded": True,
            "latency_ms": 1.0, "prompt_tokens": 100, "generated_tokens": 120,
            "model_version": "ornith-1.5:9b", "runtime_version": "0.32.5",
            "contract_version": "local-llm-semantic-client-v1", "schema_version": "semantic-proposal-output-v1",
        }
        result, _ = self.run_agent([response])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("private reasoning", serialized)
        self.assertNotIn("JSON_SCHEMA=", serialized)
        self.assertTrue(result["attempts"][0]["reasoning_discarded"])

    def test_authority_boundary_preserves_live_files(self):
        paths = [
            ROOT / "deception_engine" / "strategies" / "registry.yaml",
            ROOT / "deception_engine" / "policy_guard.py",
            ROOT / "session_module" / "authoritative_state.py",
        ]
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        result, _ = self.run_agent([encoded(semantic_output())])
        after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        self.assertEqual(result["status"], "SEMANTIC_CANDIDATE_READY")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import json
import unittest
from pathlib import Path

from candidate_validation import CandidateValidationPipeline, VALIDATOR_VERSION
from review import BlueTeamReviewStore
from test_review import FIXED_TIME, valid_proposal
from test_similarity import registry


ROOT = Path(__file__).resolve().parents[1]


def approved_review(proposal):
    return BlueTeamReviewStore().review(
        proposal,
        reviewer="blue-team-local",
        decision="APPROVE",
        reason="Evidence supports bounded deterministic Phase 17 validation.",
        timestamp=FIXED_TIME,
    )


def candidate():
    return {
        "candidate_schema_version": "candidate-strategy-v1",
        "strategy_id": "D8",
        "name": "UNMODELED_RECURRING_BEHAVIOR_LURE",
        "description": "Bounded metadata-only candidate for the evidenced behavior gap.",
        "supported_protocols": ["mysql", "postgres"],
        "required_state": ["session_id", "protocol"],
        "forbidden_state": [],
        "activation_conditions": ["reviewed recurring behavior gap is present"],
        "compatible_personas": ["script", "automated_tool", "human_attacker"],
        "schema_assets": [],
        "trap_assets": [],
        "risk_level": "medium",
        "resource_cost": "low",
        "validation_version": "phase17-candidate-v1",
    }


def valid_validation_input():
    proposal = valid_proposal()
    return {
        "proposal": proposal,
        "review": approved_review(proposal),
        "candidate_strategy": candidate(),
        "database_assets": [],
        "state_contract": {
            "observed_objects": {},
            "candidate_expectations": {},
            "retroactive_mutations": [],
        },
        "trap_definitions": [],
        "resource_limits": {
            "cost_class": "low",
            "max_rows": 1000,
            "max_schema_objects": 10,
            "background_workers": 0,
            "container_per_query": False,
        },
    }


def database_asset(protocol="mysql", rows=None):
    return {
        "asset_id": "candidate_table",
        "protocol": protocol,
        "object_type": "table",
        "sql": "CREATE TABLE candidate_table (id INT, marker VARCHAR(64))",
        "schema": {
            "table": "candidate_table",
            "columns": [
                {"name": "id", "type": "INT", "nullable": False},
                {"name": "marker", "type": "VARCHAR(64)", "nullable": True},
            ],
            "primary_key": ["id"],
            "foreign_keys": [],
            "indexes": [{"name": "idx_marker", "columns": ["marker"]}],
        },
        "rows": rows or [],
    }


def with_database_asset(value, *, candidate_protocols=None, rows=None):
    value = copy.deepcopy(value)
    value["candidate_strategy"]["schema_assets"] = ["candidate_table"]
    if candidate_protocols is not None:
        value["candidate_strategy"]["supported_protocols"] = candidate_protocols
    value["database_assets"] = [database_asset(rows=rows)]
    return value


class CandidateValidationTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = CandidateValidationPipeline()
        self.registry = registry()
        self.value = valid_validation_input()

    def validate(self, value=None, registry_value=None):
        return self.pipeline.validate(
            copy.deepcopy(value if value is not None else self.value),
            copy.deepcopy(registry_value if registry_value is not None else self.registry),
        )

    def test_valid_approved_candidate_passes_all_required_checks(self):
        result = self.validate()
        self.assertEqual(result["status"], "VALIDATED")
        self.assertEqual(result["validator_version"], VALIDATOR_VERSION)
        self.assertEqual([item["stage"] for item in result["checks"]], list(range(1, 13)))
        self.assertEqual(result["checks"][-1]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["failed_checks"], [])
        self.assertFalse(result["authority"]["deployable"])
        self.assertFalse(result["authority"]["strategy_registry_approved"])
        self.assertFalse(result["authority"]["strategy_activation"])

    def test_wrong_review_states_and_forged_authority_are_rejected(self):
        mutations = (
            ("resulting_status", "REJECTED"),
            ("resulting_status", "MORE_EVIDENCE_REQUIRED"),
            ("resulting_status", "MODIFICATION_REQUESTED"),
            ("prior_status", "NO_GAP_DETECTED"),
            ("decision", "REJECT"),
            ("reviewer", ""),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                invalid = copy.deepcopy(self.value)
                invalid["review"][field] = value
                result = self.validate(invalid)
                self.assertEqual(result["status"], "REJECTED")
                self.assertEqual(result["failed_checks"][0]["stage"], 1)
        forged = copy.deepcopy(self.value)
        forged["review"]["authority"]["deployable"] = True
        self.assertEqual(self.validate(forged)["status"], "REJECTED")

    def test_registry_collision_and_reserved_ids_are_rejected_read_only(self):
        before = copy.deepcopy(self.registry)
        for strategy_id in ("D0", "D1", self.registry["strategies"][-1]["strategy_id"]):
            with self.subTest(strategy_id=strategy_id):
                value = copy.deepcopy(self.value)
                value["candidate_strategy"]["strategy_id"] = strategy_id
                result = self.validate(value)
                self.assertEqual(result["status"], "REJECTED")
                self.assertEqual(result["failed_checks"][0]["stage"], 3)
        self.assertEqual(self.registry, before)

    def test_invalid_sql_and_schema_are_rejected(self):
        value = with_database_asset(self.value)
        value["database_assets"][0]["sql"] = "CREATE TABL candidate_table (id INT)"
        result = self.validate(value)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 4)

        value = with_database_asset(self.value)
        value["database_assets"][0]["schema"]["columns"][1]["name"] = "missing"
        result = self.validate(value)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 5)

    def test_external_network_reference_is_rejected(self):
        value = copy.deepcopy(self.value)
        value["candidate_strategy"]["description"] = "Call https://collector.example.com after a trap."
        result = self.validate(value)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 7)

    def test_real_secret_like_synthetic_row_is_rejected(self):
        value = with_database_asset(
            self.value, rows=[{"id": 1, "marker": "AKIAABCDEFGHIJKLMNOP"}]
        )
        result = self.validate(value)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 6)

    def test_protocol_mismatch_is_rejected(self):
        value = with_database_asset(self.value, candidate_protocols=["postgres"])
        result = self.validate(value)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 8)

    def test_state_contradiction_is_rejected(self):
        value = copy.deepcopy(self.value)
        value["state_contract"] = {
            "observed_objects": {"users": {"id": "BIGINT"}},
            "candidate_expectations": {"users": {"id": "VARCHAR"}},
            "retroactive_mutations": [],
        }
        result = self.validate(value)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 9)

    def test_unsafe_trap_and_unbounded_resources_are_rejected(self):
        trap = copy.deepcopy(self.value)
        trap["candidate_strategy"]["trap_assets"] = ["trap-table"]
        trap["trap_definitions"] = [{
            "trap_id": "trap-1",
            "asset_id": "trap-table",
            "synthetic": True,
            "evidence_event": "trap_interaction",
            "action": "RECORD_ONLY",
            "network_activity": True,
            "offensive_action": False,
        }]
        result = self.validate(trap)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 10)

        resource = copy.deepcopy(self.value)
        resource["resource_limits"]["max_rows"] = 10001
        result = self.validate(resource)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["failed_checks"][0]["stage"], 11)

    def test_database_asset_without_candidate_import_support_is_incomplete(self):
        result = self.validate(with_database_asset(self.value))
        self.assertEqual(result["status"], "VALIDATION_INCOMPLETE")
        self.assertEqual(result["checks"][-1]["status"], "NOT_VALIDATED")
        self.assertEqual(result["incomplete_checks"][0]["stage"], 12)
        self.assertFalse(result["evidence"]["sql_executed"])

    def test_repeat_is_byte_deterministic(self):
        first = self.validate()
        second = self.validate()
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )

    def test_authority_boundary_preserves_registry_policy_and_live_state_code(self):
        paths = [
            ROOT / "deception_engine" / "strategies" / "registry.yaml",
            ROOT / "deception_engine" / "policy_guard.py",
            ROOT / "session_module" / "authoritative_state.py",
        ]
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        result = self.validate()
        after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        self.assertEqual(before, after)
        self.assertEqual(result["evidence"]["registry_access"], "READ_ONLY")
        self.assertFalse(result["authority"]["registry_mutation"])
        self.assertFalse(result["authority"]["policy_mutation"])
        self.assertFalse(result["authority"]["asset_deployment"])
        self.assertFalse(result["authority"]["database_mutation"])
        self.assertFalse(result["next_phase_boundary"]["phase_18_started"])


if __name__ == "__main__":
    unittest.main()

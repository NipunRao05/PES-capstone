import copy
import unittest

from scripts.controlled_workloads import (
    MAX_SESSION_COUNT,
    REQUIRED_PROFILES,
    WORKLOAD_VERSION,
    generate_session,
    iter_sessions,
    plan_hash,
    summarize,
    validate_session,
)


class ControlledWorkloadTests(unittest.TestCase):
    def test_required_profiles_and_both_protocols_are_covered(self):
        sessions = list(iter_sessions(18, seed=42))
        self.assertEqual(
            {item["profile"] for item in sessions}, set(REQUIRED_PROFILES)
        )
        self.assertEqual({item["protocol"] for item in sessions}, {"mysql", "postgres"})
        for profile in REQUIRED_PROFILES:
            protocols = {
                item["protocol"] for item in sessions if item["profile"] == profile
            }
            self.assertEqual(protocols, {"mysql", "postgres"})

    def test_one_thousand_sessions_are_repeatable_and_varied(self):
        first = list(iter_sessions(1_000, seed=20260824))
        second = list(iter_sessions(1_000, seed=20260824))
        self.assertEqual(plan_hash(first), plan_hash(second))
        self.assertEqual(first, second)
        summary = summarize(first)
        self.assertEqual(summary["workload_version"], WORKLOAD_VERSION)
        self.assertEqual(summary["session_count"], 1_000)
        self.assertEqual(set(summary["profiles"]), set(REQUIRED_PROFILES))
        self.assertEqual(set(summary["protocols"]), {"mysql", "postgres"})
        self.assertGreater(summary["variation"]["query_order_signatures"], 20)
        self.assertGreater(summary["variation"]["databases"], 1)
        self.assertGreater(summary["variation"]["table_asset_sets"], 10)
        self.assertGreater(summary["variation"]["usernames"], 1)
        self.assertEqual(summary["variation"]["timing_modes"], 3)
        self.assertLess(
            summary["variation"]["attack_depth_min"],
            summary["variation"]["attack_depth_max"],
        )
        self.assertLess(
            summary["variation"]["duration_ms_min"],
            summary["variation"]["duration_ms_max"],
        )
        self.assertTrue(summary["synthetic_only"])
        self.assertTrue(summary["local_decoy_only"])
        self.assertFalse(summary["execution_performed"])

    def test_different_seeds_produce_different_stable_plans(self):
        first = list(iter_sessions(100, seed=1))
        second = list(iter_sessions(100, seed=2))
        self.assertNotEqual(plan_hash(first), plan_hash(second))
        self.assertEqual(plan_hash(first), plan_hash(iter_sessions(100, seed=1)))

    def test_destructive_statements_are_always_simulate_only(self):
        sessions = list(iter_sessions(500, seed=7))
        destructive = [
            query
            for session in sessions
            for query in session["queries"]
            if query["expected_family"] == "destructive"
        ]
        self.assertTrue(destructive)
        self.assertTrue(all(
            query["execution_policy"] == "SIMULATE_ONLY"
            for query in destructive
        ))

    def test_profiles_carry_expected_semantic_signals(self):
        sessions = list(iter_sessions(180, seed=99))
        for session in sessions:
            expected = set(session["expected_signals"])
            observed = {
                query["expected_family"] for query in session["queries"]
            }
            self.assertTrue(expected.issubset(observed), session["profile"])

    def test_safety_validator_rejects_external_and_unsafe_plans(self):
        base = generate_session(0, seed=1)
        external = copy.deepcopy(base)
        external["queries"][0]["statement"] = "SELECT 'https://example.invalid';"
        with self.assertRaises(ValueError):
            validate_session(external)
        production = copy.deepcopy(base)
        production["network_scope"] = "PRODUCTION"
        with self.assertRaises(ValueError):
            validate_session(production)
        identity = copy.deepcopy(base)
        identity["username"] = "real_admin"
        with self.assertRaises(ValueError):
            validate_session(identity)
        destructive = generate_session(7, seed=1)
        destructive["queries"][0]["execution_policy"] = "DECOY_ONLY"
        with self.assertRaises(ValueError):
            validate_session(destructive)

    def test_bounds_and_prefix_stability(self):
        with self.assertRaises(ValueError):
            list(iter_sessions(0))
        with self.assertRaises(ValueError):
            list(iter_sessions(MAX_SESSION_COUNT + 1))
        prefix = list(iter_sessions(25, seed=123))
        larger = list(iter_sessions(100, seed=123))
        self.assertEqual(prefix, larger[:25])


if __name__ == "__main__":
    unittest.main()

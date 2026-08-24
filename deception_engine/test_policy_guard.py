import unittest

from policy_guard import POLICY_VERSION, PolicyGuard
from strategy_registry import DEFAULT_REGISTRY_PATH, StrategyRegistry


def session(**changes):
    value = {
        "session_id": "s-1",
        "protocol": "postgres",
        "persona_id": "human_attacker",
        "database": "hr_production",
        "session_depth": 4,
        "modified_objects": [],
    }
    value.update(changes)
    return value


class PolicyGuardTests(unittest.TestCase):
    def setUp(self):
        self.registry = StrategyRegistry.load(DEFAULT_REGISTRY_PATH)
        self.guard = PolicyGuard(self.registry)

    def test_catalog_context_allows_d1_with_deterministic_default(self):
        result = self.guard.evaluate(
            session(), {"catalog_query_count": 2}, {}, "RULE_ADAPTIVE"
        )
        self.assertEqual(result.allowed, ("D0", "D1"))
        self.assertEqual(result.default, "D1")
        self.assertEqual(result.policy_version, POLICY_VERSION)

    def test_hybrid_learned_mode_uses_the_same_deterministic_safe_action_space(self):
        rule = self.guard.evaluate(
            session(), {"backup_keyword_count": 1}, {}, "RULE_ADAPTIVE"
        )
        learned = self.guard.evaluate(
            session(), {"backup_keyword_count": 1}, {},
            "HYBRID_LEARNED_ADAPTIVE",
        )
        self.assertEqual(learned.allowed, rule.allowed)
        self.assertEqual(learned.default, rule.default)
        self.assertEqual(learned.policy_version, POLICY_VERSION)

    def test_overlapping_backup_and_credential_context_has_stable_default(self):
        result = self.guard.evaluate(session(), {
            "backup_keyword_count": 1,
            "credential_keyword_count": 1,
        }, {}, "RULE_ADAPTIVE")
        self.assertEqual(result.allowed, ("D0", "D2", "D3"))
        self.assertEqual(result.default, "D2")

    def test_sensitive_asset_activates_d4_without_raw_query(self):
        result = self.guard.evaluate(
            session(discovered_objects=["hr.employees"]), {}, {}, "RULE_ADAPTIVE"
        )
        self.assertIn("D4", result.allowed)
        self.assertEqual(result.default, "D4")

    def test_rule_default_is_honored_only_inside_allowed_space(self):
        state = session(rule_default_strategy_id="D3")
        result = self.guard.evaluate(
            state, {"credential_keyword_count": 1}, {}, "RULE_ADAPTIVE"
        )
        self.assertEqual(result.default, "D3")
        state["rule_default_strategy_id"] = "D5"
        result = self.guard.evaluate(
            state, {"credential_keyword_count": 1}, {}, "RULE_ADAPTIVE"
        )
        self.assertEqual(result.default, "D3")

    def test_unapproved_d5_is_never_allowed_or_enforced(self):
        result = self.guard.evaluate(session(
            user="root", role="admin", permissions=["ALL"]
        ), {"mitre_stage": "privilege_discovery"}, {}, "RULE_ADAPTIVE")
        self.assertNotIn("D5", result.allowed)
        self.assertEqual(self.guard.enforce_choice("D5", result), result.default)
        self.assertEqual(self.guard.enforce_registered_choice("D5"), "D0")

    def test_unknown_strategy_is_never_allowed_or_enforced(self):
        result = self.guard.evaluate(session(), {}, {}, "RULE_ADAPTIVE")
        self.assertNotIn("D999", result.allowed)
        self.assertEqual(self.guard.enforce_choice("D999", result), "D0")
        self.assertEqual(self.guard.enforce_registered_choice("D999"), "D0")

    def test_static_safe_and_unknown_modes_fail_to_d0_only(self):
        behavior = {"backup_keyword_count": 4}
        for mode in ("STATIC", "SAFE_MODE", "HYBRID_ACTIVE", "invalid"):
            with self.subTest(mode=mode):
                result = self.guard.evaluate(session(), behavior, {}, mode)
                self.assertEqual(result.allowed, ("D0",))
                self.assertEqual(result.default, "D0")
                self.assertTrue(result.fallback_reason)

    def test_missing_or_unsupported_protocol_fails_closed(self):
        for protocol in ("", "oracle", None):
            with self.subTest(protocol=protocol):
                result = self.guard.evaluate(
                    session(protocol=protocol), {"backup_keyword_count": 1},
                    {}, "RULE_ADAPTIVE",
                )
                self.assertEqual(result.allowed, ("D0",))

    def test_persona_and_required_state_are_enforced(self):
        behavior = {"backup_keyword_count": 1}
        self.assertNotIn("D2", self.guard.evaluate(
            session(persona_id="unknown"), behavior, {}, "RULE_ADAPTIVE"
        ).allowed)
        missing_database = session()
        missing_database.pop("database")
        self.assertNotIn("D2", self.guard.evaluate(
            missing_database, behavior, {}, "RULE_ADAPTIVE"
        ).allowed)

    def test_destructive_simulation_requires_confirmed_managed_target(self):
        behavior = {"destructive_query_count": 1}
        self.assertNotIn("D6", self.guard.evaluate(
            session(), behavior, {}, "RULE_ADAPTIVE"
        ).allowed)
        allowed = self.guard.evaluate(
            session(target_is_managed_synthetic=True), behavior, {}, "RULE_ADAPTIVE"
        )
        self.assertIn("D6", allowed.allowed)
        blocked = self.guard.evaluate(
            session(target_is_managed_synthetic=False, modified_objects=["employees"]),
            behavior, {}, "RULE_ADAPTIVE",
        )
        self.assertNotIn("D6", blocked.allowed)

    def test_raw_query_text_cannot_expand_action_space(self):
        clean = self.guard.evaluate(session(), {}, {}, "RULE_ADAPTIVE")
        hostile = self.guard.evaluate(session(query_normalized=(
            "backup password credential drop api_keys_backup"
        )), {}, {}, "RULE_ADAPTIVE")
        self.assertEqual(clean, hostile)

    def test_degraded_registry_exposes_only_builtin_d0(self):
        guard = PolicyGuard(StrategyRegistry.safe_fallback("test"))
        result = guard.evaluate(session(), {"backup_keyword_count": 5}, {}, "RULE_ADAPTIVE")
        self.assertEqual(result.allowed, ("D0",))
        self.assertEqual(result.default, "D0")
        self.assertEqual(result.fallback_reason, "registry_degraded")


if __name__ == "__main__":
    unittest.main()

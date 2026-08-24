import asyncio
import unittest

from fastapi import HTTPException

import api

from policy_guard import ActionSpace, POLICY_VERSION, PolicyGuard
from strategy_agent import RULE_POLICY_VERSION, RuleOnlyStrategyAgent
from strategy_registry import DEFAULT_REGISTRY_PATH, StrategyRegistry


def session(**changes):
    value = {
        "session_id": "s-1",
        "protocol": "mysql",
        "persona_id": "human_attacker",
        "database": "hr_production",
        "session_depth": 3,
        "modified_objects": [],
    }
    value.update(changes)
    return value


class RuleOnlyStrategyAgentTests(unittest.TestCase):
    def setUp(self):
        self.registry = StrategyRegistry.load(DEFAULT_REGISTRY_PATH)
        self.guard = PolicyGuard(self.registry)
        self.agent = RuleOnlyStrategyAgent(self.guard)

    def test_output_contract_is_exact_and_deterministic(self):
        first = self.agent.decide(
            session(), {"backup_keyword_count": 1}, {}, "RULE_ADAPTIVE"
        )
        second = self.agent.decide(
            session(), {"backup_keyword_count": 1}, {}, "RULE_ADAPTIVE"
        )
        expected = {
            "strategy_id": "D2",
            "confidence": 1.0,
            "selector_type": "rule",
            "policy_version": RULE_POLICY_VERSION,
        }
        self.assertEqual(first.to_dict(), expected)
        self.assertEqual(first, second)

    def test_rule_contexts_match_existing_strategy_defaults(self):
        cases = (
            ({}, "D0"),
            ({"catalog_query_count": 1}, "D1"),
            ({"backup_keyword_count": 1}, "D2"),
            ({"credential_keyword_count": 1}, "D3"),
            ({"sensitive_table_interest": 1}, "D4"),
        )
        for behavior, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    self.agent.decide(
                        session(), behavior, {}, "RULE_ADAPTIVE"
                    ).strategy_id,
                    expected,
                )

    def test_destructive_rule_requires_managed_target(self):
        behavior = {"destructive_query_count": 1}
        self.assertEqual(
            self.agent.decide(
                session(), behavior, {}, "RULE_ADAPTIVE"
            ).strategy_id,
            "D0",
        )
        self.assertEqual(
            self.agent.decide(
                session(target_is_managed_synthetic=True), behavior,
                {}, "RULE_ADAPTIVE",
            ).strategy_id,
            "D6",
        )

    def test_overlapping_rules_use_policy_guard_default(self):
        decision = self.agent.decide(session(), {
            "backup_keyword_count": 1,
            "credential_keyword_count": 1,
            "sensitive_table_interest": 1,
        }, {}, "RULE_ADAPTIVE")
        self.assertEqual(decision.strategy_id, "D2")

    def test_explicit_legal_rule_default_is_preserved(self):
        decision = self.agent.decide(
            session(rule_default_strategy_id="D3"),
            {"credential_keyword_count": 1}, {}, "RULE_ADAPTIVE",
        )
        self.assertEqual(decision.strategy_id, "D3")

    def test_static_safe_unknown_and_degraded_modes_select_d0(self):
        for mode in ("STATIC", "SAFE_MODE", "HYBRID_ACTIVE", "invalid"):
            with self.subTest(mode=mode):
                self.assertEqual(self.agent.decide(
                    session(), {"backup_keyword_count": 1}, {}, mode
                ).strategy_id, "D0")
        degraded = RuleOnlyStrategyAgent(
            PolicyGuard(StrategyRegistry.safe_fallback("test"))
        )
        self.assertEqual(degraded.decide(
            session(), {"backup_keyword_count": 1}, {}, "RULE_ADAPTIVE"
        ).strategy_id, "D0")

    def test_forged_action_space_cannot_select_unapproved_strategy(self):
        forged = ActionSpace(
            ("D5",), "D5", POLICY_VERSION,
            self.registry.registry_version, "RULE_ADAPTIVE",
        )
        self.assertEqual(self.agent.select(forged).strategy_id, "D0")

    def test_missing_default_in_action_space_fails_to_d0(self):
        malformed = ActionSpace(
            ("D2",), "D3", POLICY_VERSION,
            self.registry.registry_version, "RULE_ADAPTIVE",
        )
        self.assertEqual(self.agent.select(malformed).strategy_id, "D0")

    def test_registered_rule_boundary_preserves_approved_and_rejects_other(self):
        for strategy_id in ("D0", "D1", "D2", "D3", "D4", "D6"):
            with self.subTest(strategy_id=strategy_id):
                self.assertEqual(
                    self.agent.select_registered_rule(strategy_id).strategy_id,
                    strategy_id,
                )
        for strategy_id in ("D5", "D7", "D999", "../D2", None):
            with self.subTest(strategy_id=strategy_id):
                self.assertEqual(
                    self.agent.select_registered_rule(strategy_id).strategy_id,
                    "D0",
                )

    def test_raw_query_text_does_not_affect_selection(self):
        clean = self.agent.decide(session(), {}, {}, "RULE_ADAPTIVE")
        hostile = self.agent.decide(
            session(query_normalized="backup password drop api_keys_backup"),
            {}, {}, "RULE_ADAPTIVE",
        )
        self.assertEqual(clean, hostile)


class NextStrategyEndpointTests(unittest.TestCase):
    @staticmethod
    def payload():
        return {
            "session_state": {
                "session_id": "next-1", "protocol": "mysql",
                "persona_id": "human_attacker", "database": "hr_production",
                "session_depth": 3, "modified_objects": [],
            },
            "behavior_state": {
                "session_id": "next-1", "backup_keyword_count": 1,
            },
            "mitre_state": {"session_id": "next-1", "phase": "data_discovery"},
            "operator_mode": "RULE_ADAPTIVE",
        }

    def test_structured_endpoint_returns_rule_v1_decision(self):
        result = asyncio.run(api.next_strategy(self.payload()))
        self.assertEqual(result, {
            "strategy_id": "D2", "confidence": 1.0,
            "selector_type": "rule", "policy_version": "rule-v1",
        })

    def test_endpoint_rejects_raw_query_or_identity(self):
        for key in ("query_normalized", "fingerprint", "source_ip"):
            with self.subTest(key=key):
                payload = self.payload()
                payload["behavior_state"][key] = "hostile input"
                with self.assertRaises(HTTPException) as raised:
                    asyncio.run(api.next_strategy(payload))
                self.assertEqual(raised.exception.status_code, 400)

    def test_endpoint_rejects_mismatched_sessions_and_extra_fields(self):
        payload = self.payload()
        payload["mitre_state"]["session_id"] = "other"
        with self.assertRaises(HTTPException) as mismatch:
            asyncio.run(api.next_strategy(payload))
        self.assertEqual(mismatch.exception.status_code, 400)
        payload = self.payload()
        payload["raw"] = "not allowed"
        with self.assertRaises(HTTPException) as extra:
            asyncio.run(api.next_strategy(payload))
        self.assertEqual(extra.exception.status_code, 400)

if __name__ == "__main__":
    unittest.main()
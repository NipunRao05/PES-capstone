"""Rule-only strategy selector bounded by the deterministic policy guard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from policy_guard import ActionSpace, PolicyGuard

RULE_POLICY_VERSION = "rule-v1"


@dataclass(frozen=True)
class StrategyDecision:
    strategy_id: str
    confidence: float = 1.0
    selector_type: str = "rule"
    policy_version: str = RULE_POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "confidence": self.confidence,
            "selector_type": self.selector_type,
            "policy_version": self.policy_version,
        }


class RuleOnlyStrategyAgent:
    """Select exactly the deterministic rule default; never expand actions."""

    def __init__(self, policy_guard: PolicyGuard):
        self.policy_guard = policy_guard

    def select(self, action_space: ActionSpace) -> StrategyDecision:
        requested = action_space.default if isinstance(action_space, ActionSpace) else ""
        allowed = action_space.allowed if isinstance(action_space, ActionSpace) else ()
        if requested not in allowed:
            requested = self.policy_guard.registry.default_strategy_id
        selected = self.policy_guard.enforce_registered_choice(requested)
        if selected not in allowed:
            selected = self.policy_guard.registry.default_strategy_id
        return StrategyDecision(strategy_id=selected)

    def decide(
        self,
        session_state: Any,
        behavior_state: Any,
        mitre_state: Any = None,
        operator_mode: Any = "STATIC",
    ) -> StrategyDecision:
        action_space = self.policy_guard.evaluate(
            session_state, behavior_state, mitre_state, operator_mode
        )
        return self.select(action_space)

    def select_registered_rule(self, requested: Any) -> StrategyDecision:
        """Preserve an existing rule choice only when the guard approves it."""
        selected = self.policy_guard.enforce_registered_choice(requested)
        return StrategyDecision(strategy_id=selected)
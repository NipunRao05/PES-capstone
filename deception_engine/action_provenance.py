"""Ephemeral producer identity; never part of client or engine JSON payloads."""
from dataclasses import dataclass
from strategy_registry import PRODUCER_ACTIONS


@dataclass(frozen=True)
class ActionProvenance:
    actual: str | None
    expected: str
    status: str


def verify_action(strategy, actual):
    if actual is None:
        return ActionProvenance(None, strategy.action_binding, "NOT_VERIFIED")
    if actual not in PRODUCER_ACTIONS:
        return ActionProvenance(actual, strategy.action_binding, "INVALID_ACTION")
    return ActionProvenance(actual, strategy.action_binding,
        "MATCH" if actual == strategy.action_binding else "MISMATCH")

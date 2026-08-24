"""Deterministic safe action-space policy for approved deception strategies."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from strategy_registry import Strategy, StrategyRegistry

POLICY_VERSION = "policy-guard-v1"
_ACTIVE_MODES = {"RULE_ADAPTIVE", "HYBRID_LEARNED_ADAPTIVE"}
_PASSIVE_MODES = {"STATIC", "SAFE_MODE"}
_DEFAULT_PRIORITY = ("D6", "D2", "D3", "D4", "D1", "D0")
_FIELD_ALIASES = {
    "session_id": ("session_id",),
    "protocol": ("protocol",),
    "persona_id": ("persona_id", "persona"),
    "database": ("database",),
    "session_depth": ("session_depth", "query_count"),
    "user": ("user", "db_user", "username"),
    "role": ("role",),
    "permissions": ("permissions",),
    "modified_objects": ("modified_objects",),
}


@dataclass(frozen=True)
class ActionSpace:
    allowed: tuple[str, ...]
    default: str
    policy_version: str
    registry_version: str
    operator_mode: str
    fallback_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": list(self.allowed),
            "default": self.default,
            "policy_version": self.policy_version,
            "registry_version": self.registry_version,
            "operator_mode": self.operator_mode,
            "fallback_reason": self.fallback_reason,
        }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _normalise_protocol(value: Any) -> str:
    protocol = str(value or "").strip().lower()
    if protocol == "mysql" or protocol.startswith("mysql"):
        return "mysql"
    if protocol in {"pg", "postgres", "postgresql"} or protocol.startswith("postgres"):
        return "postgres"
    return ""


def _safe_count(value: Any) -> int:
    try:
        count = float(value)
    except (TypeError, ValueError):
        return 0
    if not math.isfinite(count):
        return 0
    return min(max(int(count), 0), 1_000_000)


def _true(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == 1


class PolicyGuard:
    """Build and enforce the legal strategy set from structured internal state."""

    def __init__(self, registry: StrategyRegistry):
        self.registry = registry
        self._default = registry.resolve(registry.default_strategy_id).strategy_id

    @staticmethod
    def _lookup(field: str, sources: tuple[Mapping[str, Any], ...]) -> tuple[bool, Any]:
        aliases = _FIELD_ALIASES.get(field, (field,))
        for source in sources:
            for alias in aliases:
                if alias not in source:
                    continue
                value = source[alias]
                if value is None or (isinstance(value, str) and not value.strip()):
                    continue
                return True, value
        return False, None

    @staticmethod
    def _objects(session: Mapping[str, Any]) -> set[str]:
        objects: set[str] = set()
        for field in ("triggered_traps", "discovered_objects", "modified_objects"):
            values = session.get(field, [])
            if not isinstance(values, (list, tuple, set)):
                continue
            for value in values:
                name = str(value or "").strip().lower()[:256]
                if name:
                    objects.add(name)
        return objects

    @staticmethod
    def _asset_observed(strategy: Strategy, objects: set[str]) -> bool:
        assets = {item.lower() for item in (*strategy.schema_assets, *strategy.trap_assets)}
        assets.update(item.split(".")[-1] for item in tuple(assets))
        for observed in objects:
            base = observed.split(".")[-1]
            if observed in assets or base in assets:
                return True
        return False

    def _requirements_met(
        self,
        strategy: Strategy,
        sources: tuple[Mapping[str, Any], ...],
    ) -> bool:
        return all(self._lookup(field, sources)[0] for field in strategy.required_state)

    @staticmethod
    def _forbidden(strategy: Strategy, session: Mapping[str, Any]) -> bool:
        if strategy.strategy_id == "D6":
            return (
                session.get("target_is_managed_synthetic") is False
                or _true(session.get("target_outside_managed_synthetic_schema"))
            )
        return False

    def _activated(
        self,
        strategy: Strategy,
        session: Mapping[str, Any],
        behavior: Mapping[str, Any],
        mitre: Mapping[str, Any],
    ) -> bool:
        strategy_id = strategy.strategy_id
        objects = self._objects(session)
        stage = str(
            behavior.get("mitre_stage") or mitre.get("phase") or mitre.get("tactic") or ""
        ).strip().lower()
        if strategy_id == "D0":
            return True
        if strategy_id == "D1":
            return (
                _safe_count(behavior.get("catalog_query_count")) > 0
                or _safe_count(behavior.get("metadata_query_count")) > 0
                or stage in {"recon", "enumeration"}
            )
        if strategy_id == "D2":
            return (
                _safe_count(behavior.get("backup_keyword_count")) > 0
                or self._asset_observed(strategy, objects)
            )
        if strategy_id == "D3":
            return (
                _safe_count(behavior.get("credential_keyword_count")) > 0
                or self._asset_observed(strategy, objects)
            )
        if strategy_id == "D4":
            return (
                _safe_count(behavior.get("sensitive_table_interest")) > 0
                or self._asset_observed(strategy, objects)
            )
        if strategy_id == "D6":
            confirmed_managed = (
                _true(session.get("target_is_managed_synthetic"))
                or bool(session.get("modified_objects"))
            )
            return _safe_count(behavior.get("destructive_query_count")) > 0 and confirmed_managed
        # New registry entries require an explicit deterministic guard rule.
        return False

    def evaluate(
        self,
        session_state: Any,
        behavior_state: Any,
        mitre_state: Any = None,
        operator_mode: Any = "STATIC",
    ) -> ActionSpace:
        session = _mapping(session_state)
        behavior = _mapping(behavior_state)
        mitre = _mapping(mitre_state)
        sources = (session, behavior, mitre)
        mode = str(operator_mode or "").strip().upper()

        if self.registry.degraded:
            return self._fallback(mode, "registry_degraded")
        if mode in _PASSIVE_MODES:
            return self._fallback(mode, "operator_mode_rules_only")
        if mode not in _ACTIVE_MODES:
            return self._fallback(mode, "operator_mode_unknown")

        _, raw_protocol = self._lookup("protocol", sources)
        protocol = _normalise_protocol(raw_protocol)
        if not protocol:
            return self._fallback(mode, "protocol_missing_or_unsupported")

        _, raw_persona = self._lookup("persona_id", sources)
        persona = str(raw_persona or "unknown").strip().lower()
        allowed: list[str] = []
        for strategy in self.registry.approved():
            if strategy.strategy_id == self._default:
                allowed.append(strategy.strategy_id)
                continue
            if protocol not in strategy.supported_protocols:
                continue
            if persona not in strategy.compatible_personas:
                continue
            if not self._requirements_met(strategy, sources):
                continue
            if self._forbidden(strategy, session):
                continue
            if self._activated(strategy, session, behavior, mitre):
                allowed.append(strategy.strategy_id)

        if self._default not in allowed:
            allowed.insert(0, self._default)
        requested = str(session.get("rule_default_strategy_id") or "").strip().upper()
        if requested in allowed:
            default = requested
        else:
            default = next(item for item in _DEFAULT_PRIORITY if item in allowed)
        return ActionSpace(
            tuple(allowed), default, POLICY_VERSION,
            self.registry.registry_version, mode,
        )

    def _fallback(self, mode: str, reason: str) -> ActionSpace:
        return ActionSpace(
            (self._default,), self._default, POLICY_VERSION,
            self.registry.registry_version, mode, reason,
        )

    def enforce_choice(self, requested: Any, action_space: ActionSpace) -> str:
        candidate = str(requested or "").strip().upper()
        return candidate if candidate in action_space.allowed else action_space.default

    def enforce_registered_choice(self, requested: Any) -> str:
        """Final attacker-facing barrier independent of adaptive availability."""
        candidate = str(requested or "").strip().upper()
        strategy = self.registry.get(candidate)
        if strategy is None or strategy.approval_status != "APPROVED":
            return self._default
        if candidate not in {"D0", "D1", "D2", "D3", "D4", "D6"}:
            return self._default
        return candidate

"""Versioned registry for existing deterministic deception strategies."""

from __future__ import annotations

import re
import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from world_commitments import Commitments, Fact

DEFAULT_REGISTRY_PATH = Path(__file__).parent / "strategies" / "registry.yaml"
_SAFE_ASSET = re.compile(r"^[A-Za-z0-9_.-]+$")
_ALLOWED_PROTOCOLS = {"mysql", "postgres"}
_ALLOWED_APPROVAL = {"APPROVED", "REQUIRES_REVIEW", "REJECTED"}
_ALLOWED_RISK = {"low", "medium", "high", "critical"}
_ALLOWED_COST = {"low", "medium", "high"}
ACTION_BINDINGS = {"D0": "baseline_response", "D1": "catalog_response",
    "D2": "backup_asset_read", "D3": "credential_asset_read",
    "D4": "sensitive_asset_read", "D5": "review_only", "D6": "managed_mutation"}
PRODUCER_ACTIONS = frozenset(ACTION_BINDINGS.values()) - {"review_only"} | {"policy_rejection", "statement_error"}


class RegistryValidationError(ValueError):
    """Registry metadata violates the deterministic safety contract."""


@dataclass(frozen=True)
class Strategy:
    strategy_id: str
    name: str
    description: str
    supported_protocols: tuple[str, ...]
    required_state: tuple[str, ...]
    forbidden_state: tuple[str, ...]
    activation_conditions: tuple[str, ...]
    compatible_personas: tuple[str, ...]
    schema_assets: tuple[str, ...]
    trap_assets: tuple[str, ...]
    risk_level: str
    resource_cost: str
    validation_version: str
    approval_status: str
    evidence: tuple[str, ...] = ()
    strategy_version: int = 1
    implementation: str = "existing_deterministic"
    commitment_preconditions: tuple[Fact, ...] = ()
    action_binding: str = "baseline_response"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Strategy":
        required = {
            "strategy_id", "name", "description", "supported_protocols",
            "required_state", "forbidden_state", "activation_conditions",
            "compatible_personas", "schema_assets", "trap_assets", "risk_level",
            "resource_cost", "validation_version", "approval_status",
        }
        missing = sorted(required - set(raw))
        if missing:
            raise RegistryValidationError(f"missing metadata: {', '.join(missing)}")

        def strings(field: str) -> tuple[str, ...]:
            value = raw.get(field)
            if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
                raise RegistryValidationError(f"{raw.get('strategy_id', '?')}.{field} must be a string list")
            return tuple(x.strip() for x in value)

        evidence = raw.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(x, str) or not x.strip() for x in evidence):
            raise RegistryValidationError("evidence must be a string list")
        version = raw.get("strategy_version", 1)
        if type(version) is not int or not 1 <= version <= 65535:
            raise RegistryValidationError("invalid strategy version")
        if raw.get("implementation", "existing_deterministic") != "existing_deterministic":
            raise RegistryValidationError("unknown implementation")
        conditions = raw.get("commitment_preconditions", [])
        if not isinstance(conditions, list) or len(conditions) > 16:
            raise RegistryValidationError("invalid preconditions")
        try:
            facts = tuple(Fact(x["namespace"], x["subject"], x["property"], x["value"])
                for x in conditions if isinstance(x, dict) and set(x) == {"op", "namespace", "subject", "property", "value"} and x["op"] == "requires")
        except (ValueError, TypeError, KeyError) as exc:
            raise RegistryValidationError("invalid preconditions") from exc
        if len(facts) != len(conditions) or len({f.key for f in facts}) != len(facts):
            raise RegistryValidationError("invalid preconditions")
        binding = raw.get("action_binding", ACTION_BINDINGS.get(raw.get("strategy_id")))
        if binding not in ACTION_BINDINGS.values() or (binding == "review_only" and raw["approval_status"] == "APPROVED"):
            raise RegistryValidationError("unknown or non-executable action binding")
        item = cls(
            strategy_id=str(raw["strategy_id"]).strip(),
            name=str(raw["name"]).strip(),
            description=str(raw["description"]).strip(),
            supported_protocols=strings("supported_protocols"),
            required_state=strings("required_state"),
            forbidden_state=strings("forbidden_state"),
            activation_conditions=strings("activation_conditions"),
            compatible_personas=strings("compatible_personas"),
            schema_assets=strings("schema_assets"),
            trap_assets=strings("trap_assets"),
            risk_level=str(raw["risk_level"]).strip().lower(),
            resource_cost=str(raw["resource_cost"]).strip().lower(),
            validation_version=str(raw["validation_version"]).strip(),
            approval_status=str(raw["approval_status"]).strip().upper(),
            evidence=tuple(x.strip() for x in evidence),
            strategy_version=version, commitment_preconditions=facts,
            action_binding=binding,
        )
        item.validate()
        return item

    def validate(self) -> None:
        if not re.fullmatch(r"D[0-9]+", self.strategy_id):
            raise RegistryValidationError(f"invalid strategy_id: {self.strategy_id}")
        if not self.name or not self.description or not self.validation_version:
            raise RegistryValidationError(f"{self.strategy_id} contains empty metadata")
        if not self.supported_protocols or not set(self.supported_protocols) <= _ALLOWED_PROTOCOLS:
            raise RegistryValidationError(f"{self.strategy_id} has unsupported protocols")
        if set(self.required_state) & set(self.forbidden_state):
            raise RegistryValidationError(f"{self.strategy_id} requires and forbids the same state")
        if not self.activation_conditions or not self.compatible_personas:
            raise RegistryValidationError(f"{self.strategy_id} has incomplete conditions/personas")
        if self.risk_level not in _ALLOWED_RISK or self.resource_cost not in _ALLOWED_COST:
            raise RegistryValidationError(f"{self.strategy_id} has invalid risk/cost")
        if self.approval_status not in _ALLOWED_APPROVAL:
            raise RegistryValidationError(f"{self.strategy_id} has invalid approval_status")
        for asset in (*self.schema_assets, *self.trap_assets):
            if not _SAFE_ASSET.fullmatch(asset) or "://" in asset:
                raise RegistryValidationError(f"{self.strategy_id} contains unsafe asset: {asset}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id, "name": self.name,
            "description": self.description,
            "supported_protocols": list(self.supported_protocols),
            "required_state": list(self.required_state),
            "forbidden_state": list(self.forbidden_state),
            "activation_conditions": list(self.activation_conditions),
            "compatible_personas": list(self.compatible_personas),
            "schema_assets": list(self.schema_assets),
            "trap_assets": list(self.trap_assets),
            "risk_level": self.risk_level, "resource_cost": self.resource_cost,
            "validation_version": self.validation_version,
            "approval_status": self.approval_status,
            "evidence": list(self.evidence),
            "strategy_version": self.strategy_version,
            "action_binding": self.action_binding,
            "implementation": self.implementation,
            "commitment_preconditions": [dict(op="requires", namespace=f.namespace, subject=f.subject, property=f.property, value=f.value) for f in self.commitment_preconditions],
        }


    def definition_digest(self) -> str:
        semantic = self.to_dict()
        for key in ("name", "description", "approval_status", "evidence", "validation_version", "implementation"):
            semantic.pop(key)
        for key, value in semantic.items():
            if isinstance(value, list):
                semantic[key] = sorted(value, key=lambda x: json.dumps(x, sort_keys=True))
        return hashlib.sha256(json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class StrategyRegistry:
    def __init__(self, registry_version: str, default_strategy_id: str,
                 strategies: list[Strategy], unmapped_strategy_ids: tuple[str, ...] = (),
                 *, degraded: bool = False, load_error: str = "", active_versions=None):
        self.registry_version = str(registry_version).strip()
        self.default_strategy_id = str(default_strategy_id).strip()
        self.unmapped_strategy_ids = tuple(unmapped_strategy_ids)
        self.degraded = degraded
        self.load_error = str(load_error)
        self._versions = {(item.strategy_id, item.strategy_version): item for item in strategies}
        if len(self._versions) != len(strategies):
            raise RegistryValidationError("duplicate strategy ID/version")
        if active_versions is None:
            if len({x.strategy_id for x in strategies}) != len(strategies):
                raise RegistryValidationError("multiple versions require explicit active_versions")
            active_versions = {x.strategy_id: x.strategy_version for x in strategies}
        if not isinstance(active_versions, dict) or set(active_versions) != {x.strategy_id for x in strategies}:
            raise RegistryValidationError("invalid active_versions")
        self.active_versions = dict(active_versions)
        self._strategies = {}
        for sid, version in active_versions.items():
            if type(version) is not int or (sid, version) not in self._versions:
                raise RegistryValidationError("active version not found")
            self._strategies[sid] = self._versions[sid, version]
        default = self._strategies.get(self.default_strategy_id)
        if not self.registry_version or default is None or default.approval_status != "APPROVED":
            raise RegistryValidationError("an approved default strategy and registry_version are required")
        if set(self._strategies) & set(self.unmapped_strategy_ids):
            raise RegistryValidationError("mapped and unmapped strategy IDs overlap")
        if any(not re.fullmatch(r"D[0-9]+", item) for item in self.unmapped_strategy_ids):
            raise RegistryValidationError("invalid unmapped strategy_id")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "StrategyRegistry":
        if not isinstance(raw, dict):
            raise RegistryValidationError("registry root must be an object")
        items = raw.get("strategies")
        unmapped = raw.get("unmapped_strategy_ids", [])
        if not isinstance(items, list) or not items or any(not isinstance(x, dict) for x in items):
            raise RegistryValidationError("strategies must be a non-empty object list")
        if not isinstance(unmapped, list) or any(not isinstance(x, str) for x in unmapped):
            raise RegistryValidationError("unmapped_strategy_ids must be a string list")
        return cls(raw.get("registry_version", ""), raw.get("default_strategy_id", ""),
                   [Strategy.from_dict(x) for x in items], tuple(x.strip() for x in unmapped), active_versions=raw.get("active_versions"))

    @classmethod
    def load(cls, path: Path = DEFAULT_REGISTRY_PATH) -> "StrategyRegistry":
        with path.open("r", encoding="utf-8") as handle:
            registry = cls.from_dict(yaml.safe_load(handle))
        with path.with_suffix(".lock.json").open("r", encoding="utf-8") as handle:
            registry.validate_lock(json.load(handle))
        return registry

    def validate_lock(self, manifest):
        for (sid, version), item in self._versions.items():
            if manifest.get(f"{sid}:{version}") != item.definition_digest():
                raise RegistryValidationError(f"{sid} v{version}: definition integrity mismatch")

    @classmethod
    def load_with_fallback(cls, path: Path = DEFAULT_REGISTRY_PATH) -> "StrategyRegistry":
        try:
            return cls.load(path)
        except Exception as exc:
            return cls.safe_fallback(f"{type(exc).__name__}: {exc}")

    @classmethod
    def safe_fallback(cls, reason: str) -> "StrategyRegistry":
        d0 = Strategy("D0", "BASELINE",
            "Immutable deterministic protocol/backend fallback.",
            ("mysql", "postgres"), ("session_id", "protocol"), (),
            ("registry unavailable", "requested strategy missing or unapproved"),
            ("unknown", "low_activity", "script", "automated_tool", "human_attacker", "brute_bot"),
            (), (), "low", "low", "builtin-fallback-v1", "APPROVED",
            ("deception_engine/api.py",))
        return cls("builtin-fallback-v1", "D0", [d0],
                   ("D1", "D2", "D3", "D4", "D5", "D6", "D7"),
                   degraded=True, load_error=reason)

    def get(self, strategy_id: str, strategy_version: int | None = None) -> Strategy | None:
        sid = str(strategy_id or "").strip()
        return self._strategies.get(sid) if strategy_version is None else self._versions.get((sid, strategy_version))

    def eligibility(self, strategy_id: str, strategy_version: int, protocol: str, record: dict) -> tuple[bool, str]:
        item = self.get(strategy_id)
        if item is None:
            return False, "UNKNOWN_STRATEGY"
        item = self.get(strategy_id, strategy_version)
        if item is None:
            return False, "UNKNOWN_VERSION"
        if item.approval_status != "APPROVED":
            return False, "NOT_APPROVED"
        if protocol not in item.supported_protocols:
            return False, "UNSUPPORTED_PROTOCOL"
        try:
            commitments = Commitments(record)
            for fact in item.commitment_preconditions:
                state = commitments.check(fact)
                if state == "unobserved":
                    return False, "PRECONDITION_MISSING"
                if state == "conflict":
                    return False, "PRECONDITION_MISMATCH"
        except (ValueError, TypeError, KeyError):
            return False, "INVALID_COMMITMENTS"
        return True, "APPROVED"

    def resolve(self, strategy_id: str) -> Strategy:
        item = self.get(strategy_id)
        if item is not None and item.approval_status == "APPROVED":
            return item
        return self._strategies[self.default_strategy_id]

    def approved(self) -> list[Strategy]:
        return [x for x in self._strategies.values() if x.approval_status == "APPROVED"]

    def strategy_for_asset(self, schema_name: str, table_name: str) -> Strategy:
        table = str(table_name or "").strip().lower()
        qualified = f"{str(schema_name or '').strip().lower()}.{table}"
        for strategy_id in ("D2", "D3", "D4"):
            item = self.get(strategy_id)
            if item is None or item.approval_status != "APPROVED":
                continue
            assets = {x.lower() for x in (*item.schema_assets, *item.trap_assets)}
            if table in assets or qualified in assets:
                return item
        return self.resolve(self.default_strategy_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_version": self.registry_version,
            "active_versions": dict(self.active_versions),
            "default_strategy_id": self.default_strategy_id,
            "degraded": self.degraded,
            "strategy_count": len(self._strategies),
            "approved_strategy_ids": [x.strategy_id for x in self.approved()],
            "unmapped_strategy_ids": list(self.unmapped_strategy_ids),
            "strategies": [x.to_dict() for x in self._versions.values()],
        }

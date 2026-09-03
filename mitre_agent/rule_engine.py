"""
rule_engine.py — Multi-signal YAML-driven detection rule evaluator.

Loads detection_rules.yaml at startup. For each (event, session_context) pair,
evaluates all matching rules and returns:
  - list of TechniqueMatch objects
  - updated risk_score
  - deception_level to apply
  - tags accumulated

Rules are evaluated in priority order. All matching rules contribute to
risk_score cumulatively. The highest deception_level from all matching
rules is used for the proxy response.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

from models import EvalContext, TechniqueMatch

log = logging.getLogger(__name__)

# ─── Rule loader ──────────────────────────────────────────────────────────────

RULES_DIR = Path(__file__).parent / "rules"


def _load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class RuleEngine:
    """
    Loads detection_rules.yaml and all technique definitions at startup.
    Evaluates rules against (event, session) context in priority order.
    Thread-safe: rules are read-only after __init__.
    """

    def __init__(self, rules_path: Path | None = None):
        rp = rules_path or RULES_DIR / "detection_rules.yaml"
        raw = _load_yaml(rp)

        self.globals: dict = raw.get("globals", {})
        self.rules: list[dict] = sorted(
            raw.get("rules", []), key=lambda r: r.get("priority", 99)
        )
        self.thresholds: dict = self.globals.get("risk_thresholds", {
            "low": 2, "medium": 5, "high": 8, "critical": 12
        })

        # Load technique index: technique_id → {name, tactic, tactic_id, confidence}
        self.technique_index: dict[str, dict] = {}
        self._load_techniques(RULES_DIR / "techniques" / "all_techniques.yaml")

        log.info("Rule engine loaded: %d rules, %d techniques",
                 len(self.rules), len(self.technique_index))

    def _load_techniques(self, path: Path) -> None:
        """Load all technique definitions from the multi-document YAML."""
        if not path.exists():
            log.warning("Technique file not found: %s", path)
            return
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        for doc in docs:
            if not doc:
                continue
            tactic = doc.get("tactic", "")
            tactic_id = doc.get("tactic_id", "")
            for t in doc.get("techniques", []):
                tid = t.get("id", "")
                if tid:
                    self.technique_index[tid] = {
                        "name":      t.get("name", ""),
                        "tactic":    tactic,
                        "tactic_id": tactic_id,
                        "confidence": t.get("confidence", 0.70),
                    }

    # ─── Public API ───────────────────────────────────────────────────────────

    def evaluate(self, ctx: EvalContext) -> "RuleResult":
        """
        Evaluate all rules against the given context.
        Returns a RuleResult with all matched techniques, total risk delta,
        deception level, and accumulated tags.
        """
        matched_techniques: list[TechniqueMatch] = []
        risk_delta: float = 0.0
        deception_level: int = 1
        tags: list[str] = []
        is_trap: bool = False

        for rule in self.rules:
            if not self._matches(rule, ctx):
                continue
            if not self._conditions_met(rule, ctx):
                continue

            # Scoring
            score = self._compute_score(rule, ctx)
            risk_delta += score

            # Technique lookup
            technique_id = rule.get("mitre_technique", "")
            if rule.get("id") == "R001_trap_table_access" and ctx.trap_mitre_technique_id:
                technique_id = ctx.trap_mitre_technique_id
            tm = self._build_technique_match(rule, technique_id, ctx)
            if tm:
                matched_techniques.append(tm)

            # Actions
            for action in rule.get("actions", []):
                action_type = action.get("type", "")
                if action_type == "tag":
                    tags.append(action.get("value", ""))
                elif action_type == "escalate_risk":
                    level = action.get("level", "")
                    if level == "critical":
                        risk_delta = max(risk_delta, self.thresholds["critical"])

            # Trap detection
            if "trap_triggered" in [a.get("value") for a in rule.get("actions", [])]:
                is_trap = True

            # Deception level — take highest
            response = rule.get("response", {})
            dl = response.get("deception_level", 1)
            deception_level = max(deception_level, dl)

        new_risk = ctx.risk_score + risk_delta
        risk_level = self._risk_level(new_risk)

        return RuleResult(
            matched_techniques=matched_techniques,
            risk_delta=risk_delta,
            new_risk_score=new_risk,
            risk_level=risk_level,
            deception_level=deception_level,
            tags=list(set(tags)),
            is_trap_triggered=is_trap,
            explanation=self._build_explanation(matched_techniques),
        )

    # ─── Match helpers ────────────────────────────────────────────────────────

    def _matches(self, rule: dict, ctx: EvalContext) -> bool:
        """Check the 'match' block — any/all conditions on event fields."""
        match_block = rule.get("match", {})
        if not match_block:
            return True  # no match = always fires

        any_conditions = match_block.get("any", [])
        all_conditions = match_block.get("all", [])

        if any_conditions:
            if not any(self._eval_match_condition(c, ctx) for c in any_conditions):
                return False
        if all_conditions:
            if not all(self._eval_match_condition(c, ctx) for c in all_conditions):
                return False
        return True

    def _eval_match_condition(self, condition: str, ctx: EvalContext) -> bool:
        """Evaluate a single match condition string."""
        condition = condition.strip()

        # event.phase == "value"
        if condition.startswith("event.phase =="):
            val = condition.split("==")[1].strip().strip('"').strip("'")
            return ctx.phase == val

        # event.phase in ["a", "b"]
        if condition.startswith("event.phase in"):
            vals_str = condition.split("in", 1)[1].strip().strip("[]")
            vals = [v.strip().strip('"').strip("'") for v in vals_str.split(",")]
            return ctx.phase in vals

        # event.event_type == "value"
        if condition.startswith("event.event_type =="):
            val = condition.split("==")[1].strip().strip('"').strip("'")
            return ctx.event_type == val

        # event.fingerprint contains "pattern"
        if "event.fingerprint contains" in condition:
            pattern = condition.split("contains", 1)[1].strip().strip('"').strip("'").lower()
            return pattern in (ctx.fingerprint or "").lower()

        # event.table in [...]
        if condition.startswith("event.table in"):
            vals_str = condition.split("in", 1)[1].strip().strip("[]")
            vals = [v.strip().strip('"').strip("'") for v in vals_str.split(",")]
            return ctx.table in vals

        # Successful structured trap outcome supplied by the proxy/deception
        # authority. This removes trap-name lists from the live v2 path.
        if condition.startswith("event.trap_triggered =="):
            val = condition.split("==", 1)[1].strip().lower()
            return ctx.trap_triggered is (val == "true")

        log.debug("Unrecognised match condition: %s", condition)
        return False

    def _conditions_met(self, rule: dict, ctx: EvalContext) -> bool:
        """Check the 'conditions' block — all conditions on session features."""
        conditions = rule.get("conditions", {})
        if not conditions:
            return True

        all_conds = conditions.get("all", [])
        for cond in all_conds:
            if not self._eval_session_condition(cond, ctx):
                return False
        return True

    def _eval_session_condition(self, condition: str, ctx: EvalContext) -> bool:
        """Evaluate a single session condition string."""
        condition = condition.strip()

        # Map field name → ctx attribute
        field_map = {
            "session.query_count":        ctx.query_count,
            "session.timing_variance_ms": ctx.timing_variance_ms,
            "session.qps":                ctx.qps,
            "session.depth_score":        ctx.depth_score,
            "session.failed_auth":        ctx.failed_auth,
            "session.suspicion_score":    ctx.suspicion_score,
            "session.risk_score":         ctx.risk_score,
            "session.entropy":            ctx.entropy,
            "session.fingerprint_reuse":  ctx.fingerprint_reuse,
        }

        for field, value in field_map.items():
            if condition.startswith(field):
                rest = condition[len(field):].strip()
                if rest.startswith(">="):
                    try:
                        threshold = float(rest[2:].strip())
                        return value >= threshold
                    except ValueError:
                        pass
                elif rest.startswith("<="):
                    try:
                        threshold = float(rest[2:].strip())
                        return value <= threshold
                    except ValueError:
                        pass
                elif rest.startswith(">"):
                    try:
                        threshold = float(rest[1:].strip())
                        return value > threshold
                    except ValueError:
                        pass
                elif rest.startswith("<"):
                    try:
                        threshold = float(rest[1:].strip())
                        return value < threshold
                    except ValueError:
                        pass
                elif rest.startswith("=="):
                    try:
                        threshold = float(rest[2:].strip())
                        return value == threshold
                    except ValueError:
                        pass

        log.debug("Unrecognised session condition: %s", condition)
        return False

    # ─── Scoring ──────────────────────────────────────────────────────────────

    def _compute_score(self, rule: dict, ctx: EvalContext) -> float:
        scoring = rule.get("scoring", {})
        score = float(scoring.get("base", 0))
        if rule.get("id") == "R001_trap_table_access" and ctx.trap_risk_score > 0:
            score = min(25.0, ctx.trap_risk_score)

        for modifier in scoring.get("modifiers", []):
            if_clause = modifier.get("if", "")
            then_add = float(modifier.get("then_add", 0))
            if self._eval_modifier_condition(if_clause, ctx):
                score += then_add

        return score

    def _eval_modifier_condition(self, condition: str, ctx: EvalContext) -> bool:
        """Same logic as _eval_session_condition but for modifier 'if' strings."""
        return self._eval_session_condition(condition, ctx)

    # ─── Technique builder ────────────────────────────────────────────────────

    def _build_technique_match(
        self, rule: dict, technique_id: str, ctx: EvalContext
    ) -> TechniqueMatch | None:
        if not technique_id:
            return None
        info = self.technique_index.get(technique_id, {})
        explanation = (
            f"Rule {rule['id']} matched: phase={ctx.phase}, "
            f"fingerprint='{ctx.fingerprint[:40]}', "
            f"qps={ctx.qps:.1f}, timing_var={ctx.timing_variance_ms:.0f}ms"
        )
        return TechniqueMatch(
            technique_id=technique_id,
            technique_name=info.get("name", technique_id),
            tactic=info.get("tactic", "Unknown"),
            tactic_id=info.get("tactic_id", ""),
            confidence=info.get("confidence", 0.70),
            matched_by="fingerprint" if ctx.fingerprint else "phase",
            explanation=explanation,
            rule_id=rule.get("id", ""),
        )

    # ─── Risk level ───────────────────────────────────────────────────────────

    def _risk_level(self, score: float) -> str:
        if score >= self.thresholds.get("critical", 12):
            return "critical"
        if score >= self.thresholds.get("high", 8):
            return "high"
        if score >= self.thresholds.get("medium", 5):
            return "medium"
        return "low"

    def _build_explanation(self, matches: list[TechniqueMatch]) -> str:
        if not matches:
            return "No MITRE techniques matched"
        parts = [f"{m.technique_id} ({m.technique_name})" for m in matches]
        return "Matched: " + ", ".join(parts)


# ─── Rule result ──────────────────────────────────────────────────────────────

from dataclasses import dataclass, field as dc_field


@dataclass
class RuleResult:
    matched_techniques: list[TechniqueMatch]
    risk_delta:         float
    new_risk_score:     float
    risk_level:         str
    deception_level:    int
    tags:               list[str]
    is_trap_triggered:  bool
    explanation:        str

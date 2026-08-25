"""Bounded human review workflow for Phase 15 strategy-gap proposals.

Phase 16 records human governance decisions only. APPROVE means
APPROVED_FOR_VALIDATION and never strategy approval, activation, or deployment.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any

try:
    from .gap_detection import PROPOSAL_SCHEMA_VERSION
except ImportError:  # Direct script execution in the documented local container.
    from gap_detection import PROPOSAL_SCHEMA_VERSION

REVIEW_SCHEMA_VERSION = "blue-team-review-v1"
REVIEW_STORE_VERSION = "bounded-review-store-v1"

_ACTIONS = {
    "APPROVE": "APPROVED_FOR_VALIDATION",
    "REJECT": "REJECTED",
    "MODIFY": "MODIFICATION_REQUESTED",
    "REQUEST_MORE_EVIDENCE": "MORE_EVIDENCE_REQUIRED",
}
_PROPOSAL_KEYS = {
    "proposal_schema_version", "proposal_id", "status", "proposal_type", "name",
    "trigger_context", "reason", "supporting_session_ids", "supporting_decision_ids",
    "observed_behavior", "existing_strategy_analysis", "estimated_benefit",
    "confidence", "confidence_label", "confidence_basis", "proposed_capability",
    "risks", "resource_cost", "authority",
}
_PROPOSAL_AUTHORITY = {
    "read_only": True,
    "deployable": False,
    "requires_human_review": True,
    "registry_mutation": False,
    "policy_mutation": False,
    "live_execution": False,
}
_FORBIDDEN_EXECUTABLE_KEYS = {
    "command", "commands", "executable", "script", "shell", "sql", "code",
    "callback", "endpoint", "external_url",
}
_MODIFIABLE_FIELDS = {
    "name", "trigger_context", "proposed_capability.objective",
    "proposed_capability.suggested_assets",
    "proposed_capability.suggested_behavior", "resource_cost",
}
_EVIDENCE_REQUESTS = {
    "MORE_COMPARABLE_SESSIONS", "ADDITIONAL_PROTOCOL_EVIDENCE",
    "MORE_STRATEGY_DIVERSITY", "HIGHER_CONFIDENCE",
    "MORE_BEHAVIORAL_OBSERVATIONS",
}
_RESERVED_REVIEWERS = {
    "agent-self-review", "learning-agent", "learning_agent", "system", "autonomous-agent",
}
_PROPOSAL_ID = re.compile(r"^P-[0-9a-f]{24}$")
_REFERENCE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_REVIEWER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ReviewNotApplicable(ValueError):
    """A valid gap result has no reviewable proposal."""

    def __init__(self, classification: str):
        super().__init__(f"{classification} does not contain a reviewable proposal")
        self.classification = classification


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("review input must contain finite JSON values") from exc


def _bounded_string(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = value.strip()
    if not text or len(text) > limit:
        raise ValueError(f"{field} is required and must be <= {limit} characters")
    return text


def _walk_untrusted(value: Any, path: str = "proposal") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in _FORBIDDEN_EXECUTABLE_KEYS:
                raise ValueError(f"unexpected executable field: {key_text}")
            _walk_untrusted(item, f"{path}.{key_text}")
    elif isinstance(value, list):
        if len(value) > 100:
            raise ValueError(f"{path} exceeds the bounded list size")
        for index, item in enumerate(value):
            _walk_untrusted(item, f"{path}[{index}]")
    elif isinstance(value, str) and len(value) > 4096:
        raise ValueError(f"{path} exceeds the bounded string size")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{path} must be finite")


def _reference_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 50:
        raise ValueError(f"{field} must contain between 1 and 50 references")
    references: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _REFERENCE_ID.fullmatch(item):
            raise ValueError(f"{field} contains an invalid reference")
        if item in references:
            raise ValueError(f"{field} contains duplicate references")
        references.append(item)
    return references


def _string_list(value: Any, field: str, minimum: int = 0, maximum: int = 25) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} has an invalid item count")
    return [_bounded_string(item, field, 1024) for item in value]


def validate_proposal(proposal: Any) -> dict:
    """Validate and copy the exact Phase 15 proposal contract."""
    if not isinstance(proposal, dict) or set(proposal) != _PROPOSAL_KEYS:
        raise ValueError("a complete Phase 15 proposal object is required")
    if len(_canonical(proposal)) > 256_000:
        raise ValueError("proposal exceeds the bounded input size")
    _walk_untrusted(proposal)
    proposal_id = str(proposal.get("proposal_id") or "")
    if not _PROPOSAL_ID.fullmatch(proposal_id):
        raise ValueError("proposal_id is invalid")
    if (
        proposal.get("proposal_schema_version") != PROPOSAL_SCHEMA_VERSION
        or proposal.get("proposal_type") != "ACTION_SPACE_GAP"
        or proposal.get("status") != "REQUIRES_REVIEW"
        or proposal.get("estimated_benefit") is not None
    ):
        raise ValueError("proposal type, state, version, or benefit contract is invalid")
    _bounded_string(proposal.get("name"), "proposal name", 128)
    _bounded_string(proposal.get("reason"), "proposal reason", 2048)
    _bounded_string(proposal.get("confidence_basis"), "confidence basis", 1024)
    if proposal.get("confidence_label") not in {"LOW", "MEDIUM", "HIGH"}:
        raise ValueError("proposal confidence label is invalid")
    confidence = proposal.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError("proposal confidence must be numeric")
    if not math.isfinite(float(confidence)) or not 0 <= float(confidence) <= 1:
        raise ValueError("proposal confidence must be between zero and one")
    _reference_list(proposal.get("supporting_session_ids"), "supporting_session_ids")
    _reference_list(proposal.get("supporting_decision_ids"), "supporting_decision_ids")
    if proposal.get("authority") != _PROPOSAL_AUTHORITY:
        raise ValueError("proposal authority is invalid or forged")
    if proposal.get("resource_cost") not in {"unknown", "low", "medium", "high"}:
        raise ValueError("proposal resource_cost is invalid")

    trigger = proposal.get("trigger_context")
    if not isinstance(trigger, dict) or set(trigger) != {
        "context_version", "protocol", "context_group", "signal", "feature_rule"
    }:
        raise ValueError("proposal trigger context is invalid")
    for field in trigger:
        _bounded_string(trigger[field], f"trigger_context.{field}", 1024)

    observed = proposal.get("observed_behavior")
    if not isinstance(observed, dict) or set(observed) != {
        "signal", "target_feature_evidence", "comparable_completed_session_count",
        "weak_completed_history_count", "weak_strategy_ids",
    }:
        raise ValueError("proposal observed behavior is invalid")
    _bounded_string(observed.get("signal"), "observed behavior signal", 128)
    for field in ("comparable_completed_session_count", "weak_completed_history_count"):
        value = observed.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"observed_behavior.{field} must be a positive integer")
    _reference_list(observed.get("weak_strategy_ids"), "weak_strategy_ids")
    if not isinstance(observed.get("target_feature_evidence"), dict):
        raise ValueError("target feature evidence is required")

    analyses = proposal.get("existing_strategy_analysis")
    if not isinstance(analyses, list) or not 1 <= len(analyses) <= 25:
        raise ValueError("existing strategy analysis is required")
    for analysis in analyses:
        if not isinstance(analysis, dict) or set(analysis) != {
            "strategy_id", "strategy_name", "registry_status", "weak_observation_count",
            "supporting_decision_ids", "counterfactual_status",
        }:
            raise ValueError("existing strategy analysis is invalid")
        _bounded_string(analysis.get("strategy_id"), "strategy_id", 16)
        _bounded_string(analysis.get("strategy_name"), "strategy_name", 128)
        _bounded_string(analysis.get("registry_status"), "registry_status", 64)
        _bounded_string(analysis.get("counterfactual_status"), "counterfactual_status", 128)
        count = analysis.get("weak_observation_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("weak observation count must be a nonnegative integer")
        references = analysis.get("supporting_decision_ids")
        if not isinstance(references, list) or len(references) > 50:
            raise ValueError("strategy supporting decision IDs are invalid")
        for reference in references:
            if not isinstance(reference, str) or not _REFERENCE_ID.fullmatch(reference):
                raise ValueError("strategy supporting decision ID is invalid")

    capability = proposal.get("proposed_capability")
    if not isinstance(capability, dict) or set(capability) != {
        "objective", "suggested_assets", "suggested_behavior"
    }:
        raise ValueError("proposed capability is invalid")
    _bounded_string(capability.get("objective"), "capability objective", 2048)
    _string_list(capability.get("suggested_assets"), "suggested_assets", 1)
    _string_list(capability.get("suggested_behavior"), "suggested_behavior", 1)
    _string_list(proposal.get("risks"), "risks", 1)
    return copy.deepcopy(proposal)


def extract_reviewable_proposal(gap_result: Any) -> dict:
    """Extract exactly one reviewable proposal or reject non-gap results."""
    if not isinstance(gap_result, dict):
        raise ValueError("gap result must be an object")
    classification = str(gap_result.get("classification") or "")
    proposals = gap_result.get("proposals")
    if classification in {"NO_GAP_DETECTED", "INSUFFICIENT_EVIDENCE"}:
        if proposals != []:
            raise ValueError("non-gap result must not contain proposals")
        raise ReviewNotApplicable(classification)
    if classification != "ACTION_SPACE_GAP" or not isinstance(proposals, list) or len(proposals) != 1:
        raise ValueError("gap result does not contain exactly one reviewable proposal")
    return validate_proposal(proposals[0])


def _validate_reviewer(value: Any) -> str:
    reviewer = _bounded_string(value, "reviewer", 64)
    normalized = reviewer.lower()
    if (
        not _REVIEWER_ID.fullmatch(reviewer)
        or normalized in _RESERVED_REVIEWERS
        or normalized.startswith("learning-agent-")
    ):
        raise ValueError("an explicit human reviewer ID is required")
    return reviewer


def _validate_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    timestamp = _bounded_string(value, "timestamp", 64)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return timestamp


def _validate_modifications(value: Any) -> list[dict]:
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError("modifications must be a list of at most 20 entries")
    result: list[dict] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"field", "instruction"}:
            raise ValueError("modifications must contain field/instruction objects")
        field = _bounded_string(item.get("field"), "modification field", 128)
        if field not in _MODIFIABLE_FIELDS:
            raise ValueError("modification field is not reviewable in Phase 16")
        instruction = _bounded_string(item.get("instruction"), "modification instruction", 1024)
        result.append({"field": field, "instruction": instruction})
    return result


def _validate_evidence_requests(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 10:
        raise ValueError("requested_evidence must be a list of at most 10 entries")
    result: list[str] = []
    for item in value:
        request = _bounded_string(item, "requested evidence", 128).upper()
        if request not in _EVIDENCE_REQUESTS or request in result:
            raise ValueError("requested evidence is unsupported or duplicated")
        result.append(request)
    return result


class BlueTeamReviewStore:
    """Bounded in-memory immutable proposal and audit-record store."""

    def __init__(self, capacity: int = 250):
        if isinstance(capacity, bool) or not isinstance(capacity, int) or not 1 <= capacity <= 1000:
            raise ValueError("review store capacity must be between 1 and 1000")
        self.capacity = capacity
        self._entries: dict[str, dict] = {}

    def review(
        self,
        proposal: dict,
        *,
        reviewer: str,
        decision: str,
        reason: str,
        modifications: list[dict] | None = None,
        requested_evidence: list[str] | None = None,
        proposal_version: int = 1,
        timestamp: str | None = None,
    ) -> dict:
        proposal_copy = validate_proposal(proposal)
        proposal_digest = hashlib.sha256(_canonical(proposal_copy)).hexdigest()
        reviewer_id = _validate_reviewer(reviewer)
        action = str(decision or "").strip().upper()
        if action not in _ACTIONS:
            raise ValueError("review decision is unsupported")
        review_reason = _bounded_string(reason, "review reason", 2048)
        if isinstance(proposal_version, bool) or proposal_version != 1:
            raise ValueError("Phase 16 accepts proposal_version 1 only")
        modification_records = _validate_modifications(modifications or [])
        evidence_requests = _validate_evidence_requests(requested_evidence or [])
        if action == "MODIFY":
            if not modification_records or evidence_requests:
                raise ValueError("MODIFY requires modifications and no evidence requests")
        elif action == "REQUEST_MORE_EVIDENCE":
            if not evidence_requests or modification_records:
                raise ValueError("REQUEST_MORE_EVIDENCE requires evidence requests only")
        elif modification_records or evidence_requests:
            raise ValueError("this review action cannot contain modifications or evidence requests")

        stable_input = {
            "review_schema_version": REVIEW_SCHEMA_VERSION,
            "proposal_sha256": proposal_digest,
            "proposal_id": proposal_copy["proposal_id"],
            "proposal_version": proposal_version,
            "reviewer": reviewer_id,
            "decision": action,
            "reason": review_reason,
            "modifications": modification_records,
            "requested_evidence": evidence_requests,
        }
        stable_digest = hashlib.sha256(_canonical(stable_input)).hexdigest()
        review_id = "RV-" + stable_digest[:24]
        existing = self._entries.get(proposal_copy["proposal_id"])
        if existing:
            review = existing["reviews"][0]
            if review["review_id"] == review_id:
                return copy.deepcopy(review)
            raise ValueError(
                "proposal is already reviewed; an explicit later review revision is required"
            )
        if len(self._entries) >= self.capacity:
            raise ValueError("bounded review store capacity is reached")

        resulting_status = _ACTIONS[action]
        eligible = action == "APPROVE"
        authority = {
            "deployable": False,
            "strategy_registry_approved": False,
            "requires_phase_17_validation": eligible,
            "validation_started": False,
            "registry_mutation": False,
            "policy_mutation": False,
            "strategy_activation": False,
            "asset_deployment": False,
        }
        review = {
            "review_schema_version": REVIEW_SCHEMA_VERSION,
            "review_id": review_id,
            "proposal_id": proposal_copy["proposal_id"],
            "proposal_version": proposal_version,
            "proposal_sha256": proposal_digest,
            "reviewer": reviewer_id,
            "timestamp": _validate_timestamp(timestamp),
            "decision": action,
            "prior_status": "REQUIRES_REVIEW",
            "resulting_status": resulting_status,
            "reason": review_reason,
            "modifications": modification_records,
            "requested_evidence": evidence_requests,
            "can_proceed_to_validation": eligible,
            "next_phase": "PHASE_17" if eligible else None,
            "authority": authority,
            "validation_handoff": {
                "eligible": eligible,
                "candidate_id": "VC-" + stable_digest[24:48] if eligible else None,
                "phase": "PHASE_17" if eligible else None,
                "validation_started": False,
            },
            "audit": {
                "stable_review_input_sha256": stable_digest,
                "original_proposal_preserved": True,
                "durable_persistence": False,
                "persistence_phase": "PHASE_24",
            },
        }
        self._entries[proposal_copy["proposal_id"]] = {
            "store_version": REVIEW_STORE_VERSION,
            "proposal": proposal_copy,
            "proposal_sha256": proposal_digest,
            "reviews": [copy.deepcopy(review)],
        }
        return copy.deepcopy(review)

    def audit_trail(self, proposal_id: str) -> dict:
        proposal_id = _bounded_string(proposal_id, "proposal_id", 64)
        entry = self._entries.get(proposal_id)
        if entry is None:
            raise ValueError("proposal review was not found")
        return copy.deepcopy(entry)

    def count(self) -> int:
        return len(self._entries)

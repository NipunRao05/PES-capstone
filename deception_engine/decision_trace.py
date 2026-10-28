"""Bounded research record builders; not a selector or persistence authority.

Call begin only at an explicit pre-production decision boundary. Runtime wiring
is intentionally pending; never reconstruct state-before from a finished result.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from uuid import uuid4
from world_commitments import Commitments


def experiment(experiment_id="deterministic_baseline", version=1):
    if experiment_id != "deterministic_baseline" or type(version) is not int or version != 1:
        raise ValueError("Unknown experiment definition")
    return {"experiment_id": experiment_id, "experiment_version": version,
            "mode": "deterministic_rule_based", "active": True}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def begin(registry, strategy_id, *, session_id, protocol, transaction_state,
          exposure_depth, principal_record=None):
    if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id):
        raise ValueError("Invalid trace session identity")
    if protocol not in {"postgres", "mysql"} or transaction_state not in {"idle", "in_transaction", "failed_transaction"}:
        raise ValueError("Invalid trace context")
    if type(exposure_depth) is not int or not 1 <= exposure_depth <= 3:
        raise ValueError("Invalid exposure depth")
    strategy = registry.get(strategy_id)
    if strategy is None or strategy.approval_status != "APPROVED":
        raise ValueError("Trace requires an explicitly selected approved strategy")
    record = principal_record if principal_record is not None else {}
    commitments = Commitments(record)
    semantic = [{k: entry[k] for k in ("namespace", "subject", "property", "value")}
                for entry in commitments.list()]
    evaluated = []
    for fact in strategy.commitment_preconditions:
        observed = commitments.get(fact)
        evaluated.append({"identity": fact.key, "observed": observed["value"] if observed else None,
                          "result": commitments.check(fact)})
    eligible, reason = registry.eligibility(strategy_id, strategy.strategy_version, protocol, record)
    principal_id = record.get("principal_id")
    if principal_id is not None and (not isinstance(principal_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", principal_id)):
        raise ValueError("Invalid principal reference")
    return {"decision_id": str(uuid4()), "timestamp": timestamp(), **experiment(),
        "session_id": session_id, "principal_id": principal_id, "protocol": protocol,
        "strategy_id": strategy.strategy_id, "strategy_version": strategy.strategy_version,
        "strategy_definition_digest": strategy.definition_digest(),
        "expected_action_binding": strategy.action_binding, "approval_status": strategy.approval_status,
        "eligibility": {"eligible": eligible, "reason": reason},
        "reason_code": "REGISTERED_DETERMINISTIC_RULE",
        "state_before": {"transaction_state": transaction_state, "exposure_depth": exposure_depth,
            "commitment_scope": "principal" if principal_record is not None else "unavailable",
            "commitment_set_digest": hashlib.sha256(json.dumps(semantic, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest() if principal_record is not None else None,
            "evaluated_commitments": evaluated}}


def applied(decision, provenance, *, result_mode):
    if result_mode not in {"fake", "block", "passthrough", "delay"}:
        raise ValueError("Invalid result classification")
    if provenance is None:
        actual, verification = None, "NOT_VERIFIED"
    else:
        if provenance.expected != decision["expected_action_binding"]:
            raise ValueError("Decision/provenance expected binding mismatch")
        actual, verification = provenance.actual, provenance.status
    status = "NOT_VERIFIED"
    if actual == "policy_rejection":
        status = "BLOCKED"
    elif actual == "statement_error":
        status = "ERROR"
    elif actual is not None and verification in {"MATCH", "MISMATCH"}:
        status = "APPLIED" if result_mode == "fake" else "NOT_VERIFIED"
    return {"application_id": str(uuid4()), "decision_id": decision["decision_id"],
        "timestamp": timestamp(), "expected_action_binding": decision["expected_action_binding"],
        "actual_action_binding": actual, "provenance_status": verification,
        "application_status": status, "result_class": result_mode}

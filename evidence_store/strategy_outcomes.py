"""Completed-evidence temporal linkage, not causal effectiveness or reward."""
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid5, NAMESPACE_URL
import json

PROFILE_ID = "deterministic_components"
PROFILE_VERSION = 1
HORIZON_SECONDS = 300
EVENT_LIMIT = 100
QUERY_CAP = 20
ERROR_CAP = 10
TRAP_CAP = 5
OUTCOME_FIELDS = {"schema_version", "outcome_id", "decision_id", "application_id", "session_id",
    "principal_id", "strategy_id", "strategy_version", "strategy_definition_digest", "experiment_id",
    "experiment_version", "window_start", "window_end", "termination_reason", "application_status",
    "provenance_status", "effectiveness_eligible", "raw_features", "component_scores",
    "scoring_profile_id", "scoring_profile_version", "completeness", "calibration_status"}


def instant(value):
    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("Outcome timestamps require timezone")
    return value.astimezone(timezone.utc)


def outcome_id(application_id, version=PROFILE_VERSION):
    UUID(application_id)
    return str(uuid5(NAMESPACE_URL, f"strategy-outcome:{application_id}:{PROFILE_ID}:{version}"))


def evaluate(session_id, pairs, events, *, closed_at=None, as_of, query_coverage=False,
             trace_coverage=False):
    """One bounded evidence snapshot. Persisted outputs are immutable.

    request_started_at is required to distinguish follow-up from producing SQL.
    Current retained completion-only query timestamps cannot satisfy that contract.
    """
    if len(pairs) > 128 or len(events) > 1000:
        raise ValueError("Outcome input limit exceeded")
    now = instant(as_of)
    close = instant(closed_at) if closed_at else None
    if close and close > now:
        raise ValueError("Closure is after evidence snapshot")
    unique = {}
    trace_executions = {}
    for pair in pairs:
        d, a = pair["decision"], pair["application"]
        if d["session_id"] != session_id or a["decision_id"] != d["decision_id"]:
            raise ValueError("Invalid outcome trace linkage")
        if instant(d["timestamp"]) > instant(a["timestamp"]):
            raise ValueError("Application precedes decision")
        identity = a["application_id"]
        execution = d.get("query_execution_id")
        if execution:
            previous = trace_executions.setdefault(execution,(d["decision_id"],identity))
            if previous != (d["decision_id"],identity):
                raise ValueError("Multiple applications claim one execution")
        if identity in unique and unique[identity] != pair:
            raise ValueError("Conflicting application evidence")
        unique[identity] = pair
    ordered = sorted(unique.values(), key=lambda p: (instant(p["application"]["timestamp"]), p["application"]["application_id"]))
    dedup = {}
    for event in events:
        if event.get("session_id") != session_id:
            continue
        identity = event.get("event_id")
        if not identity:
            raise ValueError("Outcome evidence requires stable event ID")
        if identity in dedup and dedup[identity] != event:
            raise ValueError("Conflicting duplicate evidence")
        dedup[identity] = event
    executions = {}
    unlinked = []
    for event in dedup.values():
        identity = event.get("query_execution_id")
        if not identity:
            unlinked.append(event)
            continue
        semantic = {k:event.get(k) for k in ("session_id","request_started_at","timestamp","decision_id","application_id","response","is_trap","deception_profile")}
        if identity in executions and executions[identity][0] != semantic:
            raise ValueError("Conflicting execution evidence")
        if identity not in executions or event["event_id"] < executions[identity][1]["event_id"]:
            executions[identity] = (semantic,event)
    dedup = {e["event_id"]:e for e in unlinked+[v[1] for v in executions.values()]}
    application_map = {p["application"]["application_id"]:p for p in ordered}
    for event in dedup.values():
        linked = application_map.get(event.get("application_id"))
        if event.get("application_id") and linked is None:
            trace_coverage = False
        if linked is not None:
            expected = linked["decision"].get("query_execution_id")
            if (expected is not None and expected != event.get("query_execution_id")) or (event.get("decision_id") and event["decision_id"] != linked["decision"]["decision_id"]):
                raise ValueError("Query/application correlation conflict")
    results = []
    for index, pair in enumerate(ordered):
        d, a = pair["decision"], pair["application"]
        producing_query = d.get("query_execution_id")
        start = instant(a["timestamp"])
        end, reason = start + timedelta(seconds=HORIZON_SECONDS), "MAX_DURATION"
        if close is None and now < end:
            continue  # Do not finalize an active, open-ended snapshot.
        if close is not None and close < start:
            continue
        if index + 1 < len(ordered):
            next_pair = ordered[index + 1]
            boundary = instant(next_pair["decision"]["timestamp"])
            if boundary <= end:
                end, reason = max(start, boundary), "NEXT_STRATEGY"
        if close is not None and close <= end:
            end, reason = close, "SESSION_CLOSED"
        queries = [e for e in dedup.values() if e.get("event_type") == "query"
            and (not producing_query or (e.get("query_execution_id") and e["query_execution_id"] != producing_query))
            and e.get("request_started_at") and start < instant(e["request_started_at"]) < end
            and instant(e["timestamp"]) < end]
        queries.sort(key=lambda e: (instant(e["request_started_at"]), e["event_id"]))
        if len(queries) > EVENT_LIMIT:
            end, reason = instant(queries[EVENT_LIMIT]["request_started_at"]), "MAX_EVENTS"
            queries = [e for e in queries if instant(e["timestamp"]) < end][:EVENT_LIMIT]
        verified = [e for e in queries if e.get("response", {}).get("outcome_verified") is True]
        # Partial/unattributed sources must not be represented as observed zero.
        ambiguous = any(e.get("event_type") == "query" and (not e.get("request_started_at") or (producing_query and not e.get("query_execution_id")))
            and start < instant(e["timestamp"]) < end for e in dedup.values())
        observed = query_coverage and trace_coverage and not ambiguous
        errors = sum(e["response"].get("success") is False for e in verified)
        traps = sum(e.get("is_trap") is True and e["response"].get("success") is True and
                    e["response"].get("authority") == "deception" and
                    e.get("deception_profile") in {"fake_table_data", "high_value_target"} for e in verified)
        duration = max(0, (end - start).total_seconds())
        raw = {"followup_queries": len(queries) if observed else None,
            "verified_followup_queries": len(verified) if observed else None,
            "successful_followup_queries": sum(e["response"].get("success") is True for e in verified) if observed else None,
            "verified_errors": errors if observed else None, "verified_trap_interactions": traps if observed else None,
            "window_duration_seconds": duration, "disconnect_observed": reason == "SESSION_CLOSED" if close is not None else None,
            "new_relations": None, "new_query_families": None, "new_commitments": None, "exposure_depth_delta": None}
        scores = {"engagement": min(len(verified) / QUERY_CAP, 1) if observed else None,
            "error_component": min(errors / ERROR_CAP, 1) if observed else None,
            "trap_interaction": min(traps / TRAP_CAP, 1) if observed else None,
            "disconnect_signal": float(reason == "SESSION_CLOSED") if close is not None else None}
        result = {"schema_version": 1, "outcome_id": outcome_id(a["application_id"]),
            **{k: d.get(k) for k in ("decision_id", "session_id", "principal_id", "strategy_id", "strategy_version",
                "strategy_definition_digest", "experiment_id", "experiment_version")},
            "application_id": a["application_id"], "window_start": start.isoformat(), "window_end": end.isoformat(),
            "termination_reason": reason, "application_status": a["application_status"], "provenance_status": a["provenance_status"],
            "effectiveness_eligible": a["application_status"] == "APPLIED" and a["provenance_status"] == "MATCH",
            "raw_features": raw, "component_scores": scores, "scoring_profile_id": PROFILE_ID,
            "scoring_profile_version": PROFILE_VERSION, "calibration_status": "CALIBRATION_REQUIRED",
            "completeness": "COMPLETE" if observed and close is not None and reason not in {"MAX_DURATION", "MAX_EVENTS"} else "PARTIAL"}
        results.append(result)
    return results

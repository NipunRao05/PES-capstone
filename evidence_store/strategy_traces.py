"""Trace-specific Redis records with atomic versioned retained indexing.

No generic artifact claims/indexes participate. Caller retries transport failures
with the original record/UUID, never a rebuilt timestamp or identity.
"""
from research_metadata import metadata as research_metadata
import json
import re
from datetime import datetime
from uuid import UUID
from trace_index import TraceIndex, GROUP_CONTEXT

FIELDS = {
    "decision": {"schema_version", "decision_id", "timestamp", "experiment_id", "experiment_version",
        "mode", "active", "session_id", "principal_id", "protocol", "strategy_id", "strategy_version",
        "strategy_definition_digest", "expected_action_binding", "approval_status", "eligibility", "reason_code", "state_before"},
    "application": {"schema_version", "application_id", "decision_id", "timestamp", "expected_action_binding",
        "actual_action_binding", "provenance_status", "application_status", "result_class"},
}
OPTIONAL_FIELDS = {"decision": {"query_execution_id", "request_started_at", "world_id", "world_version", "traffic_origin", "deployment_manifest_id"}, "application": {"world_id", "world_version", "traffic_origin", "deployment_manifest_id"}, "outcome": {"traffic_origin", "deployment_manifest_id"}}


def world_metadata(record):
    if not record.get("world_id") and "world_version" not in record:
        return {}
    identity, version = record.get("world_id"), record.get("world_version")
    if not isinstance(identity, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", identity) or type(version) is not int or not 1 <= version <= 65535:
        raise ValueError("Invalid world identity")
    return {"world_id": identity, "world_version": version}


def correlation_metadata(record):
    identity, started = record.get("query_execution_id"), record.get("request_started_at")
    if identity is None and started is None:
        return {}
    if not isinstance(identity,str) or len(identity)!=36 or str(UUID(identity))!=identity:
        raise ValueError("Invalid execution identity")
    if not isinstance(started,str) or len(started)>40 or datetime.fromisoformat(started.replace("Z","+00:00")).tzinfo is None:
        raise ValueError("Invalid request start")
    return {"query_execution_id":identity,"request_started_at":started}


def event_correlation(payload):
    try:
        metadata = {**correlation_metadata(payload), **world_metadata(payload), **research_metadata(payload)}
        if not metadata:
            return {}
        for field in ("decision_id","application_id"):
            value=payload.get(field)
            if value:
                if not isinstance(value,str) or len(value)!=36 or str(UUID(value))!=value:
                    raise ValueError("Invalid strategy correlation")
                metadata[field]=value
        return metadata
    except (ValueError,TypeError,AttributeError):
        return {"correlation_status":"INVALID"}
def outcome_schema(kind):
    if kind == "outcome" and kind not in FIELDS:
        from strategy_outcomes import OUTCOME_FIELDS
        FIELDS[kind] = OUTCOME_FIELDS


class TraceConflict(ValueError):
    pass


def validate_ingestion(pair):
    """Validate the bounded HTTP contract, independent of live policy authority."""
    for kind in ("decision", "application"):
        record = pair.get(kind)
        if not isinstance(record, dict) or set(record)-OPTIONAL_FIELDS[kind] != FIELDS[kind]:
            raise ValueError("Invalid trace fields")
        if type(record["schema_version"]) is not int or record["schema_version"] != 1:
            raise ValueError("Invalid trace version")
        if datetime.fromisoformat(record["timestamp"]).tzinfo is None:
            raise ValueError("Invalid timestamp")
        world_metadata(record)
        research_metadata(record)
        TraceStore.key(kind, record[kind + "_id"])
    d, a = pair["decision"], pair["application"]
    if research_metadata(d) != research_metadata(a):
        raise ValueError("Research provenance mismatch")
    if world_metadata(d) != world_metadata(a):
        raise ValueError("World identity mismatch")
    correlation_metadata(d)
    if a["decision_id"] != d["decision_id"] or a["expected_action_binding"] != d["expected_action_binding"]:
        raise ValueError("Invalid trace linkage")
    for field in ("session_id", "principal_id"):
        value = d[field]
        if value is None and field == "principal_id":
            continue
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            raise ValueError("Invalid context identity")
    if d["protocol"] not in {"mysql", "postgres"} or d["approval_status"] != "APPROVED":
        raise ValueError("Invalid selected strategy")
    if not re.fullmatch(r"D[0-9]{1,4}", d["strategy_id"]) or type(d["strategy_version"]) is not int or not 1 <= d["strategy_version"] <= 65535:
        raise ValueError("Invalid strategy identity")
    if not re.fullmatch(r"[0-9a-f]{64}", d["strategy_definition_digest"]):
        raise ValueError("Invalid definition digest")
    if (d["experiment_id"], d["experiment_version"], d["mode"], d["active"]) != ("deterministic_baseline", 1, "deterministic_rule_based", True):
        raise ValueError("Invalid experiment")
    for value in (d["reason_code"], d["expected_action_binding"], a["expected_action_binding"], a["actual_action_binding"]):
        if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,64}", value)):
            raise ValueError("Invalid bounded code")
    if a["provenance_status"] not in {"MATCH", "MISMATCH", "NOT_VERIFIED", "INVALID_ACTION"} or a["application_status"] not in {"APPLIED", "BLOCKED", "ERROR", "NOT_VERIFIED"} or a["result_class"] not in {"fake", "block", "passthrough", "delay"}:
        raise ValueError("Invalid application classification")
    eligibility = d["eligibility"]
    if not isinstance(eligibility, dict) or set(eligibility) != {"eligible", "reason"} or eligibility["eligible"] is not True or not re.fullmatch(r"[A-Z_]{1,64}", eligibility["reason"]):
        raise ValueError("Invalid eligibility")
    state = d["state_before"]
    if not isinstance(state, dict) or set(state) != {"transaction_state", "exposure_depth", "commitment_scope", "commitment_set_digest", "evaluated_commitments"}:
        raise ValueError("Invalid state snapshot")
    if state["transaction_state"] not in {"idle", "in_transaction", "failed_transaction"} or type(state["exposure_depth"]) is not int or not 1 <= state["exposure_depth"] <= 3 or state["commitment_scope"] not in {"principal", "unavailable"}:
        raise ValueError("Invalid state features")
    digest = state["commitment_set_digest"]
    if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid commitment digest")
    facts = state["evaluated_commitments"]
    if not isinstance(facts, list) or len(facts) > 16:
        raise ValueError("Invalid evaluated commitments")
    for fact in facts:
        if not isinstance(fact, dict) or set(fact) != {"identity", "observed", "result"} or not re.fullmatch(r"relation\|[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}\|(exists|kind)", fact["identity"]) or fact["result"] not in {"unobserved", "unchanged", "conflict"}:
            raise ValueError("Invalid evaluated fact")
        value = fact["observed"]
        if value is not None and type(value) is not bool and value not in ("table", "view"):
            raise ValueError("Invalid observed value")


class TraceStore:
    def __init__(self, client, ttl_seconds):
        if type(ttl_seconds) is not int or ttl_seconds <= 0:
            raise ValueError("Invalid trace retention")
        self.client, self.ttl = client, ttl_seconds

    @staticmethod
    def key(kind, identity):
        outcome_schema(kind)
        if kind not in FIELDS or str(UUID(identity)) != identity:
            raise ValueError("Invalid trace identity")
        return "evidence:strategy_trace:" + kind + ":" + identity

    def get(self, kind, identity):
        raw = self.client.get(self.key(kind, identity))
        return json.loads(raw) if raw is not None else None

    def activate_index(self):
        return TraceIndex(self.client).activate()

    def list_records(self, kind, **kwargs):
        if kind not in {"decision", "application", "outcome"}:
            raise ValueError("Invalid indexed record kind")
        return TraceIndex(self.client).read(kind, **kwargs)

    def indexed_snapshot(self, **kwargs):
        from trace_index import REPORT_LIMIT
        snapshot = TraceIndex(self.client).read("all", limit=REPORT_LIMIT, **kwargs)
        if any(not group["done"] for group in snapshot["kinds"].values()):
            raise ValueError("REPORT_LIMIT_EXCEEDED_USE_PAGINATED_EXPORT")
        return snapshot

    def store(self, kind, record):
        outcome_schema(kind)
        if kind not in FIELDS or not isinstance(record, dict) or set(record)-OPTIONAL_FIELDS[kind] != FIELDS[kind] or record.get("schema_version") != 1:
            raise ValueError("Invalid trace schema")
        if kind in {"decision", "application"}:
            world_metadata(record)
        research_metadata(record)
        if kind == "decision":
            correlation_metadata(record)
        identity = record[kind + "_id"]
        key = self.key(kind, identity)
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode()) > 16384:
            raise ValueError("Trace size exceeded")
        # Preserve identity conflicts even after referenced records have expired.
        # Lua repeats this comparison atomically before changing any membership.
        existing = self.client.get(key)
        if isinstance(existing, bytes):
            existing = existing.decode()
        if existing is not None and existing != encoded:
            raise TraceConflict("Trace identity reused with different content")
        context = {k: record[k] for k in GROUP_CONTEXT} if kind in {"decision", "outcome"} else None
        if context is not None:
            context.update({k:record[k] for k in ("traffic_origin","deployment_manifest_id") if k in record})
        if kind == "application":
            decision = self.get("decision", record["decision_id"])
            if decision is None:
                if self.get(kind, identity) != record:
                    raise ValueError("Decision missing; retry after decision delivery")
            elif research_metadata(decision) != research_metadata(record):
                raise TraceConflict("Application research provenance differs")
            elif world_metadata(decision) != world_metadata(record):
                raise TraceConflict("Application world differs")
            elif decision["expected_action_binding"] != record["expected_action_binding"]:
                raise TraceConflict("Application decision binding differs")
            else:
                context = {k: decision[k] for k in GROUP_CONTEXT}
                context.update({k:decision[k] for k in ("traffic_origin","deployment_manifest_id") if k in decision})
        if kind == "outcome":
            decision = self.get("decision", record["decision_id"])
            application = self.get("application", record["application_id"])
            if decision is None or application is None:
                if self.get(kind, identity) != record:
                    raise ValueError("Outcome requires retained decision/application")
            elif research_metadata(record) != research_metadata(decision) or research_metadata(record) != research_metadata(application):
                raise TraceConflict("Outcome research provenance differs")
            elif application["decision_id"] != decision["decision_id"] or any(record[k] != decision[k]
                for k in ("session_id", "strategy_id", "strategy_version", "strategy_definition_digest", "experiment_id", "experiment_version")):
                raise TraceConflict("Outcome linkage mismatch")
        result = TraceIndex(self.client).write(kind, identity, encoded, self.ttl, context, key)
        if result == "CONFLICT":
            raise TraceConflict("Trace identity reused with different content")
        return result.lower()

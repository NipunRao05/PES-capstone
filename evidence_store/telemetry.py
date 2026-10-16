
"""Bounded, process-lifetime telemetry for accepted evidence, never raw SQL labels."""
from prometheus_client import Counter, Histogram

INGEST = Counter("honeypot_evidence_ingest_total", "Kafka evidence processing attempts", ("result",))
LATENCY = Histogram("honeypot_evidence_ingest_seconds", "Kafka evidence processing time", buckets=(.001,.005,.01,.025,.05,.1,.25,.5,1,2,5))
QUERIES = Counter("honeypot_query_outcomes_total", "New query evidence records accepted by this process", ("protocol","authority","verified","success"))
AUTH = Counter("honeypot_authentication_total", "New authentication evidence records accepted by this process", ("protocol","success"))
TRAPS = Counter("honeypot_trap_interactions_total", "New verified successful query evidence marked as trap", ("protocol",))
LINKS = Counter("honeypot_session_links_total", "New session-link evidence records accepted by this process")
PRINCIPALS = Counter("honeypot_principal_evidence_total", "New principal evidence records", ("event",))
PROFILES = Counter("honeypot_behavior_profiles_total", "New behavior profile evidence records")
REUSE = Histogram("honeypot_first_reuse_seconds", "Time to first principal reuse from explicit first-return evidence", buckets=(1,5,30,60,300,900,3600,86400,604800))


def protocol(payload, topic):
    return "mysql" if topic.startswith("mysql-") else "postgres" if topic.startswith("pg-") else "unknown"


def query(payload, topic):
    proto = protocol(payload, topic)
    authority = payload.get("authority")
    if not isinstance(authority, str) or authority not in {"backend", "deception", "policy"}:
        authority = "unknown"
    verified = payload.get("outcome_verified") is True
    success = str(payload["success"]).lower() if verified and type(payload.get("success")) is bool else "unknown"
    QUERIES.labels(proto, authority, str(verified).lower(), success).inc()
    if verified and success == "true" and payload.get("is_trap") is True:
        TRAPS.labels(proto).inc()


def session(payload, topic):
    import math
    kind = payload.get("event_type")
    if not isinstance(kind, str):
        kind = "unknown"
    if topic == "session-profiles":
        PROFILES.inc()
    if kind == "auth" and type(payload.get("success")) is bool:
        AUTH.labels(protocol(payload, topic), str(payload["success"]).lower()).inc()
    if kind == "session_link":
        LINKS.inc()
    if kind == "deceptive_principal_authenticated":
        value = payload.get("time_to_first_reuse_seconds")
        if payload.get("return_session_number") == 1 and type(value) in (int,float) and math.isfinite(value) and value >= 0:
            REUSE.observe(value)
    if kind in {"deceptive_principal_created", "deceptive_principal_authenticated"}:
        PRINCIPALS.labels(kind).inc()

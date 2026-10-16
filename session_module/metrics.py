from prometheus_client import Counter, Gauge, Histogram

# =========================
# Event metrics
# =========================

events_processed_total = Counter(
    "events_processed_total",
    "Total events processed by session engine"
)

events_dropped_total = Counter(
    "events_dropped_total",
    "Total events dropped before session processing",
    ["reason"]
)

events_failed_total = Counter(
    "events_failed_total",
    "Total events that failed during session processing",
    ["stage"]
)

# =========================
# Session lifecycle
# =========================

active_sessions = Gauge(
    "active_sessions",
    "Number of currently active sessions"
)

sessions_closed_total = Counter(
    "sessions_closed_total",
    "Total sessions closed"
)

# =========================
# Behavioral metrics
# =========================

session_entropy = Gauge(
    "session_entropy",
    "Entropy of last closed session"
)

session_depth_score = Gauge(
    "session_depth_score",
    "Depth score of last closed session"
)

# =========================
# Clustering metrics
# =========================

cluster_sessions_total = Counter(
    "cluster_sessions_total",
    "Number of sessions assigned to clusters",
    ["classification"]
)
# Process-local aggregates; session IDs and cluster IDs do not become labels.
session_duration_seconds = Histogram("honeypot_session_duration_seconds", "Closed-session active duration", buckets=(1,5,15,30,60,120,300,900,3600))
session_queries = Histogram("honeypot_session_queries", "Queries per closed session", buckets=(0,1,2,5,10,20,50,100,500,1000))
session_depth = Histogram("honeypot_session_depth", "Depth score per closed session", buckets=(0,.1,.25,.5,.75,1,2,5,10,50))
pipeline_seconds = Histogram("honeypot_session_pipeline_seconds", "Session engine processing time", buckets=(.001,.005,.01,.025,.05,.1,.25,.5,1,2,5))
event_backlog = Gauge("honeypot_session_queue_depth", "Events currently waiting in the real session queue")
publish_results = Counter("honeypot_session_publish_total", "Kafka publish attempts by result", ("result",))

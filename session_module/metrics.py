from prometheus_client import Counter, Gauge

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
    ["cluster_id"]
)
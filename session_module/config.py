"""
config.py
---------
All settings driven by environment variables with sane defaults.
In Docker, these are set via the 'environment:' block in docker-compose.yml.
Locally, you can export them or just rely on the defaults.
"""

import os

# ------------------------------------------------------------------
# Session engine
# ------------------------------------------------------------------
SESSION_TIMEOUT         = int(os.getenv("SESSION_TIMEOUT", 10))
MAX_ACTIVE_SESSIONS     = int(os.getenv("MAX_ACTIVE_SESSIONS", 1000))
CLEANUP_INTERVAL        = int(os.getenv("CLEANUP_INTERVAL", 30))
EVENT_QUEUE_MAX_SIZE    = int(os.getenv("EVENT_QUEUE_MAX_SIZE", 10000))

# ------------------------------------------------------------------
# Clustering
# ------------------------------------------------------------------
CLUSTER_INTERVAL_SECONDS = int(os.getenv("CLUSTER_INTERVAL_SECONDS", 20))
CLUSTER_BATCH_SIZE       = int(os.getenv("CLUSTER_BATCH_SIZE", 100))
DBSCAN_EPS               = float(os.getenv("DBSCAN_EPS", 1.2))
DBSCAN_MIN_SAMPLES       = int(os.getenv("DBSCAN_MIN_SAMPLES", 3))

# ------------------------------------------------------------------
# INPUT: Teammates' Redpanda instances
# (consume proxy events FROM these)
#
# From host:  mysql Redpanda = localhost:9093
#             pg    Redpanda = localhost:9092
# From Docker network (service name):
#             mysql = redpanda:9092 on mysqlproxy_default network
#             pg    = redpanda:9092 on pgproxy_default network
# ------------------------------------------------------------------
MYSQL_REDPANDA_BOOTSTRAP = os.getenv("MYSQL_REDPANDA_BOOTSTRAP", "localhost:9093")
PG_REDPANDA_BOOTSTRAP    = os.getenv("PG_REDPANDA_BOOTSTRAP",    "localhost:9092")

TOPIC_MYSQL_INPUT        = os.getenv("TOPIC_MYSQL_INPUT", "mysql-query-events")
TOPIC_PG_INPUT           = os.getenv("TOPIC_PG_INPUT",    "pg-query-events")
TOPIC_MYSQL_SESSION      = os.getenv("TOPIC_MYSQL_SESSION", "mysql-session-events")
TOPIC_PG_SESSION         = os.getenv("TOPIC_PG_SESSION",    "pg-session-events")
TOPIC_MITRE_EVENTS       = os.getenv("TOPIC_MITRE_EVENTS",  "mitre-events")
# MITRE integration temporarily disabled; source retained.
MITRE_ENABLED = os.getenv("MITRE_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}

CONSUMER_GROUP           = os.getenv("CONSUMER_GROUP", "session-module-group")
CONSUMER_AUTO_OFFSET_RESET = os.getenv("CONSUMER_AUTO_OFFSET_RESET", "latest")

# ------------------------------------------------------------------
# OUTPUT: Your own Redpanda instance
# (publish processed results TO this)
#
# From host:  localhost:9094
# From inside your Docker network: redpanda:9092
# ------------------------------------------------------------------
OWN_REDPANDA_BOOTSTRAP   = os.getenv("OWN_REDPANDA_BOOTSTRAP", "localhost:9094")

TOPIC_SESSION_CLOSED     = os.getenv("TOPIC_SESSION_CLOSED",   "session-closed-events")
TOPIC_SESSION_PROFILES   = os.getenv("TOPIC_SESSION_PROFILES", "session-profiles")
TOPIC_DEAD_LETTER        = os.getenv("TOPIC_DEAD_LETTER",      "dead-letter-events")
DEAD_LETTER_MAX_RAW_BYTES = int(os.getenv("DEAD_LETTER_MAX_RAW_BYTES", "16384"))

# ------------------------------------------------------------------
# Prometheus
# ------------------------------------------------------------------
METRICS_PORT             = int(os.getenv("METRICS_PORT", 8000))
STATE_API_HOST           = os.getenv("STATE_API_HOST", "0.0.0.0")
STATE_API_PORT           = int(os.getenv("STATE_API_PORT", 8003))
STATE_MAX_SESSIONS       = int(os.getenv("STATE_MAX_SESSIONS", 5000))
ADAPTATION_ENDPOINT      = os.getenv("ADAPTATION_ENDPOINT", "http://deception-engine:8001/strategy/next")
ADAPTATION_OPERATOR_MODE = os.getenv("ADAPTATION_OPERATOR_MODE", "RULE_ADAPTIVE")
ADAPTATION_TIMEOUT_SECONDS = float(os.getenv("ADAPTATION_TIMEOUT_SECONDS", "0.5"))
ADAPTATION_QUEUE_SIZE    = int(os.getenv("ADAPTATION_QUEUE_SIZE", "2048"))
LEARNED_SELECTION_MIN_CONFIDENCE = float(
    os.getenv("LEARNED_SELECTION_MIN_CONFIDENCE", "0.75")
)
LEARNED_SELECTION_MIN_UPDATES = int(
    os.getenv("LEARNED_SELECTION_MIN_UPDATES", "20")
)

# ------------------------------------------------------------------
# Dynamic Phase D1 experiment assignment and control persistence
# ------------------------------------------------------------------
EXPERIMENT_REDIS_HOST = os.getenv("EXPERIMENT_REDIS_HOST", "redis-mitre")
EXPERIMENT_REDIS_PORT = int(os.getenv("EXPERIMENT_REDIS_PORT", "6379"))
EXPERIMENT_REDIS_DB = int(os.getenv("EXPERIMENT_REDIS_DB", "0"))
EXPERIMENT_REDIS_PASSWORD = os.getenv("EXPERIMENT_REDIS_PASSWORD", "")
EXPERIMENT_REDIS_KEY_PREFIX = os.getenv(
    "EXPERIMENT_REDIS_KEY_PREFIX", "capstone:dynamic-experiment:v1"
)
EXPERIMENT_REDIS_TIMEOUT_SECONDS = float(
    os.getenv("EXPERIMENT_REDIS_TIMEOUT_SECONDS", "1.0")
)
EXPERIMENT_PERSISTENCE_REQUIRED = os.getenv(
    "EXPERIMENT_PERSISTENCE_REQUIRED", "true"
).strip().lower() in {"1", "true", "yes", "on"}
# In local development an unexported key is generated once and kept in the
# private Redis volume. Production can inject a Secret Manager value here.
EXPERIMENT_ASSIGNMENT_SECRET = os.getenv("EXPERIMENT_ASSIGNMENT_SECRET", "")
EXPERIMENT_MAX_PROCESSED_EVENTS = int(
    os.getenv("EXPERIMENT_MAX_PROCESSED_EVENTS", "10000")
)

# Kafka producer ack wait for low-volume session/profile outputs.
PRODUCER_ACK_TIMEOUT_SECONDS = float(os.getenv("PRODUCER_ACK_TIMEOUT_SECONDS", "10"))

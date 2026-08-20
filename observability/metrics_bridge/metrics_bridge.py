"""
metrics_bridge.py — Prometheus metrics bridge for the capstone platform.

Scrapes the JSON /metrics endpoints from all services and re-exposes
them in Prometheus text format so Grafana can use a single Prometheus
datasource for all dashboards.

Scraped sources:
  - pgproxy:9090/metrics        (PostgreSQL proxy)
  - mysqlproxy:9091/metrics     (MySQL proxy)
  - scaling-agent:9092/metrics  (Scaling agent — also has /metrics/raw native)

Also exposes mitre-events and session data from Redis (mitre-agent writes there).
"""

import json
import logging
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import redis
import requests

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

PGPROXY_URL      = os.environ.get("PGPROXY_METRICS_URL",      "http://pgproxy:9090/metrics")
MYSQLPROXY_URL   = os.environ.get("MYSQLPROXY_METRICS_URL",   "http://mysqlproxy:9091/metrics")
SCALING_URL      = os.environ.get("SCALING_METRICS_URL",      "http://scaling-agent:8080/metrics")
SCALING_RAW_URL  = os.environ.get("SCALING_RAW_URL",          "http://scaling-agent:8080/metrics/raw")
SCALING_EVENTS_URL = os.environ.get("SCALING_EVENTS_URL",     "http://scaling-agent:8080/scale/events")

REDIS_HOST       = os.environ.get("REDIS_HOST",  "redis-mitre")
REDIS_PORT       = int(os.environ.get("REDIS_PORT", "6379"))
HTTP_PORT        = int(os.environ.get("PORT", "9100"))
SCRAPE_TIMEOUT   = float(os.environ.get("SCRAPE_TIMEOUT", "1.0"))

# ── Redis client ──────────────────────────────────────────────────────────────

try:
    _redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                         decode_responses=True, socket_timeout=2)
except Exception:
    _redis = None


# ── Scrape helpers ────────────────────────────────────────────────────────────

def _get_json(url: str) -> dict:
    try:
        r = requests.get(url, timeout=SCRAPE_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.debug("scrape failed %s: %s", url, e)
        return {}


def _get_text(url: str) -> str:
    try:
        r = requests.get(url, timeout=SCRAPE_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.debug("scrape failed %s: %s", url, e)
        return ""


# ── Prometheus text builder ───────────────────────────────────────────────────

class PrometheusWriter:
    def __init__(self):
        self._lines: list[str] = []
        self._declared: set[str] = set()

    def _declare(self, name: str, metric_type: str, help_text: str = ""):
        if name in self._declared:
            return
        if help_text:
            self._lines.append(f"# HELP {name} {help_text}")
        self._lines.append(f"# TYPE {name} {metric_type}")
        self._declared.add(name)

    def gauge(self, name: str, value, labels: dict = None, help_text: str = ""):
        self._declare(name, "gauge", help_text)
        label_str = self._label_str(labels)
        self._lines.append(f"{name}{label_str} {value}")

    def counter(self, name: str, value, labels: dict = None, help_text: str = ""):
        self._declare(name, "counter", help_text)
        label_str = self._label_str(labels)
        self._lines.append(f"{name}{label_str} {value}")

    def _escape_label_value(self, value) -> str:
        # Prometheus label values must escape backslash, double quote, and
        # newlines. Raw control characters can make the entire scrape invalid.
        return (str(value)
                .replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace('"', '\\"'))

    def _label_str(self, labels: dict) -> str:
        if not labels:
            return ""
        pairs = ",".join(f'{k}="{self._escape_label_value(v)}"' for k, v in labels.items())
        return "{" + pairs + "}"

    def render(self) -> str:
        return "\n".join(self._lines) + "\n"


# ── Scrape functions ──────────────────────────────────────────────────────────

def scrape_pgproxy(pw: PrometheusWriter):
    data = _get_json(PGPROXY_URL)
    pw.gauge("capstone_bridge_scrape_success", 1 if data else 0, labels={"service": "pgproxy"}, help_text="1 if bridge scrape succeeded")
    if not data:
        return
    prefix = "capstone_pgproxy"
    pw.gauge(f"{prefix}_active_connections",   data.get("active_connections", 0),
             help_text="Active PG proxy connections")
    pw.counter(f"{prefix}_total_connections",  data.get("total_connections", 0),
               help_text="Total PG proxy connections")
    pw.counter(f"{prefix}_rejected_connections", data.get("rejected_connections", 0))
    pw.counter(f"{prefix}_backend_dial_errors",  data.get("backend_dial_errors", 0))
    pw.counter(f"{prefix}_cancel_requests",      data.get("cancel_requests", 0))
    pw.gauge(f"{prefix}_backend_healthy",
             1 if data.get("backend_healthy") else 0,
             help_text="1 if PG backend is reachable")


def scrape_mysqlproxy(pw: PrometheusWriter):
    data = _get_json(MYSQLPROXY_URL)
    pw.gauge("capstone_bridge_scrape_success", 1 if data else 0, labels={"service": "mysqlproxy"}, help_text="1 if bridge scrape succeeded")
    if not data:
        return
    prefix = "capstone_mysqlproxy"
    pw.gauge(f"{prefix}_active_connections",   data.get("active_connections", 0),
             help_text="Active MySQL proxy connections")
    pw.counter(f"{prefix}_total_connections",  data.get("total_connections", 0),
               help_text="Total MySQL proxy connections")
    pw.counter(f"{prefix}_rejected_connections", data.get("rejected_connections", 0))
    pw.counter(f"{prefix}_backend_dial_errors",  data.get("backend_dial_errors", 0))
    pw.counter(f"{prefix}_kill_requests",        data.get("kill_requests", 0))
    pw.gauge(f"{prefix}_backend_healthy",
             1 if data.get("backend_healthy") else 0,
             help_text="1 if MySQL backend is reachable")


def scrape_scaling_agent(pw: PrometheusWriter) -> dict:
    data = _get_json(SCALING_URL)
    pw.gauge("capstone_bridge_scrape_success", 1 if data else 0, labels={"service": "scaling-agent"}, help_text="1 if bridge scrape succeeded")
    if not data:
        return {}
    prefix = "capstone_scaling"
    pw.gauge(f"{prefix}_current_replicas",   data.get("current_replicas", 0),
             help_text="Current honeypot replica target")
    pw.gauge(f"{prefix}_scale_pressure",     data.get("scale_pressure", 0),
             help_text="Normalized pressure metric for KEDA metrics-api")
    pw.counter(f"{prefix}_total_signals",    data.get("total_signals", 0),
               help_text="Total scaling signals processed")
    pw.counter(f"{prefix}_noise_signals",    data.get("noise_signals", 0),
               help_text="Bot-flood sessions suppressed")
    pw.counter(f"{prefix}_scale_up_events",  data.get("scale_up_events", 0),
               help_text="Total scale-up decisions")
    pw.counter(f"{prefix}_scale_down_events", data.get("scale_down_events", 0),
               help_text="Total scale-down decisions")
    pw.counter(f"{prefix}_trap_triggers",    data.get("trap_triggers", 0),
               help_text="Deprecated alias for the canonical MITRE trap-trigger counter")
    pw.counter("capstone_mitre_trap_triggers_total", data.get("trap_triggers", 0),
               help_text="Canonical persisted trap-trigger count from scaling-agent")
    pw.counter(f"{prefix}_duplicate_events_total", data.get("duplicate_events", 0),
               help_text="Duplicate or replayed Kafka events ignored")
    pw.gauge(f"{prefix}_processed_event_ids", data.get("processed_event_count", 0),
             help_text="Durable event IDs retained for duplicate detection")
    pw.gauge(f"{prefix}_scorer_mean",        data.get("scorer_mean", 0),
             help_text="Global mean of EWMA-smoothed scale scores")
    pw.gauge(f"{prefix}_scorer_std_dev",     data.get("scorer_std_dev", 0),
             help_text="Global std dev of scale scores (Z-score base)")
    pw.counter(f"{prefix}_scorer_count",     data.get("scorer_count", 0),
               help_text="Total samples in rolling statistics")
    return data


def scrape_scaling_events(pw: PrometheusWriter):
    """Expose per-session scaling event details as labelled metrics."""
    data = _get_json(SCALING_EVENTS_URL)
    if not data or not data.get("events"):
        return
    events = data["events"]
    # Latest event per unique session
    seen = {}
    for ev in events:
        sid = ev.get("session_id", "")[:8]
        seen[sid] = ev

    for sid, ev in seen.items():
        labels = {"session_id": sid}
        pw.gauge("capstone_session_raw_score",
                 ev.get("raw_score", 0), labels=labels,
                 help_text="Raw scale_score for session")
        pw.gauge("capstone_session_smoothed_score",
                 ev.get("smoothed_score", 0), labels=labels,
                 help_text="EWMA-smoothed scale_score for session")
        pw.gauge("capstone_session_replica_target",
                 ev.get("replica_target", 0), labels=labels,
                 help_text="Replica target suggested by this session")
        pw.gauge("capstone_session_z_score",
                 ev.get("z_score", 0), labels=labels,
                 help_text="Z-score anomaly signal for session")
        pw.gauge("capstone_session_is_noise",
                 1 if ev.get("is_noise") else 0, labels=labels,
                 help_text="1 if session was suppressed as bot flood")


def scrape_redis_mitre(pw: PrometheusWriter):
    """Read actor profile summaries from Redis.

    The MITRE agent writes actor:{ip} records after mitre-sessions. This
    aggregation gives Grafana real persona/technique distributions instead of
    only service-health counters. Keep the scan bounded so Prometheus scrapes
    stay predictable during demos.
    """
    if not _redis:
        pw.gauge("capstone_bridge_scrape_success", 0, labels={"service": "redis-mitre"}, help_text="1 if bridge scrape succeeded")
        return
    try:
        keys = list(_redis.scan_iter("actor:*", count=200))[:500]
        pw.gauge("capstone_bridge_scrape_success", 1, labels={"service": "redis-mitre"}, help_text="1 if bridge scrape succeeded")
        pw.gauge("capstone_mitre_actor_count", len(keys),
                 help_text="Number of unique attacker IPs tracked in Redis")

        total_risk = 0.0
        parsed_actors = 0
        total_sessions = 0
        known_attackers = 0
        trap_triggers = 0
        persona_counts: dict[str, int] = {}
        technique_counts: dict[str, int] = {}
        phase_counts: dict[str, int] = {}
        parse_errors = 0

        for key in keys:
            try:
                raw = _redis.get(key)
                if not raw:
                    continue
                profile = json.loads(raw)
                parsed_actors += 1
                total_risk += float(profile.get("cumulative_risk", 0))
                total_sessions += int(profile.get("session_count", 0))
                trap_triggers += int(profile.get("trap_triggers", 0))
                if profile.get("is_known_attacker"):
                    known_attackers += 1

                for persona in profile.get("personas_seen", []) or []:
                    persona = str(persona or "unknown")
                    persona_counts[persona] = persona_counts.get(persona, 0) + 1
                for technique in profile.get("techniques_seen", []) or []:
                    technique = str(technique or "unknown")
                    technique_counts[technique] = technique_counts.get(technique, 0) + 1
                for phase in profile.get("phase_history", []) or []:
                    phase = str(phase or "unknown")
                    phase_counts[phase] = phase_counts.get(phase, 0) + 1
            except Exception:
                parse_errors += 1
                continue

        if parsed_actors:
            pw.gauge("capstone_mitre_avg_actor_risk",
                     total_risk / parsed_actors,
                     help_text="Average cumulative risk score across successfully parsed actor profiles")
        pw.gauge("capstone_mitre_parsed_actor_count", parsed_actors,
                 help_text="Number of actor profiles successfully parsed from Redis")
        pw.gauge("capstone_mitre_actor_parse_errors", parse_errors,
                 help_text="Number of Redis actor profiles that could not be parsed")
        pw.gauge("capstone_mitre_total_actor_sessions", total_sessions,
                 help_text="Total sessions accumulated across tracked actors")
        pw.gauge("capstone_mitre_known_attacker_count", known_attackers,
                 help_text="Actors whose cumulative risk crossed the known-attacker threshold")
        pw.gauge("capstone_mitre_actor_profile_trap_triggers", trap_triggers,
                 help_text="Diagnostic trap-trigger sum from current Redis actor profiles")

        for persona, count in sorted(persona_counts.items()):
            pw.gauge("capstone_persona_actor_count", count, labels={"persona": persona},
                     help_text="Number of actors that have exhibited each persona")
        for technique, count in sorted(technique_counts.items()):
            pw.gauge("capstone_mitre_technique_actor_count", count, labels={"technique_id": technique},
                     help_text="Number of actors that have matched each MITRE technique")
        for phase, count in sorted(phase_counts.items()):
            pw.gauge("capstone_attack_phase_observations", count, labels={"phase": phase},
                     help_text="Observed attack-phase entries accumulated in actor profiles")
    except Exception as e:
        pw.gauge("capstone_bridge_scrape_success", 0, labels={"service": "redis-mitre"}, help_text="1 if bridge scrape succeeded")
        log.debug("redis scrape failed: %s", e)


# ── HTTP handler ──────────────────────────────────────────────────────────────

class MetricsHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence per-request access logs

    def do_GET(self):
        if self.path in ("/metrics", "/metrics/"):
            self._serve_metrics()
        elif self.path in ("/health", "/healthz", "/readyz"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","ready":true}')
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_metrics(self):
        pw = PrometheusWriter()

        # Always include the native Prometheus output from scaling agent first
        native = _get_text(SCALING_RAW_URL)

        # Then add bridge metrics
        scrape_pgproxy(pw)
        scrape_mysqlproxy(pw)
        scrape_scaling_agent(pw)
        scrape_scaling_events(pw)
        scrape_redis_mitre(pw)

        # Scrape timestamp
        pw.gauge("capstone_bridge_last_scrape_timestamp",
                 int(time.time()),
                 help_text="Unix timestamp of last bridge scrape")

        body = (native + "\n" + pw.render()).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("metrics bridge starting on port %d", HTTP_PORT)
    log.info("scraping: pgproxy=%s mysqlproxy=%s scaling=%s",
             PGPROXY_URL, MYSQLPROXY_URL, SCALING_URL)

    server = HTTPServer(("0.0.0.0", HTTP_PORT), MetricsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("metrics bridge stopped")

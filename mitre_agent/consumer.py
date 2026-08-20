"""
consumer.py — MITRE Intelligence Agent main consumer.

Consumes query events from mysql-query-events, pg-query-events, and
session-profiles (from the session module). Orchestrates the rule engine,
HMM scorer, attack graph builder, and actor tracker.

Data flow:
  query-events → rule_engine.evaluate() → MitreEvent → mitre-events
  session-profiles → hmm_scorer.score_sequence() + attack_graph.build()
                   → MitreSession → mitre-sessions
                   → actor_tracker.update_from_session()

Architecture principle: this service never calls the proxy or deception engine
directly. It only publishes to Redpanda topics. The proxy shaper reads
mitre-events to get deception_level decisions.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import defaultdict
import math
import re
from datetime import datetime, timezone

import redis
from kafka import KafkaConsumer
from kafka.errors import KafkaError

from actor_tracker import ActorTracker
from attack_graph import AttackGraphBuilder, build_session_graph
from hmm_scorer import HMMScorer
from models import (
    ActorProfile,
    EvalContext,
    MitreEvent,
    MitreSession,
    QueryEvent,
    SessionProfile,
    TechniqueMatch,
    make_mitre_event_id,
)
from rule_engine import RuleEngine
from storage import MitreStore

log = logging.getLogger(__name__)

# ─── Environment config ───────────────────────────────────────────────────────

MYSQL_BROKERS  = os.environ.get("MYSQL_KAFKA_BROKERS", "localhost:9093").split(",")
PG_BROKERS     = os.environ.get("PG_KAFKA_BROKERS",    "localhost:9092").split(",")
MITRE_BROKERS  = os.environ.get("MITRE_KAFKA_BROKERS", "localhost:9094").split(",")
SESSION_BROKERS = os.environ.get("SESSION_KAFKA_BROKERS", os.environ.get("PG_KAFKA_BROKERS", "localhost:9092")).split(",")
REDIS_HOST     = os.environ.get("REDIS_HOST",  "localhost")
REDIS_PORT     = int(os.environ.get("REDIS_PORT", "6379"))

TOPIC_MYSQL_QUERIES    = os.environ.get("TOPIC_MYSQL_QUERIES", "mysql-query-events")
TOPIC_PG_QUERIES       = os.environ.get("TOPIC_PG_QUERIES", "pg-query-events")
TOPIC_MYSQL_SESSION    = os.environ.get("TOPIC_MYSQL_SESSION", "mysql-session-events")
TOPIC_PG_SESSION       = os.environ.get("TOPIC_PG_SESSION", "pg-session-events")
TOPIC_SESSION_PROFILES = os.environ.get("TOPIC_SESSION_PROFILES", "session-profiles")

GROUP_ID = os.environ.get("CONSUMER_GROUP", "mitre-agent")
CONSUMER_AUTO_OFFSET_RESET = os.environ.get("CONSUMER_AUTO_OFFSET_RESET", "latest")
HEALTH_ADDR = os.environ.get("HEALTH_ADDR", "0.0.0.0:8002")
AUTH_FAIL_WINDOW_SECONDS = float(os.environ.get("AUTH_FAIL_WINDOW_SECONDS", "60"))
AUTH_FAIL_THRESHOLD = int(os.environ.get("AUTH_FAIL_THRESHOLD", "3"))
DEAD_LETTER_MAX_RAW_BYTES = int(os.environ.get("DEAD_LETTER_MAX_RAW_BYTES", "16384"))


# ─── Per-session in-memory state ─────────────────────────────────────────────

class SessionState:
    """Tracks accumulated state for one active session."""

    def __init__(self, session_id: str, client_ip: str, username: str, protocol: str = "", database: str = "", first_seen: float | None = None):
        self.session_id    = session_id
        self.client_ip     = client_ip
        self.username      = username
        self.protocol      = protocol
        self.database      = database
        self.risk_score    = 0.0
        self.query_count   = 0
        self.failed_auth   = 0
        self.depth_score   = 0
        self.entropy       = 0.0
        self.timing_var    = 0.0
        self.qps           = 0.0
        self.suspicion     = 0
        self.attack_path   : list[str] = []
        self.phases_seen   : list[str] = []      # for HMM
        self.fingerprint_counts: dict[str, int] = defaultdict(int)
        self.event_timestamps: list[float] = []
        self.technique_matches: list[TechniqueMatch] = []
        self.graph_builder = AttackGraphBuilder()
        self.trap_tables   : list[str] = []
        self.first_seen    = first_seen if first_seen is not None else time.time()
        self.persona       = "unknown"


# ─── Main agent ───────────────────────────────────────────────────────────────

class MitreAgent:
    """
    Orchestrates the MITRE intelligence pipeline.
    Spawns consumer threads for each Redpanda source.
    """

    def __init__(self):
        # Core components
        self.rule_engine   = RuleEngine()
        self.hmm_scorer    = HMMScorer()
        self.store         = MitreStore(MITRE_BROKERS)

        # Redis actor tracker
        redis_client = redis.Redis(
            host=REDIS_HOST, port=REDIS_PORT,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
        )
        self.actor_tracker = ActorTracker(redis_client)

        # Per-session state: session_id → SessionState
        self._sessions: dict[str, SessionState] = {}
        # Actor-level auth-failure windows catch brute-force behavior that spans
        # many short-lived failed database connections. Keyed by
        # protocol/client_ip/username/database, not proxy session_id.
        self._auth_fail_windows: dict[str, list[float]] = defaultdict(list)
        # Prevent one brute-force burst from spamming duplicate actor-level
        # alerts. The key includes a coarse time bucket, so a later burst after
        # the configured rolling window can alert again.
        self._auth_fail_alert_buckets: set[str] = set()
        self._lock = threading.Lock()

        self._running = False
        self._health_server = None
        self._consumer_status = {"mysql": False, "pg": False, "profiles": False}

    # ─── Health endpoint ──────────────────────────────────────────────────────

    def _start_health_server(self) -> None:
        """Expose a tiny broker-independent health endpoint for Compose/K8s.

        The MITRE agent is otherwise a pure consumer with no HTTP surface, which
        makes orchestration blind: a process can be alive while no consumers have
        started. This endpoint reports process liveness plus current in-memory
        session count; it intentionally does not require Redis or Redpanda calls.
        """
        host, port_s = HEALTH_ADDR.rsplit(":", 1)
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib callback name
                if self.path not in ("/healthz", "/readyz"):
                    self.send_response(404)
                    self.end_headers()
                    return
                with agent._lock:
                    consumer_status = dict(getattr(agent, "_consumer_status", {}))
                    ready = bool(agent._running) and (not consumer_status or all(consumer_status.values()))
                    payload = {
                        "status": "ok" if agent._running else "starting",
                        "ready": ready,
                        "active_sessions": len(agent._sessions),
                        "consumers": consumer_status,
                    }
                data = json.dumps(payload).encode("utf-8")
                self.send_response(200 if self.path == "/healthz" or ready else 503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, fmt, *args):  # silence default access logs
                return

        self._health_server = ThreadingHTTPServer((host, int(port_s)), Handler)
        thread = threading.Thread(
            target=self._health_server.serve_forever,
            name="health-http",
            daemon=True,
        )
        thread.start()
        log.info("Health endpoint listening: %s", HEALTH_ADDR)

    def _stop_health_server(self) -> None:
        if self._health_server:
            self._health_server.shutdown()
            self._health_server.server_close()
            self._health_server = None


    def _set_consumer_status(self, name: str, ready: bool) -> None:
        with self._lock:
            if not hasattr(self, "_consumer_status"):
                self._consumer_status = {}
            self._consumer_status[name] = ready

    # ─── Consumer threads ─────────────────────────────────────────────────────

    def _consume_queries(
        self, brokers: list[str], topics: list[str], source: str
    ) -> None:
        """Consume query/auth events from one Redpanda source.

        KafkaConsumer construction can fail during Compose startup while the
        broker is accepting TCP but not yet serving metadata. Do not let the
        thread die permanently; keep retrying and surface readiness through the
        health endpoint.
        """
        while self._running:
            consumer = None
            try:
                consumer = KafkaConsumer(
                    *topics,
                    bootstrap_servers=brokers,
                    group_id=f"{GROUP_ID}-{source}",
                    auto_offset_reset=CONSUMER_AUTO_OFFSET_RESET,
                    consumer_timeout_ms=1000,
                )
                self._set_consumer_status(source, True)
                log.info("Query consumer started: source=%s topics=%s", source, topics)

                while self._running:
                    for msg in consumer:
                        if not self._running:
                            break
                        raw = self._decode_json_record(msg, stage="parse_query_event")
                        if raw is None:
                            continue
                        if not isinstance(raw, dict):
                            self._publish_dead_letter(msg, "validate_query_event", "expected JSON object", raw_payload=raw)
                            continue
                        try:
                            self._handle_query_event(raw, source)
                        except Exception as e:
                            log.error("Query event processing failed: %s", e, exc_info=True)
                            self._publish_dead_letter(msg, "process_query_event", e, raw_payload=raw)

            except KafkaError as e:
                if self._running:
                    log.warning("Consumer error (%s): %s — retrying", source, e)
                    time.sleep(2)
            except Exception as e:
                if self._running:
                    log.error("Unexpected consumer error (%s): %s", source, e, exc_info=True)
                    time.sleep(2)
            finally:
                self._set_consumer_status(source, False)
                if consumer is not None:
                    try:
                        consumer.close()
                    except Exception:
                        log.debug("consumer close failed: source=%s", source, exc_info=True)

        log.info("Query consumer stopped: source=%s", source)

    def _consume_session_profiles(self, brokers: list[str]) -> None:
        """Consume session-profiles from the session module Redpanda."""
        while self._running:
            consumer = None
            try:
                # Session module publishes to its own Redpanda. If all modules
                # share one Redpanda instance, SESSION_KAFKA_BROKERS should point
                # at that shared broker.
                consumer = KafkaConsumer(
                    TOPIC_SESSION_PROFILES,
                    bootstrap_servers=brokers,
                    group_id=GROUP_ID + "-profiles",
                    auto_offset_reset=CONSUMER_AUTO_OFFSET_RESET,
                    consumer_timeout_ms=1000,
                )
                self._set_consumer_status("profiles", True)
                log.info("Session profile consumer started")

                while self._running:
                    for msg in consumer:
                        if not self._running:
                            break
                        raw = self._decode_json_record(msg, stage="parse_session_profile")
                        if raw is None:
                            continue
                        if not isinstance(raw, dict):
                            self._publish_dead_letter(msg, "validate_session_profile", "expected JSON object", raw_payload=raw)
                            continue
                        if not raw.get("session_id"):
                            self._publish_dead_letter(msg, "validate_session_profile", "missing required field: session_id", raw_payload=raw)
                            continue
                        try:
                            self._handle_session_profile(raw)
                        except Exception as e:
                            log.error("Session profile processing failed: %s", e, exc_info=True)
                            self._publish_dead_letter(msg, "process_session_profile", e, raw_payload=raw)

            except KafkaError as e:
                if self._running:
                    log.warning("Session profile consumer error: %s", e)
                    time.sleep(2)
            except Exception as e:
                if self._running:
                    log.error("Unexpected session profile consumer error: %s", e, exc_info=True)
                    time.sleep(2)
            finally:
                self._set_consumer_status("profiles", False)
                if consumer is not None:
                    try:
                        consumer.close()
                    except Exception:
                        log.debug("session profile consumer close failed", exc_info=True)

        log.info("Session profile consumer stopped")


    # ─── Dead-letter helpers ──────────────────────────────────────────────────

    @staticmethod
    def _payload_preview(value) -> str:
        if isinstance(value, bytes):
            text = value[:DEAD_LETTER_MAX_RAW_BYTES].decode("utf-8", errors="replace")
        else:
            try:
                text = json.dumps(value, default=str)
            except Exception:
                text = str(value)
            if len(text.encode("utf-8")) > DEAD_LETTER_MAX_RAW_BYTES:
                text = text[:DEAD_LETTER_MAX_RAW_BYTES]
        return text

    def _decode_json_record(self, msg, stage: str) -> dict | list | str | int | float | bool | None:
        try:
            parsed = json.loads(msg.value.decode("utf-8"))
            if parsed is None:
                self._publish_dead_letter(msg, stage.replace("parse", "validate"), "expected JSON object, got null", raw_payload=None)
            return parsed
        except Exception as e:
            log.warning(
                "Malformed Kafka JSON: topic=%s partition=%s offset=%s error=%s",
                getattr(msg, "topic", ""), getattr(msg, "partition", None), getattr(msg, "offset", None), e,
            )
            self._publish_dead_letter(msg, stage, e)
            return None

    def _publish_dead_letter(self, msg, stage: str, error, raw_payload=None) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "mitre-agent",
            "source_topic": getattr(msg, "topic", ""),
            "source_partition": getattr(msg, "partition", None),
            "source_offset": getattr(msg, "offset", None),
            "stage": stage,
            "error": str(error),
            "raw_payload": self._payload_preview(msg.value if raw_payload is None else raw_payload),
        }
        payload["dead_letter_id"] = (
            f"{payload['service']}:{payload['source_topic']}:"
            f"{payload['source_partition']}:{payload['source_offset']}"
        )
        try:
            self.store.publish_dead_letter(payload)
        except Exception:
            log.error("Dead-letter publish failed", exc_info=True)

    # ─── Event handlers ───────────────────────────────────────────────────────

    def _handle_query_event(self, raw: dict, source: str) -> None:
        """Process one query event through the rule engine."""
        try:
            event = self._parse_query_event(raw, source)
        except Exception as e:
            log.warning("Failed to parse query event: %s | raw=%s", e, str(raw)[:200])
            return

        # Successful auth and session lifecycle records are useful for ordering,
        # but they should not be treated as SQL query events by the rule engine.
        if event.event_type in {"auth_success", "session_start", "session_end"}:
            return

        # If the proxy did not tag the phase (it never does — phase tagging
        # lives in the session module), classify it here from the normalised SQL.
        if not event.phase and event.query_normalized:
            try:
                from phase_classifier import classify
                event.phase = classify(event.query_normalized) or ""
            except Exception:
                pass  # phase stays empty — rules that need phase will just not fire

        mitre_event = None
        log_fields = None

        with self._lock:
            sess = self._get_or_create_session(event)

            # Update live session counters/features before rule evaluation.
            actor_failed_auth = 0
            if event.event_type == "auth_fail":
                sess.failed_auth += 1
                actor_failed_auth = self._record_actor_auth_failure_event(event)
            else:
                sess.query_count += 1
                fp_key = event.query_normalized or event.fingerprint
                sess.fingerprint_counts[fp_key] += 1
                sess.event_timestamps.append(event.timestamp)

            if event.phase:
                sess.phases_seen.append(event.phase)

            # Replay and multi-topic delivery can occasionally produce events
            # out of timestamp order. Keep first_seen as the earliest observed
            # event and calculate timing features on sorted, non-negative gaps so
            # QPS/variance do not become misleading during replay demos.
            if event.timestamp < sess.first_seen:
                sess.first_seen = event.timestamp

            sess.depth_score = len(sess.fingerprint_counts)
            sess.entropy = self._entropy(sess.fingerprint_counts)
            sess.timing_var = self._timing_variance_ms(sess.event_timestamps)
            elapsed = max(0.0, max(sess.event_timestamps or [event.timestamp]) - sess.first_seen)
            sess.qps = (sess.query_count / elapsed) if elapsed > 0 else 0.0
            if self._is_suspicious_probe(event.query_normalized):
                sess.suspicion += 1

            # Build evaluation context
            eval_fingerprint = event.query_normalized or event.fingerprint
            fp_reuse = sess.fingerprint_counts.get(eval_fingerprint, 0)
            ctx = EvalContext(
                fingerprint=eval_fingerprint,
                phase=event.phase,
                event_type=event.event_type,
                table=self._extract_table(event.query_normalized),
                session_id=event.session_id,
                client_ip=event.client_ip,
                query_count=sess.query_count,
                timing_variance_ms=sess.timing_var,
                qps=sess.qps,
                entropy=sess.entropy,
                depth_score=sess.depth_score,
                failed_auth=max(sess.failed_auth, actor_failed_auth),
                suspicion_score=sess.suspicion,
                risk_score=sess.risk_score,
                attack_path=list(sess.attack_path),
                fingerprint_reuse=fp_reuse,
            )

            # Evaluate rules
            result = self.rule_engine.evaluate(ctx)

            # Update session state
            sess.risk_score = result.new_risk_score
            for tag in result.tags:
                if tag not in sess.attack_path:
                    sess.attack_path.append(tag)
            if result.is_trap_triggered:
                table = ctx.table
                if table and table not in sess.trap_tables:
                    sess.trap_tables.append(table)

            # Update graph builder
            for match in result.matched_techniques:
                sess.graph_builder.add_technique(match)
                sess.technique_matches.append(match)

            # Build MitreEvent if a technique matched. The actual Kafka write is
            # intentionally performed after releasing _lock; broker stalls must
            # not block live rule evaluation for other sessions.
            if result.matched_techniques:
                best = result.matched_techniques[0]
                fingerprint = event.fingerprint or event.query_normalized
                rule_id = best.rule_id or best.matched_by
                mitre_event = MitreEvent(
                    session_id=event.session_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    client_ip=event.client_ip,
                    fingerprint=fingerprint,
                    phase=event.phase,
                    technique_id=best.technique_id,
                    technique_name=best.technique_name,
                    tactic=best.tactic,
                    tactic_id=best.tactic_id,
                    rule_id=rule_id,
                    rule_confidence=best.confidence,
                    event_id=make_mitre_event_id(
                        event.session_id,
                        best.technique_id,
                        rule_id,
                        event.timestamp,
                        fingerprint,
                    ),
                    risk_score=result.new_risk_score,
                    risk_level=result.risk_level,
                    deception_level=result.deception_level,
                    tags=result.tags,
                    explanation=result.explanation,
                    is_trap_triggered=result.is_trap_triggered,
                    protocol=event.protocol,
                    database=event.database,
                )
                log_fields = (
                    self._short_id(event.session_id), best.technique_id,
                    result.new_risk_score, result.risk_level, result.is_trap_triggered,
                )

        if mitre_event:
            self.store.publish_event(mitre_event)
            if log_fields:
                log.info(
                    "MITRE: session=%s technique=%s risk=%.1f level=%s trap=%s",
                    *log_fields,
                )

    def _handle_session_profile(self, raw: dict) -> None:
        """
        Process a session-profiles event from the session module.
        This fires at session close — triggers HMM scoring, graph build,
        and actor profile update.
        """
        session_id = raw.get("session_id", "")
        if not session_id:
            return

        mitre_session = None
        log_fields = None
        profile_only = False

        with self._lock:
            sess = self._sessions.get(session_id)
            if not sess:
                # Profiles can arrive without a live query-side session when the
                # MITRE agent starts after the query stream or when a sparse/auth-only
                # session closes. Build/publish outside the lock.
                profile_only = True
            else:
                # Update session features from the session module's computed values.
                # Session profiles are a cross-service boundary: malformed or
                # partially migrated fields must not kill the consumer thread.
                sess.entropy        = self._safe_float(raw.get("entropy", 0.0), 0.0)
                sess.depth_score    = int(self._safe_float(raw.get("depth_score", 0), 0.0))
                sess.timing_var     = self._safe_float(raw.get("timing_variance_ms", 0.0), 0.0)
                sess.qps            = self._safe_float(raw.get("queries_per_second", 0.0), 0.0)
                sess.suspicion      = int(self._safe_float(raw.get("suspicion_score", 0), 0.0))
                sess.persona        = raw.get("persona", "unknown") or "unknown"
                if not sess.protocol and raw.get("protocol"):
                    sess.protocol = self._normalise_protocol(raw.get("protocol", ""))
                if not sess.database and raw.get("database"):
                    sess.database = str(raw.get("database", ""))

                # HMM sequence scoring
                seq_confidence = self.hmm_scorer.score_sequence(sess.phases_seen)
                decoded_states = self.hmm_scorer.decode_sequence(sess.phases_seen)

                # Combined confidence across all matched techniques
                if sess.technique_matches:
                    avg_rule_conf = sum(
                        m.confidence for m in sess.technique_matches
                    ) / len(sess.technique_matches)
                    combined = self.hmm_scorer.combined_confidence(
                        avg_rule_conf, seq_confidence
                    )
                else:
                    combined = seq_confidence * self.hmm_scorer.w_hmm

                # Build final attack graph
                attack_graph = sess.graph_builder.build()

                # Prefer the session module's duration because replayed events
                # can be much older than the MITRE agent wall clock. Fall back to
                # wall-clock duration only when the profile does not provide one.
                raw_duration = raw.get("duration", None)
                has_profile_duration = raw_duration not in (None, "")
                duration_s = self._safe_float(raw_duration, -1.0)
                if duration_s < 0.0:
                    duration_s = 0.0 if has_profile_duration else max(0.0, time.time() - sess.first_seen)

                # Build MitreSession while holding the lock, but publish/update
                # Redis after releasing it. Redpanda/Redis backpressure should not
                # pause live query classification.
                mitre_session = MitreSession(
                    session_id=session_id,
                    client_ip=sess.client_ip,
                    username=sess.username,
                    protocol=sess.protocol,
                    database=sess.database,
                    timestamp_closed=datetime.now(timezone.utc).isoformat(),
                    duration_s=round(duration_s, 2),
                    final_risk_score=round(sess.risk_score, 2),
                    risk_level=self.rule_engine._risk_level(sess.risk_score),
                    persona=sess.persona,
                    attack_path=list(sess.attack_path),
                    techniques_matched=[
                        dataclasses.asdict(m) for m in sess.technique_matches
                    ],
                    sequence_confidence=round(seq_confidence, 4),
                    attack_graph=attack_graph,
                    trap_triggered=len(sess.trap_tables) > 0,
                    trap_tables_accessed=list(sess.trap_tables),
                    explanation=(
                        f"HMM decoded: {' → '.join(decoded_states[:5])}. "
                        f"Combined confidence: {combined:.2f}. "
                        f"Persona: {sess.persona}."
                    ),
                )
                log_fields = (
                    self._short_id(session_id), sess.risk_score, seq_confidence,
                    len(sess.technique_matches), len(sess.trap_tables) > 0,
                )

                # Clean up session state before doing external I/O.
                del self._sessions[session_id]

        if profile_only:
            self._publish_profile_only_session(raw)
            return

        if not mitre_session:
            return

        self.store.publish_session(mitre_session)

        # Update actor profile
        try:
            self.actor_tracker.update_from_session(mitre_session)
        except Exception as e:
            log.error("Actor tracker update failed: %s", e)

        if log_fields:
            log.info(
                "Session closed: id=%s risk=%.1f seq_conf=%.2f techniques=%d trap=%s",
                *log_fields,
            )

    # ─── Session management ───────────────────────────────────────────────────

    def _get_or_create_session(self, event: QueryEvent) -> SessionState:
        if event.session_id not in self._sessions:
            self._sessions[event.session_id] = SessionState(
                session_id=event.session_id,
                client_ip=event.client_ip,
                username=event.username,
                protocol=event.protocol,
                database=event.database,
                first_seen=event.timestamp,
            )
        sess = self._sessions[event.session_id]
        if not sess.protocol and event.protocol:
            sess.protocol = event.protocol
        if not sess.database and event.database:
            sess.database = event.database
        return sess

    def _publish_profile_only_session(self, raw: dict) -> None:
        session_id = raw.get("session_id", "")
        if not session_id:
            return

        client_ip = raw.get("source_ip") or raw.get("client_ip") or "unknown"
        username = raw.get("db_user") or raw.get("username") or "unknown"
        persona = raw.get("persona") or "unknown"
        protocol = self._normalise_protocol(raw.get("protocol", ""))
        database = raw.get("database", "")

        query_sequence = self._json_list(raw.get("query_sequence", "[]"))
        phases = []
        try:
            from phase_classifier import classify
            for item in query_sequence:
                if item == "AUTH_FAIL":
                    phases.append("credential_access")
                    continue
                phase = classify(str(item)) or ""
                if phase:
                    phases.append(phase)
        except Exception:
            phases = []

        failed_auth_count = self._safe_float(raw.get("failed_auth", 0), 0.0)
        suspicion_count = self._safe_float(raw.get("suspicion_score", 0), 0.0)
        depth_value = self._safe_float(raw.get("depth_score", 0), 0.0)
        query_count = self._safe_float(raw.get("query_count", 0), 0.0)
        actor_failed_auth = 0
        if failed_auth_count > 0:
            actor_failed_auth = self._record_actor_auth_failure_profile(
                protocol, client_ip, username, database, raw, int(failed_auth_count)
            )

        base_risk = 0.0
        base_risk += min(max(failed_auth_count, actor_failed_auth), 5.0) * 0.8
        base_risk += min(suspicion_count, 5.0) * 0.6
        base_risk += min(depth_value / 2.0, 4.0)
        cluster_id = int(self._safe_float(raw.get("cluster_id", 0), 0.0))
        if actor_failed_auth >= AUTH_FAIL_THRESHOLD:
            base_risk = max(base_risk, 6.0)
            if "credential_access" not in phases:
                phases.append("credential_access")
        if cluster_id == -1 and base_risk == 0.0:
            base_risk = 0.5 if query_count else 0.0

        decoded_states = self.hmm_scorer.decode_sequence(phases) if phases else []
        seq_confidence = self.hmm_scorer.score_sequence(phases) if phases else 0.0
        technique_matches = self._profile_only_techniques(raw, phases, actor_failed_auth)
        auth_alert_event = None
        auth_event_timestamp = self._safe_float(
            raw.get("created_at", raw.get("timestamp", time.time())), time.time()
        )
        if actor_failed_auth >= AUTH_FAIL_THRESHOLD and self._should_emit_actor_auth_alert(
            protocol, client_ip, username, database,
            auth_event_timestamp,
            actor_failed_auth,
        ):
            auth_alert_event = self._build_actor_auth_mitre_event(
                session_id=session_id,
                client_ip=client_ip,
                username=username,
                protocol=protocol,
                database=database,
                actor_failed_auth=actor_failed_auth,
                source_timestamp=auth_event_timestamp,
            )

        mitre_session = MitreSession(
            session_id=session_id,
            client_ip=client_ip,
            username=username,
            protocol=protocol,
            database=database,
            timestamp_closed=datetime.now(timezone.utc).isoformat(),
            duration_s=round(max(0.0, self._safe_float(raw.get("duration", 0.0), 0.0)), 2),
            final_risk_score=round(base_risk, 2),
            risk_level=self.rule_engine._risk_level(base_risk),
            persona=persona,
            attack_path=phases,
            techniques_matched=[dataclasses.asdict(m) for m in technique_matches],
            sequence_confidence=round(seq_confidence, 4),
            attack_graph=build_session_graph(technique_matches),
            trap_triggered=False,
            trap_tables_accessed=[],
            explanation=(
                "Profile-only session summary; no live query-side MITRE state was available. "
                f"HMM decoded: {' → '.join(decoded_states[:5]) if decoded_states else 'n/a'}. "
                f"Techniques inferred: {len(technique_matches)}. "
                f"Persona: {persona}."
            ),
        )
        if auth_alert_event and hasattr(self.store, "publish_event"):
            self.store.publish_event(auth_alert_event)
        self.store.publish_session(mitre_session)
        try:
            self.actor_tracker.update_from_session(mitre_session)
        except Exception as e:
            log.error("Actor tracker update failed for profile-only session: %s", e)
        log.info(
            "Profile-only session closed: id=%s risk=%.1f persona=%s phases=%d",
            self._short_id(session_id), base_risk, persona, len(phases),
        )


    def _profile_only_techniques(self, raw: dict, phases: list[str], actor_failed_auth: int = 0) -> list[TechniqueMatch]:
        """Infer coarse MITRE techniques for sessions seen only after close.

        When the MITRE agent starts after the query stream, it may only receive a
        session-profile summary. That profile has enough aggregate signal to
        preserve obvious technique evidence such as brute-force auth failures and
        schema enumeration. This is intentionally conservative: it adds only
        high-level matches backed by explicit counters/phases, not per-query
        claims that would require the original event stream.
        """
        matches: list[TechniqueMatch] = []
        seen: set[str] = set()

        def add(technique_id: str, rule_id: str, matched_by: str, explanation: str) -> None:
            if technique_id in seen:
                return
            info = self.rule_engine.technique_index.get(technique_id, {})
            matches.append(TechniqueMatch(
                technique_id=technique_id,
                technique_name=info.get("name", technique_id),
                tactic=info.get("tactic", "Unknown"),
                tactic_id=info.get("tactic_id", ""),
                confidence=float(info.get("confidence", 0.70)),
                matched_by=matched_by,
                explanation=explanation,
                rule_id=rule_id,
            ))
            seen.add(technique_id)

        failed_auth = max(int(self._safe_float(raw.get("failed_auth", 0), 0.0)), int(actor_failed_auth))
        suspicion = int(self._safe_float(raw.get("suspicion_score", 0), 0.0))
        depth = self._safe_float(raw.get("depth_score", 0), 0.0)
        phase_set = set(phases)

        if failed_auth > 2:
            add(
                "T1110.001", "R009_brute_force", "aggregate_auth_fail",
                f"session profile contained {failed_auth} failed authentication attempts",
            )
        if "recon" in phase_set or suspicion > 0:
            add(
                "T1082", "R002_automated_recon_probe", "aggregate_phase",
                f"session profile contained recon/honeypot-probe evidence; suspicion_score={suspicion}",
            )
        if "enumeration" in phase_set and depth > 2:
            add(
                "T1213.006", "R003_schema_enumeration", "aggregate_phase",
                f"session profile contained schema enumeration with depth_score={depth}",
            )
        if "exploitation" in phase_set:
            add(
                "T1190", "R006_exploitation_attempt", "aggregate_phase",
                "session profile contained exploitation-phase queries",
            )
        if "exfiltration" in phase_set:
            add(
                "T1048", "R007_data_exfiltration", "aggregate_phase",
                "session profile contained exfiltration-phase queries",
            )

        return matches

    def _record_actor_auth_failure_event(self, event: QueryEvent) -> int:
        return self._record_actor_auth_failure(
            event.protocol, event.client_ip, event.username, event.database, event.timestamp, 1
        )

    def _record_actor_auth_failure_profile(
        self, protocol: str, client_ip: str, username: str, database: str, raw: dict, count: int
    ) -> int:
        ts = self._safe_float(raw.get("created_at", raw.get("timestamp", time.time())), time.time())
        return self._record_actor_auth_failure(protocol, client_ip, username, database, ts, count)

    def _record_actor_auth_failure(
        self, protocol: str, client_ip: str, username: str, database: str, timestamp: float, count: int = 1
    ) -> int:
        if not hasattr(self, "_auth_fail_windows"):
            self._auth_fail_windows = defaultdict(list)
        key = self._actor_key(protocol, client_ip, username, database)
        now = float(timestamp) if timestamp is not None else time.time()
        floor = now - AUTH_FAIL_WINDOW_SECONDS
        window = [ts for ts in self._auth_fail_windows.get(key, []) if ts >= floor]
        window.extend([now] * max(1, int(count)))
        self._auth_fail_windows[key] = window
        return len(window)

    def _should_emit_actor_auth_alert(
        self, protocol: str, client_ip: str, username: str, database: str, timestamp: float, count: int
    ) -> bool:
        if count < AUTH_FAIL_THRESHOLD:
            return False
        if not hasattr(self, "_auth_fail_alert_buckets"):
            self._auth_fail_alert_buckets = set()
        window = max(AUTH_FAIL_WINDOW_SECONDS, 1.0)
        bucket = int((float(timestamp) if timestamp is not None else time.time()) // window)
        key = f"{self._actor_key(protocol, client_ip, username, database)}|{bucket}"
        if key in self._auth_fail_alert_buckets:
            return False
        self._auth_fail_alert_buckets.add(key)
        return True

    def _build_actor_auth_mitre_event(
        self, session_id: str, client_ip: str, username: str, protocol: str,
        database: str, actor_failed_auth: int, source_timestamp: float
    ) -> MitreEvent:
        info = self.rule_engine.technique_index.get("T1110.001", {})
        risk_score = max(6.0, min(10.0, float(actor_failed_auth) * 1.5))
        return MitreEvent(
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_ip=client_ip,
            fingerprint="AUTH_FAIL",
            phase="credential_access",
            technique_id="T1110.001",
            technique_name=info.get("name", "Password Guessing"),
            tactic=info.get("tactic", "Credential Access"),
            tactic_id=info.get("tactic_id", "TA0006"),
            rule_id="R009_brute_force",
            rule_confidence=float(info.get("confidence", 0.90)),
            event_id=make_mitre_event_id(
                session_id,
                "T1110.001",
                "R009_brute_force",
                source_timestamp,
                "AUTH_FAIL",
            ),
            risk_score=risk_score,
            risk_level=self.rule_engine._risk_level(risk_score),
            deception_level=3,
            tags=["brute_force", "actor_window"],
            explanation=(
                f"Actor-level failed-auth window crossed threshold: "
                f"{actor_failed_auth} failures for {protocol or 'db'} {client_ip} {username}."
            ),
            is_trap_triggered=False,
            protocol=protocol,
            database=database,
        )

    @staticmethod
    def _actor_key(protocol: str, client_ip: str, username: str, database: str = "") -> str:
        proto = MitreAgent._normalise_protocol(protocol) or "db"
        return "|".join([proto, client_ip or "unknown", username or "unknown", database or ""])

    @staticmethod
    def _safe_float(value, default: float = 0.0) -> float:
        try:
            if value is None or value == "":
                return default
            parsed = float(value)
            return parsed if math.isfinite(parsed) else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _is_false(value) -> bool:
        if value is False:
            return True
        if isinstance(value, str):
            return value.strip().lower() in {"false", "0", "no", "n"}
        if isinstance(value, (int, float)):
            return value == 0
        return False

    @staticmethod
    def _json_list(value) -> list:
        if isinstance(value, list):
            return value
        if not value:
            return []
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    @staticmethod
    def _normalise_protocol(value: str) -> str:
        v = (value or "").lower()
        if v in ("pg", "postgres", "postgresql"):
            return "postgres"
        if "mysql" in v:
            return "mysql"
        if "pg" in v:
            return "postgres"
        return v or "db"

    @staticmethod
    def _fallback_session_id(protocol: str, client_ip: str, username: str, database: str = "") -> str:
        proto = MitreAgent._normalise_protocol(protocol) or "db"
        ip = client_ip or "unknown"
        user = username or "unknown"
        db = database or ""
        return f"{proto}:{ip}:{user}:{db}" if db else f"{proto}:{ip}:{user}"

    # ─── Helpers ──────────────────────────────────────────────────────────────


    @staticmethod
    def _short_id(value: str) -> str:
        if not value:
            return ""
        return value[:8] if len(value) > 8 else value

    @staticmethod
    def _entropy(counter: dict[str, int]) -> float:
        total = sum(counter.values())
        if total <= 0:
            return 0.0
        value = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                value -= p * math.log2(p)
        return value

    @staticmethod
    def _timing_variance_ms(timestamps: list[float]) -> float:
        if len(timestamps) < 3:
            return 0.0
        ordered = sorted(float(ts) for ts in timestamps)
        gaps = [
            max(0.0, ordered[i] - ordered[i - 1])
            for i in range(1, len(ordered))
        ]
        if len(gaps) < 2:
            return 0.0
        mean = sum(gaps) / len(gaps)
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        return math.sqrt(var) * 1000.0

    @staticmethod
    def _is_suspicious_probe(query_normalized: str) -> bool:
        q = (query_normalized or "").lower()
        return any(fragment in q for fragment in (
            "@@hostname", "@@version_comment", "@@datadir", "@@secure_file_priv",
            "sleep(", "benchmark(", "load_file(", "pg_sleep(", "pg_read_file(",
            "into outfile", "into dumpfile",
        ))

    @staticmethod
    def _parse_query_event(raw: dict, source: str = "") -> QueryEvent:
        # Parse timestamp — proxy publishes ISO strings, not floats
        ts_raw = raw.get("timestamp", "")
        try:
            if isinstance(ts_raw, (int, float)):
                ts = float(ts_raw)
            elif ts_raw:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                ts = dt.timestamp()
            else:
                ts = time.time()
        except Exception:
            ts = time.time()
        client_ip = raw.get("client_ip") or raw.get("source_ip") or "unknown"
        username = raw.get("username") or raw.get("db_user") or "unknown"
        event_type = str(raw.get("event_type", "query")).strip().lower()
        if event_type == "auth":
            if MitreAgent._is_false(raw.get("success")):
                event_type = "auth_fail"
            else:
                event_type = "auth_success"
        if MitreAgent._is_false(raw.get("auth_success")):
            event_type = "auth_fail"
        protocol = MitreAgent._normalise_protocol(raw.get("protocol") or source or raw.get("protocol_mode", "db"))
        database = raw.get("database", "")
        session_id = raw.get("session_id") or MitreAgent._fallback_session_id(protocol, client_ip, username, database)
        return QueryEvent(
            session_id=session_id,
            timestamp=ts,
            client_ip=client_ip,
            username=username,
            database=database,
            query_raw=raw.get("query_raw", ""),
            query_normalized=raw.get("query_normalized", ""),
            fingerprint=raw.get("fingerprint") or raw.get("query_normalized", ""),
            protocol_mode=raw.get("protocol_mode") or "text",
            event_type=event_type,
            protocol=protocol,
            phase=raw.get("phase", ""),
            bytes_in=int(MitreAgent._safe_float(raw.get("bytes_in", 0), 0.0)),
            bytes_out=int(MitreAgent._safe_float(raw.get("bytes_out", 0), 0.0)),
        )

    @staticmethod
    def _extract_table(query_normalized: str) -> str:
        """Best-effort table-name extraction from normalized SQL.

        This intentionally stays conservative: it handles the common single-table
        forms used by scanners and demos, strips schema qualifiers/quotes, and
        avoids returning WHERE/JOIN/LIMIT fragments as part of the table name. It
        is not a full SQL parser.
        """
        if not query_normalized:
            return ""
        q = query_normalized.strip().lower()
        patterns = (
            r"\bfrom\s+([^\s,;()]+)",
            r"\bjoin\s+([^\s,;()]+)",
            r"\binto\s+([^\s,;()]+)",
            r"\bupdate\s+([^\s,;()]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, q)
            if not match:
                continue
            token = match.group(1).strip("`'\"[]()")
            if not token or token in {"select", "where", "set", "values"}:
                continue
            if "." in token:
                token = token.split(".")[-1]
            return token.strip("`'\"[]()")
        return ""

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._start_health_server()

        threads = [
            threading.Thread(
                target=self._consume_queries,
                args=(MYSQL_BROKERS, [TOPIC_MYSQL_QUERIES, TOPIC_MYSQL_SESSION], "mysql"),
                name="consumer-mysql",
                daemon=True,
            ),
            threading.Thread(
                target=self._consume_queries,
                args=(PG_BROKERS, [TOPIC_PG_QUERIES, TOPIC_PG_SESSION], "pg"),
                name="consumer-pg",
                daemon=True,
            ),
            threading.Thread(
                target=self._consume_session_profiles,
                args=(SESSION_BROKERS,),
                name="consumer-profiles",
                daemon=True,
            ),
        ]

        for t in threads:
            t.start()
            log.info("Started thread: %s", t.name)

        log.info("MITRE agent running")

        def _shutdown(sig, frame):
            log.info("Shutdown signal received")
            self._running = False

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        for t in threads:
            t.join()

        self.store.flush()
        self.store.close()
        self._stop_health_server()
        log.info("MITRE agent stopped")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    agent = MitreAgent()
    agent.start()

"""
redpanda_consumer.py
--------------------
Main entry point for the session module.

Consumes SQL events from TWO sources simultaneously:
  - mysql-query-events  (mysqlproxy's Redpanda)
  - pg-query-events     (pgproxy's Redpanda)

Gap 3 fix: select @@... queries are no longer silently discarded.
They are emitted as event_type='recon_probe' with a phase tag and enter
the SessionEngine feature pipeline so recon-only sessions still produce
profiles for downstream MITRE/deception/scaling consumers.
"""

import json
import time
import queue
import threading
import logging
from datetime import datetime, timezone

from kafka import KafkaConsumer

from models import Event
from phase_classifier import classify_phase
from session_engine import SessionEngine
from storage import RedpandaSessionStore
from clustering_worker import ClusteringWorker
from authoritative_state import AuthoritativeStateStore, start_state_api
from async_adaptation import AsyncStrategyAdapter
import config

from prometheus_client import start_http_server
from metrics import events_processed_total, events_dropped_total, events_failed_total

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

event_queue = queue.Queue(maxsize=config.EVENT_QUEUE_MAX_SIZE)
shutdown_event = threading.Event()


def _normalise_protocol(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "mysql" in v:
        return "mysql"
    if v in ("pg", "postgres", "postgresql") or v.startswith("pg-") or v.startswith("postgres"):
        return "postgres"
    return v


def _protocol_from_label(label: str) -> str:
    return _normalise_protocol(label)


def _is_false(value) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "n"}
    if isinstance(value, (int, float)):
        return value == 0
    return False


# ─────────────────────────────────────────────────────────────────────
# Event mapping
# ─────────────────────────────────────────────────────────────────────

def map_proxy_event_to_event(raw: dict, source_label: str = "") -> Event | None:
    """Map proxy query/auth JSON into the session module's Event model."""
    ts_str = raw.get("timestamp", "")
    try:
        from datetime import datetime
        if isinstance(ts_str, (int, float)):
            ts = float(ts_str)
        else:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")).timestamp()
    except Exception:
        ts = time.time()

    source_ip = raw.get("client_ip") or raw.get("source_ip") or "unknown"
    db_user = raw.get("username") or raw.get("db_user") or "unknown"
    session_id = raw.get("session_id", "")
    protocol = _normalise_protocol(raw.get("protocol", "")) or _protocol_from_label(source_label)
    database = raw.get("database", "")

    # Auth events often do not carry query_normalized. Handle them before
    # dropping empty queries.
    event_type = str(raw.get("event_type", "")).strip().lower()
    is_auth_fail = (
        event_type == "auth_fail"
        or (event_type == "auth" and _is_false(raw.get("success")))
        or _is_false(raw.get("auth_success"))
    )
    if is_auth_fail:
        return Event(
            timestamp=ts,
            source_ip=source_ip,
            db_user=db_user,
            query_fingerprint="",
            event_type="auth_fail",
            phase="",
            session_id=session_id,
            protocol=protocol,
            database=database,
        )

    query = (raw.get("query_normalized") or raw.get("fingerprint") or "").lower().strip()
    if not query:
        return None

    fingerprint = raw.get("query_normalized") or raw.get("fingerprint", "")

    # Recon probes remain visible to session features and downstream MITRE/HMM.
    if query.startswith("select @@") or query.startswith("show "):
        phase = classify_phase(fingerprint) or "recon"
        return Event(
            timestamp=ts,
            source_ip=source_ip,
            db_user=db_user,
            query_fingerprint=fingerprint,
            event_type="recon_probe",
            phase=phase,
            session_id=session_id,
            protocol=protocol,
            database=database,
        )

    phase = classify_phase(fingerprint) or ""
    return Event(
        timestamp=ts,
        source_ip=source_ip,
        db_user=db_user,
        query_fingerprint=fingerprint,
        event_type="query",
        phase=phase,
        session_id=session_id,
        protocol=protocol,
        database=database,
    )


# ─────────────────────────────────────────────────────────────────────
# Queue drainer — feeds SessionEngine
# ─────────────────────────────────────────────────────────────────────

def event_worker(engine: SessionEngine):
    while True:
        event = event_queue.get()
        try:
            if event is None:
                return
            try:
                engine.process_event(event)
                events_processed_total.inc()
            except Exception as e:
                events_failed_total.labels(stage="session_engine").inc()
                logger.error("Session event processing failed: %s", e, exc_info=True)
        finally:
            event_queue.task_done()




def _payload_preview(value) -> str:
    if isinstance(value, bytes):
        return value[:config.DEAD_LETTER_MAX_RAW_BYTES].decode("utf-8", errors="replace")
    try:
        text = json.dumps(value, default=str)
    except Exception:
        text = str(value)
    return text[:config.DEAD_LETTER_MAX_RAW_BYTES]


def publish_dead_letter(storage: RedpandaSessionStore, message, service: str, stage: str, error, raw_payload=None) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "source_topic": getattr(message, "topic", ""),
        "source_partition": getattr(message, "partition", None),
        "source_offset": getattr(message, "offset", None),
        "stage": stage,
        "error": str(error),
        "raw_payload": _payload_preview(message.value if raw_payload is None else raw_payload),
    }
    payload["dead_letter_id"] = (
        f"{payload['service']}:{payload['source_topic']}:"
        f"{payload['source_partition']}:{payload['source_offset']}"
    )
    try:
        storage.publish_dead_letter(payload)
    except Exception:
        logger.error("Dead-letter publish failed", exc_info=True)


def decode_json_message(storage: RedpandaSessionStore, message, service: str, stage: str):
    try:
        parsed = json.loads(message.value.decode("utf-8"))
        if parsed is None:
            publish_dead_letter(storage, message, service, stage.replace("parse", "validate"), "expected JSON object, got null", raw_payload=None)
        return parsed
    except Exception as e:
        logger.warning(
            "Malformed Kafka JSON: topic=%s partition=%s offset=%s error=%s",
            getattr(message, "topic", ""), getattr(message, "partition", None), getattr(message, "offset", None), e,
        )
        publish_dead_letter(storage, message, service, stage, e)
        return None

# ─────────────────────────────────────────────────────────────────────
# Generic Redpanda consumer — one per proxy
# ─────────────────────────────────────────────────────────────────────

def run_consumer(bootstrap: str, topic: str, label: str, storage: RedpandaSessionStore, state_store: AuthoritativeStateStore, adaptation: AsyncStrategyAdapter):
    logger.info(f"[{label}] Connecting to {bootstrap}, topic={topic}")
    group_id = f"{config.CONSUMER_GROUP}-{label.lower()}"

    while not shutdown_event.is_set():
        consumer = None
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap,
                group_id=group_id,
                auto_offset_reset=config.CONSUMER_AUTO_OFFSET_RESET,
                enable_auto_commit=True,
                consumer_timeout_ms=1000,
            )
            logger.info(f"[{label}] Subscribed to {topic}. Waiting for events...")

            while not shutdown_event.is_set():
                for message in consumer:
                    if shutdown_event.is_set():
                        break
                    raw = decode_json_message(storage, message, "session-module", "parse_proxy_event")
                    if raw is None:
                        continue
                    if not isinstance(raw, dict):
                        publish_dead_letter(storage, message, "session-module", "validate_proxy_event", "expected JSON object", raw_payload=raw)
                        continue

                    try:
                        if label == "MITRE":
                            state_store.apply_mitre_event(raw)
                            snapshot = state_store.get_adaptation_snapshot(raw.get("session_id"))
                            if snapshot:
                                state_store.observe_strategy_outcomes(snapshot)
                            adaptation.schedule(raw.get("session_id"))
                            continue
                        state_store.apply_proxy_event(raw, label)
                        snapshot = state_store.get_adaptation_snapshot(raw.get("session_id"))
                        if snapshot:
                            state_store.observe_strategy_outcomes(snapshot)
                        if str(raw.get("event_type") or "").lower() in {"query", "session_end"}:
                            adaptation.schedule(raw.get("session_id"))
                    except Exception as e:
                        events_failed_total.labels(stage="state_projection").inc()
                        logger.error("[%s] State projection failed: %s", label, e, exc_info=True)
                        publish_dead_letter(storage, message, "session-module", "state_projection", e, raw_payload=raw)
                        continue

                    try:
                        event = map_proxy_event_to_event(raw, label)
                    except Exception as e:
                        events_failed_total.labels(stage="map_proxy_event").inc()
                        logger.error("[%s] Failed to map proxy event: %s", label, e, exc_info=True)
                        publish_dead_letter(storage, message, "session-module", "map_proxy_event", e, raw_payload=raw)
                        continue

                    if event is None:
                        continue

                    logger.info(
                        f"[{label}] {event.source_ip} | {event.db_user} | "
                        f"{event.event_type} | {event.query_fingerprint[:60]}"
                    )
                    try:
                        event_queue.put(event, timeout=2)
                    except queue.Full:
                        events_dropped_total.labels(reason="queue_full").inc()
                        publish_dead_letter(storage, message, "session-module", "queue_full", "event queue full", raw_payload=raw)
                        logger.warning(
                            "[%s] event queue full, dropping event: session_id=%s type=%s",
                            label, event.session_id, event.event_type,
                        )
                # consumer_timeout_ms lets us re-check shutdown_event here.

        except Exception as e:
            if not shutdown_event.is_set():
                logger.warning(f"[{label}] Connection error: {e}. Retrying in 5s...")
                shutdown_event.wait(5)
        finally:
            if consumer is not None:
                try:
                    consumer.close()
                except Exception:
                    logger.debug("[%s] consumer close failed", label, exc_info=True)

    logger.info("[%s] consumer stopped", label)


# ─────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    start_http_server(config.METRICS_PORT)
    logger.info(f"Prometheus metrics at http://localhost:{config.METRICS_PORT}/metrics")

    storage = RedpandaSessionStore()
    engine = SessionEngine(storage)
    state_store = AuthoritativeStateStore(
        config.STATE_MAX_SESSIONS,
        learned_confidence_threshold=config.LEARNED_SELECTION_MIN_CONFIDENCE,
        learned_minimum_updates=config.LEARNED_SELECTION_MIN_UPDATES,
    )
    adaptation = AsyncStrategyAdapter(
        state_store,
        config.ADAPTATION_ENDPOINT,
        config.ADAPTATION_OPERATOR_MODE,
        config.ADAPTATION_TIMEOUT_SECONDS,
        config.ADAPTATION_QUEUE_SIZE,
    )
    state_api = start_state_api(state_store, config.STATE_API_HOST, config.STATE_API_PORT)
    logger.info(f"Authoritative state API at http://{config.STATE_API_HOST}:{config.STATE_API_PORT}")

    clustering = ClusteringWorker(storage)
    clustering.start()

    worker_thread = threading.Thread(target=event_worker, args=(engine,), daemon=True)
    worker_thread.start()

    mysql_thread = threading.Thread(
        target=run_consumer,
        args=(config.MYSQL_REDPANDA_BOOTSTRAP, config.TOPIC_MYSQL_INPUT, "MySQL", storage, state_store, adaptation),
        daemon=True,
    )
    mysql_thread.start()

    pg_thread = threading.Thread(
        target=run_consumer,
        args=(config.PG_REDPANDA_BOOTSTRAP, config.TOPIC_PG_INPUT, "PG", storage, state_store, adaptation),
        daemon=True,
    )
    pg_thread.start()

    mysql_session_thread = threading.Thread(
        target=run_consumer,
        args=(config.MYSQL_REDPANDA_BOOTSTRAP, config.TOPIC_MYSQL_SESSION, "MySQL-Session", storage, state_store, adaptation),
        daemon=True,
    )
    mysql_session_thread.start()

    pg_session_thread = threading.Thread(
        target=run_consumer,
        args=(config.PG_REDPANDA_BOOTSTRAP, config.TOPIC_PG_SESSION, "PG-Session", storage, state_store, adaptation),
        daemon=True,
    )
    pg_session_thread.start()

    mitre_thread = threading.Thread(
        target=run_consumer,
        args=(config.OWN_REDPANDA_BOOTSTRAP, config.TOPIC_MITRE_EVENTS, "MITRE", storage, state_store, adaptation),
        daemon=True,
    )
    mitre_thread.start()
    state_store.ready = True

    logger.info("Session module running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        shutdown_event.set()

        # Stop network-facing consumers first so no new events arrive behind
        # the worker sentinel. Joins are bounded because consumers use
        # consumer_timeout_ms and re-check shutdown_event.
        for thread in (mysql_thread, pg_thread, mysql_session_thread, pg_session_thread, mitre_thread):
            thread.join(timeout=5)

        adaptation.stop()

        clustering.stop()
        clustering.join(timeout=10)

        # Drain every event already accepted into the bounded queue, then send
        # a sentinel. Sending the sentinel before draining can strand later
        # queue items forever.
        event_queue.join()
        event_queue.put(None)
        worker_thread.join(timeout=5)

        state_store.ready = False
        state_api.shutdown()
        state_api.server_close()
        engine.shutdown()
        storage.close()
        logger.info("Goodbye.")

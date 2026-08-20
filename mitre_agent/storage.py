"""
storage.py — Redpanda producer for MITRE agent outputs.

Publishes to:
  - mitre-events        (per-query MitreEvent, keyed by session_id)
  - mitre-sessions      (per-session MitreSession at close, keyed by session_id)

All Kafka I/O is isolated here so the rest of the agent is broker-independent
and fully unit-testable with mocks.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import time

from kafka import KafkaProducer
from kafka.errors import KafkaError

from models import MitreEvent, MitreSession

log = logging.getLogger(__name__)

TOPIC_MITRE_EVENTS   = os.environ.get("TOPIC_MITRE_EVENTS",   "mitre-events")
TOPIC_MITRE_SESSIONS = os.environ.get("TOPIC_MITRE_SESSIONS", "mitre-sessions")
TOPIC_DEAD_LETTER    = os.environ.get("TOPIC_DEAD_LETTER",    "dead-letter-events")
PRODUCER_RETRIES = int(os.environ.get("PRODUCER_CONNECT_RETRIES", "10"))
PRODUCER_RETRY_DELAY = float(os.environ.get("PRODUCER_CONNECT_RETRY_DELAY_SECONDS", "5"))
PRODUCER_ACK_TIMEOUT = float(os.environ.get("PRODUCER_ACK_TIMEOUT_SECONDS", "10"))

# Per-record publish hardening. The initial send counts as attempt 1, so the
# default of 2 retries gives 3 attempts total before a record is dropped.
PRODUCER_SEND_RETRIES = int(os.environ.get("PRODUCER_SEND_RETRIES", "2"))
PRODUCER_SEND_RETRY_DELAY = float(os.environ.get("PRODUCER_SEND_RETRY_DELAY_SECONDS", "0.25"))


def _serialise(obj: object) -> bytes:
    """JSON-serialise a dataclass to bytes."""
    return json.dumps(dataclasses.asdict(obj), default=str).encode("utf-8")


def _make_producer(brokers: list[str]) -> KafkaProducer:
    last_error: Exception | None = None
    for attempt in range(1, PRODUCER_RETRIES + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=brokers,
                value_serializer=lambda v: v,    # pre-serialised bytes
                key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
                retries=5,
                acks="all",
                linger_ms=10,
                batch_size=16384,
            )
            log.info("MitreStore connected: brokers=%s", brokers)
            return producer
        except Exception as e:  # kafka-python raises several concrete subclasses here
            last_error = e
            log.warning(
                "MitreStore connection attempt %d/%d failed: %s; retrying in %.1fs",
                attempt, PRODUCER_RETRIES, e, PRODUCER_RETRY_DELAY,
            )
            time.sleep(PRODUCER_RETRY_DELAY)
    raise RuntimeError(f"MitreStore could not connect to {brokers}: {last_error}")


class MitreStore:
    """
    Wraps a KafkaProducer and provides typed publish methods
    for MitreEvent and MitreSession.
    """

    def __init__(self, brokers: list[str]):
        self._producer = _make_producer(brokers)
        self._brokers = brokers
        self.publish_successes = 0
        self.publish_failures = 0
        self.last_publish_error = ""

    def _send_checked(self, topic: str, key: str, value: bytes) -> bool:
        """Best-effort Kafka send with bounded retries.

        Publish failures must not crash the MITRE analysis path. A failed record
        is logged with topic/key/attempt details and then dropped after retries
        are exhausted.
        """
        attempts = max(1, PRODUCER_SEND_RETRIES + 1)
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                future = self._producer.send(topic, key=key, value=value)
                future.get(timeout=PRODUCER_ACK_TIMEOUT)
                self.publish_successes += 1
                return True
            except Exception as e:
                last_error = e
                log.error(
                    "Kafka publish attempt failed: topic=%s key=%s attempt=%d/%d error=%s",
                    topic, key, attempt, attempts, e,
                )
                if attempt < attempts:
                    time.sleep(PRODUCER_SEND_RETRY_DELAY)

        self.publish_failures += 1
        self.last_publish_error = str(last_error) if last_error else "unknown publish failure"
        log.error(
            "Kafka publish dropped after retries: topic=%s key=%s attempts=%d error=%s",
            topic, key, attempts, self.last_publish_error,
        )
        return False

    def publish_event(self, event: MitreEvent) -> bool:
        """Publish one MitreEvent to mitre-events, keyed by session_id."""
        key = getattr(event, "session_id", "unknown-session")
        try:
            value = _serialise(event)
        except Exception as e:
            log.exception("Failed to serialise MitreEvent for session=%s: %s", key, e)
            self.publish_dead_letter({
                "source": "mitre-agent",
                "stage": "serialise_mitre_event",
                "session_id": key,
                "error": str(e),
            })
            return False

        return self._send_checked(TOPIC_MITRE_EVENTS, key=key, value=value)

    def publish_session(self, session: MitreSession) -> bool:
        """Publish one MitreSession summary to mitre-sessions, keyed by session_id."""
        key = getattr(session, "session_id", "unknown-session")
        try:
            payload = json.dumps(dataclasses.asdict(session), default=str).encode("utf-8")
        except Exception as e:
            log.exception("Failed to serialise MitreSession for session=%s: %s", key, e)
            self.publish_dead_letter({
                "source": "mitre-agent",
                "stage": "serialise_mitre_session",
                "session_id": key,
                "error": str(e),
            })
            return False

        return self._send_checked(TOPIC_MITRE_SESSIONS, key=key, value=payload)

    def publish_dead_letter(self, payload: dict) -> bool:
        """Publish a malformed/failed input record to dead-letter-events.

        This method must never crash the consumer path. If the DLQ topic or
        broker is unavailable, we log the failure and continue processing later
        Kafka records.
        """
        try:
            key = payload.get("dead_letter_id") or payload.get("session_id") or payload.get("source_topic") or "dead-letter"
            value = json.dumps(payload, default=str).encode("utf-8")
        except Exception as e:
            log.error("Failed to serialise dead-letter payload: %s", e)
            return False

        return self._send_checked(TOPIC_DEAD_LETTER, key=str(key), value=value)

    def stats(self) -> dict:
        return {
            "publish_successes": self.publish_successes,
            "publish_failures": self.publish_failures,
            "last_publish_error": self.last_publish_error,
        }

    def flush(self) -> None:
        try:
            self._producer.flush(timeout=PRODUCER_ACK_TIMEOUT)
        except TypeError:
            # Older kafka-python versions do not accept timeout.
            try:
                self._producer.flush()
            except Exception as e:
                log.error("MitreStore flush failed: %s", e)
        except Exception as e:
            log.error("MitreStore flush failed: %s", e)

    def close(self) -> None:
        self.flush()
        try:
            self._producer.close()
        except Exception as e:
            log.error("MitreStore close failed: %s", e)

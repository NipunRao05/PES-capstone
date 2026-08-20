"""
storage.py
----------
Kafka producer using kafka-python.
Publishes closed sessions and cluster results to your own Redpanda.

Two topics (both on YOUR Redpanda):
  - session-closed-events  : raw closed SessionOutput objects
  - session-profiles       : enriched with cluster_id + persona
"""

import json
import time
import logging
from dataclasses import asdict
from kafka import KafkaProducer
import config

PRODUCER_ACK_TIMEOUT = float(getattr(config, "PRODUCER_ACK_TIMEOUT_SECONDS", 10))

# Per-record publish hardening. The initial send counts as attempt 1, so the
# default of 2 retries gives 3 attempts total before a record is dropped.
PRODUCER_SEND_RETRIES = int(getattr(config, "PRODUCER_SEND_RETRIES", 2))
PRODUCER_SEND_RETRY_DELAY = float(getattr(config, "PRODUCER_SEND_RETRY_DELAY_SECONDS", 0.25))

logger = logging.getLogger(__name__)


def _make_producer(retries: int = 10, delay: int = 5) -> KafkaProducer:
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=config.OWN_REDPANDA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                acks="all",
                retries=5,
                linger_ms=10,
            )
            logger.info(f"[Storage] Connected to Redpanda at {config.OWN_REDPANDA_BOOTSTRAP}")
            return producer
        except Exception as e:
            logger.warning(f"[Storage] Attempt {attempt}/{retries} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)

    raise RuntimeError(f"[Storage] Could not connect to {config.OWN_REDPANDA_BOOTSTRAP} after {retries} attempts.")


class RedpandaSessionStore:

    def __init__(self):
        self.producer = _make_producer()
        self.publish_successes = 0
        self.publish_failures = 0
        self.last_publish_error = ""

    def _send_checked(self, topic: str, key: bytes, value: dict) -> bool:
        """Best-effort Kafka send with bounded retries.

        kafka-python's send() is asynchronous; this waits briefly for the broker
        ack so publish failures are visible, but failures never crash the session
        processing path.
        """
        attempts = max(1, PRODUCER_SEND_RETRIES + 1)
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                future = self.producer.send(topic, key=key, value=value)
                future.get(timeout=PRODUCER_ACK_TIMEOUT)
                self.publish_successes += 1
                return True
            except Exception as e:
                last_error = e
                logger.error(
                    "[Storage] Kafka publish attempt failed: topic=%s key=%s attempt=%d/%d error=%s",
                    topic, key.decode("utf-8", errors="replace") if isinstance(key, bytes) else key,
                    attempt, attempts, e,
                )
                if attempt < attempts:
                    time.sleep(PRODUCER_SEND_RETRY_DELAY)

        self.publish_failures += 1
        self.last_publish_error = str(last_error) if last_error else "unknown publish failure"
        logger.error(
            "[Storage] Kafka publish dropped after retries: topic=%s key=%s attempts=%d error=%s",
            topic, key.decode("utf-8", errors="replace") if isinstance(key, bytes) else key,
            attempts, self.last_publish_error,
        )
        return False

    def save_session(self, session_output) -> bool:
        try:
            payload = asdict(session_output)
            key = session_output.session_id.encode("utf-8")
        except Exception as e:
            session_id = getattr(session_output, "session_id", "unknown-session")
            logger.exception("[Storage] Failed to build closed-session payload for %s: %s", session_id, e)
            self.publish_dead_letter({
                "source": "session-module",
                "stage": "serialise_closed_session",
                "session_id": session_id,
                "error": str(e),
            })
            return False

        return self._send_checked(
            config.TOPIC_SESSION_CLOSED,
            key=key,
            value=payload,
        )

    def publish_profile(self, session_id: str, cluster_id: int, persona: str, original_payload: dict) -> bool:
        try:
            profile = {**original_payload, "cluster_id": cluster_id, "persona": persona}
        except Exception as e:
            logger.exception("[Storage] Failed to build session profile for %s: %s", session_id, e)
            self.publish_dead_letter({
                "source": "session-module",
                "stage": "serialise_session_profile",
                "session_id": session_id,
                "error": str(e),
            })
            return False

        return self._send_checked(
            config.TOPIC_SESSION_PROFILES,
            key=session_id.encode("utf-8"),
            value=profile,
        )

    def publish_dead_letter(self, payload: dict) -> bool:
        """Publish a malformed/failed input record to dead-letter-events.

        DLQ publishing is best-effort and must not crash the session module.
        """
        try:
            key = str(
                payload.get("dead_letter_id")
                or payload.get("session_id")
                or payload.get("source_topic")
                or "dead-letter"
            ).encode("utf-8")
            return self._send_checked(config.TOPIC_DEAD_LETTER, key=key, value=payload)
        except Exception as e:
            logger.error("[Storage] Failed to publish dead-letter event: %s", e)
            return False

    def stats(self) -> dict:
        return {
            "publish_successes": self.publish_successes,
            "publish_failures": self.publish_failures,
            "last_publish_error": self.last_publish_error,
        }

    def flush(self) -> None:
        try:
            self.producer.flush(timeout=PRODUCER_ACK_TIMEOUT)
        except TypeError:
            # Older kafka-python versions do not accept timeout.
            try:
                self.producer.flush()
            except Exception as e:
                logger.error("[Storage] Producer flush failed: %s", e)
        except Exception as e:
            logger.error("[Storage] Producer flush failed: %s", e)
        else:
            logger.info("[Storage] Producer flushed.")

    def close(self) -> None:
        self.flush()
        try:
            self.producer.close()
            logger.info("[Storage] Producer closed.")
        except Exception as e:
            logger.error("[Storage] Producer close failed: %s", e)

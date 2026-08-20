"""
clustering_worker.py
--------------------
Subscribes to session-closed-events (your own Redpanda),
runs DBSCAN + persona mapping, publishes to session-profiles.
"""

import threading
import time
import json
import logging
from datetime import datetime, timezone
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from kafka import KafkaConsumer
from persona_mapper import map_cluster_to_persona, map_sparse_session_to_persona
from metrics import cluster_sessions_total
import config

logger = logging.getLogger(__name__)


def _make_consumer(retries: int = 10, delay: int = 5) -> KafkaConsumer:
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                config.TOPIC_SESSION_CLOSED,
                bootstrap_servers=config.OWN_REDPANDA_BOOTSTRAP,
                group_id=f"{config.CONSUMER_GROUP}-clustering",
                auto_offset_reset=config.CONSUMER_AUTO_OFFSET_RESET,
                enable_auto_commit=True,
            )
            logger.info(f"[Clustering] Subscribed to {config.TOPIC_SESSION_CLOSED} on {config.OWN_REDPANDA_BOOTSTRAP}")
            return consumer
        except Exception as e:
            logger.warning(f"[Clustering] Attempt {attempt}/{retries} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)

    raise RuntimeError(f"[Clustering] Could not connect after {retries} attempts.")


class ClusteringWorker(threading.Thread):

    def __init__(self, storage):
        super().__init__(daemon=True)
        self.storage = storage
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    @staticmethod
    def _payload_preview(value) -> str:
        if isinstance(value, bytes):
            return value[:config.DEAD_LETTER_MAX_RAW_BYTES].decode("utf-8", errors="replace")
        try:
            text = json.dumps(value, default=str)
        except Exception:
            text = str(value)
        return text[:config.DEAD_LETTER_MAX_RAW_BYTES]

    def _publish_dead_letter(self, message, stage: str, error, raw_payload=None) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "session-module-clustering",
            "source_topic": getattr(message, "topic", ""),
            "source_partition": getattr(message, "partition", None),
            "source_offset": getattr(message, "offset", None),
            "stage": stage,
            "error": str(error),
            "raw_payload": self._payload_preview(message.value if raw_payload is None else raw_payload),
        }
        payload["dead_letter_id"] = (
            f"{payload['service']}:{payload['source_topic']}:"
            f"{payload['source_partition']}:{payload['source_offset']}"
        )
        try:
            self.storage.publish_dead_letter(payload)
        except Exception:
            logger.error("[Clustering] Dead-letter publish failed", exc_info=True)

    def _decode_session_record(self, message):
        try:
            raw = json.loads(message.value.decode("utf-8"))
        except Exception as e:
            logger.warning(
                "[Clustering] Malformed Kafka JSON: topic=%s partition=%s offset=%s error=%s",
                getattr(message, "topic", ""), getattr(message, "partition", None), getattr(message, "offset", None), e,
            )
            self._publish_dead_letter(message, "parse_session_closed", e)
            return None
        if raw is None:
            self._publish_dead_letter(message, "validate_session_closed", "expected JSON object, got null", raw_payload=None)
            return None
        if not isinstance(raw, dict):
            self._publish_dead_letter(message, "validate_session_closed", "expected JSON object", raw_payload=raw)
            return None
        if not raw.get("session_id"):
            self._publish_dead_letter(message, "validate_session_closed", "missing required field: session_id", raw_payload=raw)
            return None
        return raw

    def run(self):
        consumer = _make_consumer()
        buffer = []
        last_flush = time.time()

        try:
            while not self._stop_event.is_set():
                try:
                    records = consumer.poll(timeout_ms=1000)
                except Exception as e:
                    logger.warning("[Clustering] Consumer poll failed: %s", e)
                    time.sleep(2)
                    continue

                for tp, messages in records.items():
                    for message in messages:
                        record = self._decode_session_record(message)
                        if record is not None:
                            buffer.append(record)

                now = time.time()
                batch_ready = len(buffer) >= config.CLUSTER_BATCH_SIZE
                interval_due = (now - last_flush) >= config.CLUSTER_INTERVAL_SECONDS

                if (batch_ready or interval_due) and len(buffer) >= config.DBSCAN_MIN_SAMPLES:
                    self._process_batch(buffer)
                    buffer = []
                    last_flush = now
                elif interval_due and len(buffer) > 0:
                    logger.info(
                        f"[Clustering] Only {len(buffer)} sessions in buffer; "
                        "publishing rule-based sparse profiles instead of waiting forever."
                    )
                    self._publish_sparse_profiles(buffer)
                    buffer = []
                    last_flush = now
        finally:
            # Do not drop a final partial batch on shutdown. In demos, this is
            # often the only evidence that should feed MITRE/scaling.
            if buffer:
                if len(buffer) >= config.DBSCAN_MIN_SAMPLES:
                    self._process_batch(buffer)
                else:
                    self._publish_sparse_profiles(buffer)
            consumer.close()
            logger.info("[Clustering] Worker stopped.")

    def _process_batch(self, batch: list):
        # Bug 2 fix — empty batch guard
        if not batch:
            logger.warning("[Clustering] _process_batch called with empty batch, skipping.")
            return

        try:
            logger.info(f"[Clustering] Processing batch of {len(batch)} sessions...")

            session_ids = []
            features = []

            for record in batch:
                session_ids.append(record["session_id"])
                features.append([
                    record.get("entropy",             0.0),
                    record.get("failed_auth",         0),
                    record.get("depth_score",         0.0),
                    record.get("query_count",         0),
                    record.get("duration",            0.0),
                    # Gap 1 — timing features now in feature vector
                    record.get("timing_variance_ms",  0.0),
                    record.get("queries_per_second",  0.0),
                ])

            X = np.array(features)
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            clustering = DBSCAN(
                eps=config.DBSCAN_EPS,
                min_samples=config.DBSCAN_MIN_SAMPLES,
            ).fit(X_scaled)

            labels = clustering.labels_.tolist()

            for i, (session_id, label) in enumerate(zip(session_ids, labels)):
                persona = map_cluster_to_persona(int(label), features[i])
                self.storage.publish_profile(
                    session_id=session_id,
                    cluster_id=int(label),   # explicit int() cast — numpy.int64 safe
                    persona=persona,
                    original_payload=batch[i],
                )
                cluster_sessions_total.labels(cluster_id=str(label)).inc()

            logger.info(f"[Clustering] Done — {len(batch)} sessions, {len(set(labels))} clusters found.")

        except Exception as e:
            logger.error(f"[Clustering] Error processing batch: {e}", exc_info=True)

    def _publish_sparse_profiles(self, batch: list):
        """Publish profiles for small demo batches where DBSCAN cannot run yet.

        Without this fallback, one or two attacker sessions can sit in the
        clustering buffer forever and the MITRE/scaling layers never receive a
        session-profile event. cluster_id=-1 means "not clustered"; persona is
        still derived with the same rule-based mapper used after DBSCAN.
        """
        for record in batch:
            try:
                features = [
                    record.get("entropy",             0.0),
                    record.get("failed_auth",         0),
                    record.get("depth_score",         0.0),
                    record.get("query_count",         0),
                    record.get("duration",            0.0),
                    record.get("timing_variance_ms",  0.0),
                    record.get("queries_per_second",  0.0),
                ]
                persona = map_sparse_session_to_persona(features)
                self.storage.publish_profile(
                    session_id=record["session_id"],
                    cluster_id=-1,
                    persona=persona,
                    original_payload=record,
                )
                cluster_sessions_total.labels(cluster_id="-1").inc()
            except Exception as e:
                logger.error(f"[Clustering] Failed to publish sparse profile: {e}", exc_info=True)

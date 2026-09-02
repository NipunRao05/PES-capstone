import importlib.util
import sys
import threading
import types
import unittest
from unittest.mock import patch


def _install_test_dependency_stubs():
    """Allow pure unit tests on hosts where only the container has service deps."""
    if importlib.util.find_spec("redis") is None:
        module = types.ModuleType("redis")
        module.Redis = object
        sys.modules["redis"] = module
    if importlib.util.find_spec("requests") is None:
        module = types.ModuleType("requests")
        module.get = module.post = lambda *_args, **_kwargs: None
        sys.modules["requests"] = module
    if importlib.util.find_spec("kafka") is None:
        module = types.ModuleType("kafka")
        module.KafkaConsumer = object
        sys.modules["kafka"] = module
    if importlib.util.find_spec("pydantic") is None:
        module = types.ModuleType("pydantic")
        module.BaseModel = object
        module.Field = lambda default=None, **_kwargs: default
        sys.modules["pydantic"] = module
    if importlib.util.find_spec("fastapi") is None:
        module = types.ModuleType("fastapi")

        class _FastAPI:
            def __init__(self, *_args, **_kwargs):
                pass

            def get(self, *_args, **_kwargs):
                return lambda function: function

            def post(self, *_args, **_kwargs):
                return lambda function: function

        class _HTTPException(Exception):
            def __init__(self, status_code, detail):
                super().__init__(detail)
                self.status_code = status_code
                self.detail = detail

        module.FastAPI = _FastAPI
        module.HTTPException = _HTTPException
        module.Query = lambda default=None, **_kwargs: default
        sys.modules["fastapi"] = module


_install_test_dependency_stubs()

from main import (
    AdaptiveEvidencePoller,
    EvidenceRepository,
    bounded_text,
    canonical_timestamp,
    decode_json_object,
    kafka_event_id,
    redact_query,
    sanitize_artifact,
    stable_id,
    timestamp_score,
    validate_artifact_link,
)


class MemoryRedis:
    def __init__(self):
        self.values = {}
        self.hashes = {}
        self.lists = {}
        self.sets = {}
        self.sorted_sets = {}

    def pipeline(self, transaction=False):
        return self

    def execute(self):
        return []

    def expire(self, key, _ttl):
        return int(key in self.values or key in self.hashes or key in self.lists or key in self.sets)

    def setnx(self, key, value):
        if key in self.values:
            return 0
        self.values[key] = str(value)
        return 1

    def get(self, key):
        return self.values.get(key)

    def hset(self, key, field=None, value=None, mapping=None):
        target = self.hashes.setdefault(key, {})
        if mapping is not None:
            target.update({str(k): str(v) for k, v in mapping.items()})
        elif field is not None:
            target[str(field)] = str(value)
        return 1

    def hsetnx(self, key, field, value):
        target = self.hashes.setdefault(key, {})
        if field in target:
            return 0
        target[field] = str(value)
        return 1

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def zadd(self, key, mapping):
        self.sorted_sets.setdefault(key, {}).update(mapping)
        return len(mapping)

    def zscore(self, key, member):
        return self.sorted_sets.get(key, {}).get(member)

    def zrevrange(self, key, start, end):
        ordered = sorted(
            self.sorted_sets.get(key, {}).items(), key=lambda item: item[1], reverse=True
        )
        return [item[0] for item in ordered[start:end + 1]]

    def sadd(self, key, value):
        target = self.sets.setdefault(key, set())
        if value in target:
            return 0
        target.add(value)
        return 1

    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    def ltrim(self, key, start, end):
        values = self.lists.setdefault(key, [])
        start = max(0, len(values) + start) if start < 0 else start
        end = len(values) + end if end < 0 else end
        self.lists[key] = values[start:end + 1]
        return True

    def lrange(self, key, start, end):
        values = self.lists.get(key, [])
        end = len(values) - 1 if end == -1 else end
        return values[start:end + 1]


class EvidenceSafetyTests(unittest.TestCase):
    def test_query_literals_are_redacted(self):
        query = "SELECT * FROM users WHERE email='person@example.test' AND token=secret-value"
        redacted = redact_query(query)
        self.assertNotIn("person@example.test", redacted)
        self.assertNotIn("secret-value", redacted)
        self.assertIn("'[REDACTED]'", redacted)
        self.assertIn("token=[REDACTED]", redacted)

    def test_identified_by_password_is_redacted(self):
        redacted = redact_query("CREATE USER demo IDENTIFIED BY 'unsafe-password'")
        self.assertNotIn("unsafe-password", redacted)
        self.assertIn("IDENTIFIED BY [REDACTED]", redacted)

    def test_spaced_secret_and_long_numbers_are_redacted(self):
        query = "UPDATE users SET password='two word secret' WHERE card_number=4111111111111111"
        redacted = redact_query(query)
        self.assertNotIn("two word secret", redacted)
        self.assertNotIn("4111111111111111", redacted)
        self.assertIn("[REDACTED_NUMBER]", redacted)

    def test_text_is_bounded_and_nul_removed(self):
        self.assertEqual(bounded_text("abc\x00def", 5), "abcde")

    def test_stable_id_is_deterministic(self):
        self.assertEqual(stable_id("a", 1), stable_id("a", 1))
        self.assertNotEqual(stable_id("a", 1), stable_id("a", 2))

    def test_timestamp_score_is_event_grounded_and_future_bounded(self):
        older = timestamp_score("2026-08-20T00:00:00Z")
        newer = timestamp_score("2026-08-21T00:00:00Z")
        self.assertLess(older, newer)
        self.assertLessEqual(timestamp_score("2999-01-01T00:00:00Z"), __import__("time").time() + 301)

    def test_kafka_event_id_preserves_upstream_identity_across_offsets(self):
        payload = {"event_id": "mitre:event-1"}
        first = kafka_event_id(payload, "mitre-events", 0, 10, "session-1")
        replay = kafka_event_id(payload, "mitre-events", 0, 99, "session-1")
        self.assertEqual(first, "mitre:event-1")
        self.assertEqual(first, replay)

    def test_kafka_event_id_falls_back_to_source_coordinates(self):
        first = kafka_event_id({}, "mitre-events", 0, 10, "session-1")
        replay = kafka_event_id({}, "mitre-events", 0, 11, "session-1")
        self.assertNotEqual(first, replay)

    def test_malformed_kafka_value_is_skipped_without_raising(self):
        self.assertIsNone(decode_json_object(b"{not-json"))
        self.assertIsNone(decode_json_object(b"[1, 2, 3]"))
        self.assertEqual(decode_json_object(b'{"session_id":"safe-1"}'), {"session_id": "safe-1"})

    def test_structured_artifacts_are_bounded_redacted_and_session_scoped(self):
        sanitized = sanitize_artifact({
            "session_id": "session-20",
            "source_ip": "192.0.2.10",
            "query": "SELECT * FROM users WHERE token='unsafe'",
        })
        self.assertEqual(sanitized["source_ip"], "[REDACTED]")
        self.assertNotIn("unsafe", sanitized["query"])
        features = sanitize_artifact({
            "credential_keyword_count": 3,
            "bounded_credential_keyword_count": 2,
            "credential_signal_present": True,
            "credential_value": "actual-secret",
            "api_token": "actual-token",
        })
        self.assertEqual(features["credential_keyword_count"], 3)
        self.assertEqual(features["bounded_credential_keyword_count"], 2)
        self.assertIs(features["credential_signal_present"], True)
        self.assertEqual(features["credential_value"], "[REDACTED]")
        self.assertEqual(features["api_token"], "[REDACTED]")
        with self.assertRaisesRegex(ValueError, "cross-session"):
            validate_artifact_link(
                "session-20", "replay_result", "RP-1",
                {"session_id": "session-20", "nested": {"session_id": "other"}},
            )

    def test_timestamps_are_normalized_sorted_and_traps_are_not_double_counted(self):
        repository = EvidenceRepository(MemoryRedis())
        session_id = "ordered-evidence"
        repository.ingest_kafka(
            "mysql-session-events",
            {"event_id": "later", "session_id": session_id, "timestamp": "1788000001", "event_type": "session_end"},
            0, 1,
        )
        repository.ingest_kafka(
            "mysql-session-events",
            {"event_id": "earlier", "session_id": session_id, "timestamp": "1788000000", "event_type": "session_start"},
            0, 2,
        )
        trap = {
            "session_id": session_id, "timestamp": "2026-08-28T00:00:02+00:00",
            "technique_id": "T1555", "trap_triggered": True,
        }
        repository.ingest_kafka("mitre-events", {**trap, "event_id": "detail"}, 0, 3)
        repository.ingest_kafka("mitre-sessions", {**trap, "event_id": "summary"}, 0, 4)
        record = repository.get_session(session_id)
        self.assertLessEqual(
            timestamp_score(record["connection_events"][0]["timestamp"]),
            timestamp_score(record["connection_events"][1]["timestamp"]),
        )
        self.assertTrue(all(item["timestamp"].endswith("Z") for item in record["connection_events"]))
        self.assertEqual(len(record["trap_events"]), 1)
        self.assertEqual(record["trap_events"][0]["provenance"], "detailed")
        self.assertEqual(
            sum(bool(item["logical_trap_interaction"]) for item in record["mitre_events"]), 1
        )
        self.assertEqual(canonical_timestamp("1788000000"), "2026-08-29T10:40:00Z")

    def test_phase20_end_to_end_trace_contract(self):
        repository = EvidenceRepository(MemoryRedis())
        session_id = "phase20-trace"
        repository.ingest_kafka(
            "mysql-session-events",
            {
                "event_id": "connection-1", "session_id": session_id,
                "event_type": "session_start", "protocol": "mysql",
                "timestamp": "2026-08-28T00:00:00Z", "client_ip": "192.0.2.8",
            },
            0, 1,
        )
        repository.ingest_kafka(
            "mysql-query-events",
            {
                "event_id": "query-1", "session_id": session_id,
                "protocol": "mysql", "timestamp": "2026-08-28T00:00:01Z",
                "query_raw": "SELECT * FROM backup WHERE token='fictional'",
                "query_normalized": "select * from backup where token=?",
                "fingerprint": "fp-1", "outcome_verified": True,
                "success": True, "authority": "deception", "bytes_out": 128,
            },
            0, 2,
        )
        repository.ingest_kafka(
            "mitre-events",
            {
                "event_id": "mitre-1", "session_id": session_id,
                "timestamp": "2026-08-28T00:00:02Z", "technique_id": "T1555",
                "risk_score": 0.8, "risk_level": "high", "trap_triggered": True,
            },
            0, 3,
        )
        repository.ingest_scale_event({
            "session_id": session_id, "timestamp": "2026-08-28T00:00:03Z",
            "replica_target": 2, "raw_score": 0.8,
        })
        repository.ingest_ai_report({
            "session_id": session_id, "report_id": "AI-1",
            "generated_at": "2026-08-28T00:00:04Z", "summary": "Synthetic trace.",
        })
        artifacts = (
            ("session_state", "SS-1", {"session_id": session_id, "strategy_id": "D2"}),
            ("strategy_decision", "SD-1", {"session_id": session_id, "decision_id": "SD-1"}),
            ("strategy_reward", "RW-1", {"session_id": session_id, "status": "COMPLETE"}),
            ("replay_result", "RP-1", {"session_id": session_id, "replay_id": "RP-1"}),
            ("hardening_finding", "HR-1", {"session_id": session_id, "hardening_report_id": "HR-1"}),
            ("learning_analysis", "LA-1", {"session_id": session_id, "analysis_id": "LA-1"}),
            ("proposal", "P-1", {"session_id": session_id, "proposal_id": "P-1"}),
            ("analyst_report", "AR-1", {"session_id": session_id, "report_id": "AR-1"}),
        )
        for kind, identity, payload in artifacts:
            self.assertTrue(repository.ingest_artifact(session_id, kind, identity, payload))

        record = repository.get_session(session_id)
        self.assertEqual(record["schema_version"], 2)
        self.assertTrue(record["trace_id"].startswith("TR-"))
        self.assertTrue(record["responses"][0]["outcome_verified"])
        self.assertEqual(record["proposal_ids"], ["P-1"])
        self.assertEqual(record["analyst_report_ids"], ["AR-1"])
        self.assertTrue(record["trace"]["complete"])
        self.assertEqual(record["trace"]["missing"], [])

    def test_artifact_updates_are_versioned_and_exact_replays_are_idempotent(self):
        repository = EvidenceRepository(MemoryRedis())
        first = {"session_id": "s-1", "status": "PENDING"}
        final = {"session_id": "s-1", "status": "COMPLETE"}
        self.assertTrue(repository.ingest_artifact("s-1", "strategy_reward", "RW-1", first))
        self.assertFalse(repository.ingest_artifact("s-1", "strategy_reward", "RW-1", first))
        self.assertTrue(repository.ingest_artifact("s-1", "strategy_reward", "RW-1", final))
        self.assertEqual(len(repository.get_session("s-1")["strategy_rewards"]), 2)

    def test_polling_old_artifacts_does_not_make_old_session_newest(self):
        repository = EvidenceRepository(MemoryRedis())
        repository.ingest_artifact(
            "new", "session_state", "SS-new", {"session_id": "new"},
            "2026-08-28T10:00:00Z",
        )
        repository.ingest_artifact(
            "old", "session_state", "SS-old", {"session_id": "old"},
            "2026-08-20T10:00:00Z",
        )
        repository.ingest_artifact(
            "old", "session_state", "SS-old-2", {"session_id": "old", "query_count": 1},
            "2026-08-20T10:00:01Z",
        )
        self.assertEqual([item["session_id"] for item in repository.list_sessions(2)], ["new", "old"])
        record = repository.get_session("new")
        self.assertEqual(record["first_seen"], "2026-08-28T10:00:00Z")
        self.assertEqual(record["last_seen"], "2026-08-28T10:00:00Z")

    def test_first_and_last_seen_are_monotonic_for_out_of_order_artifacts(self):
        repository = EvidenceRepository(MemoryRedis())
        repository.ingest_artifact(
            "ordered", "session_state", "middle", {"session_id": "ordered"},
            "2026-08-25T10:00:00Z",
        )
        repository.ingest_artifact(
            "ordered", "strategy_decision", "older", {"session_id": "ordered"},
            "2026-08-25T09:00:00Z",
        )
        repository.ingest_artifact(
            "ordered", "strategy_reward", "newer", {"session_id": "ordered"},
            "2026-08-25T11:00:00Z",
        )
        record = repository.get_session("ordered")
        self.assertEqual(record["first_seen"], "2026-08-25T09:00:00Z")
        self.assertEqual(record["last_seen"], "2026-08-25T11:00:00Z")

    def test_adaptive_poller_collects_state_decision_and_reward_asynchronously(self):
        class Response:
            def __init__(self, payload, status_code=200):
                self.payload = payload
                self.status_code = status_code

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise RuntimeError(f"HTTP {self.status_code}")

            def json(self):
                return self.payload

        session_id = "adaptive-trace"
        decision_id = "SD-adaptive"

        def get(url, **_kwargs):
            if "/state/sessions" in url:
                return Response({"sessions": [{"session_id": session_id, "strategy_id": "D2"}]})
            if "/telemetry/decisions" in url:
                return Response({"records": [{
                    "decision": {
                        "session_id": session_id, "decision_id": decision_id,
                        "timestamp": "2026-08-28T00:00:00Z",
                    },
                    "outcome": {"session_id": session_id, "decision_id": decision_id},
                }]})
            if f"/reward/decision/{decision_id}" in url:
                return Response({
                    "session_id": session_id, "decision_id": decision_id,
                    "status": "COMPLETE",
                })
            return Response({}, 404)

        repository = EvidenceRepository(MemoryRedis())
        poller = AdaptiveEvidencePoller(repository, threading.Event())
        with patch("main.requests.get", side_effect=get):
            poller.collect_once()
            poller.collect_once()
        record = repository.get_session(session_id)
        self.assertEqual(len(record["session_states"]), 1)
        self.assertEqual(len(record["strategy_decisions"]), 1)
        self.assertEqual(len(record["strategy_rewards"]), 1)
        self.assertNotIn("outcome", record["strategy_decisions"][0]["payload"])


if __name__ == "__main__":
    unittest.main()

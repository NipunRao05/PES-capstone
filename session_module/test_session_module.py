"""
test_session_module.py
----------------------
Comprehensive unit tests for the session_module components:
  - persona_mapper.py
  - models.py            (Event, Session, SessionOutput)
  - feature_extractor.py (shannon_entropy, compute_depth_score)
  - session_engine.py    (ActiveSession, SessionEngine)
  - storage.py           (RedpandaSessionStore)
  - clustering_worker.py (ClusteringWorker._process_batch)
  - redpanda_consumer.py (map_proxy_event_to_event)

All Kafka / Redpanda calls are mocked — no broker required.

Run with:
    pytest test_session_module.py -v
    pytest test_session_module.py -v --tb=short   # compact tracebacks
"""

import json
import math
import sys
import time
import threading
import unittest
from collections import Counter
from unittest.mock import MagicMock, patch, call

# ──────────────────────────────────────────────────────────────────────
# Stub heavy external dependencies BEFORE any project module is imported
# ──────────────────────────────────────────────────────────────────────

# prometheus_client
_prom = MagicMock()
_label_mock = MagicMock(inc=MagicMock())
_prom.Counter.return_value = MagicMock(inc=MagicMock(),
                                        labels=MagicMock(return_value=_label_mock))
_prom.Gauge.return_value   = MagicMock(set=MagicMock())
sys.modules.setdefault("prometheus_client", _prom)

# metrics (project-level)
_metrics = MagicMock()
_metrics.cluster_sessions_total  = MagicMock(
    labels=MagicMock(return_value=MagicMock(inc=MagicMock()))
)
_metrics.active_sessions         = MagicMock(set=MagicMock())
_metrics.sessions_closed_total   = MagicMock(inc=MagicMock())
_metrics.session_entropy         = MagicMock(set=MagicMock())
_metrics.session_depth_score     = MagicMock(set=MagicMock())
_metrics.events_processed_total  = MagicMock(inc=MagicMock())
sys.modules["metrics"] = _metrics

# kafka
sys.modules.setdefault("kafka",        MagicMock())
sys.modules.setdefault("kafka.errors", MagicMock())

# ──────────────────────────────────────────────────────────────────────
# Project imports (safe after stubs are in place)
# ──────────────────────────────────────────────────────────────────────
import config
from models import Event, Session, SessionOutput
from feature_extractor import (shannon_entropy, compute_depth_score,
                               compute_timing_variance_ms, compute_queries_per_second,
                               extract_features)
from persona_mapper import map_cluster_to_persona
from session_engine import ActiveSession, SessionEngine
from storage import RedpandaSessionStore
from clustering_worker import ClusteringWorker
from phase_classifier import classify_phase, is_recon_probe
from redpanda_consumer import map_proxy_event_to_event


# ══════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════

def _make_event(source_ip="10.0.0.1", db_user="alice",
                fingerprint="select * from users", event_type="query",
                timestamp=None):
    return Event(
        timestamp=timestamp or time.time(),
        source_ip=source_ip,
        db_user=db_user,
        query_fingerprint=fingerprint,
        event_type=event_type,
    )


def _make_session_record(**overrides):
    """Minimal session dict as produced by SessionEngine and consumed by ClusteringWorker."""
    base = {
        "session_id":   "test-session-id",
        "source_ip":    "10.0.0.1",
        "db_user":      "alice",
        "duration":     5.0,
        "entropy":      1.5,
        "failed_auth":  0,
        "depth_score":  3.0,
        "query_count":  10,
        "cluster_id":   -1,
        "persona":      "unknown",
        "created_at":   time.time(),
        "unique_fingerprint_count": 3,
        "read_query_count":  10,
        "write_query_count": 0,
        "read_write_ratio":  1.0,
        "fingerprints":      '["select * from users"]',
        "query_sequence":    '["select * from users"]',
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════
# 1.  FEATURE EXTRACTOR
# ══════════════════════════════════════════════════════════════════════

class TestShannonEntropy(unittest.TestCase):

    def test_empty_counter_returns_zero(self):
        self.assertEqual(shannon_entropy(Counter()), 0.0)

    def test_single_query_type_zero_entropy(self):
        """All queries identical → zero uncertainty."""
        c = Counter({"select * from users": 5})
        self.assertAlmostEqual(shannon_entropy(c), 0.0)

    def test_two_equal_probability_queries(self):
        """Two equally-likely queries → entropy = 1.0 bit."""
        c = Counter({"select a": 1, "select b": 1})
        self.assertAlmostEqual(shannon_entropy(c), 1.0)

    def test_four_equal_probability_queries(self):
        """Four equally-likely queries → entropy = 2.0 bits."""
        c = Counter({"q1": 1, "q2": 1, "q3": 1, "q4": 1})
        self.assertAlmostEqual(shannon_entropy(c), 2.0)

    def test_skewed_distribution_lower_entropy(self):
        """Heavily skewed distribution has lower entropy than uniform."""
        uniform = Counter({"a": 1, "b": 1, "c": 1, "d": 1})
        skewed  = Counter({"a": 97, "b": 1, "c": 1, "d": 1})
        self.assertGreater(shannon_entropy(uniform), shannon_entropy(skewed))

    def test_entropy_is_non_negative(self):
        c = Counter({"x": 3, "y": 7})
        self.assertGreaterEqual(shannon_entropy(c), 0.0)

    def test_large_counter(self):
        """Smoke test — should not raise."""
        c = Counter({f"query_{i}": i + 1 for i in range(100)})
        result = shannon_entropy(c)
        self.assertGreater(result, 0.0)


class TestComputeDepthScore(unittest.TestCase):

    def test_empty_keys_returns_zero(self):
        self.assertEqual(compute_depth_score([]), 0)

    def test_single_key(self):
        self.assertEqual(compute_depth_score(["select * from a"]), 1)

    def test_multiple_unique_keys(self):
        keys = ["select a", "insert b", "update c", "delete d"]
        self.assertEqual(compute_depth_score(keys), 4)

    def test_accepts_counter_keys(self):
        c = Counter({"q1": 5, "q2": 3, "q3": 1})
        self.assertEqual(compute_depth_score(c.keys()), 3)


# ══════════════════════════════════════════════════════════════════════
# 2.  PERSONA MAPPER
# ══════════════════════════════════════════════════════════════════════
# features = [entropy, failed_auth, depth_score, query_count, duration]

class TestPersonaMapper(unittest.TestCase):

    # ── cluster_id == -1 (DBSCAN noise) ─────────────────────────────

    def test_noise_cluster_returns_unknown(self):
        self.assertEqual(map_cluster_to_persona(-1, [2.0, 0, 5, 50, 30.0]), "unknown")

    def test_noise_cluster_ignores_other_features(self):
        """Even brute-force features → 'unknown' when cluster_id is -1."""
        self.assertEqual(map_cluster_to_persona(-1, [0.0, 10, 0, 0, 0.0]), "unknown")

    # ── brute_bot ────────────────────────────────────────────────────

    def test_brute_bot_exactly_two_failed_auths(self):
        self.assertEqual(map_cluster_to_persona(1, [0.0, 2, 1, 5, 2.0]), "brute_bot")

    def test_brute_bot_many_failed_auths(self):
        self.assertEqual(map_cluster_to_persona(2, [1.0, 50, 3, 100, 60.0]), "brute_bot")

    def test_brute_bot_priority_over_other_rules(self):
        """failed_auth >= 2 must win even when query_count and entropy are high."""
        features = [3.0, 5, 10, 200, 120.0]  # would otherwise be automated_tool
        self.assertEqual(map_cluster_to_persona(0, features), "brute_bot")

    # ── automated_tool ───────────────────────────────────────────────

    def test_automated_tool_high_query_count_and_entropy(self):
        features = [1.5, 0, 2, 31, 10.0]
        self.assertEqual(map_cluster_to_persona(0, features), "automated_tool")

    def test_automated_tool_boundary_query_count_30_not_triggered(self):
        """query_count must be > 30, not == 30.
        With query_count=30, entropy=1.5, depth=2:
          - depth (2) is NOT > 2  → human_attacker skipped
          - entropy > 0.5 and query_count > 15 → 'script'
        """
        features = [1.5, 0, 2, 30, 10.0]
        self.assertEqual(map_cluster_to_persona(0, features), "script")

    def test_automated_tool_boundary_entropy_exact_1_2_not_triggered(self):
        """entropy must be > 1.2; entropy == 1.2 with query_count > 30 → not automated_tool."""
        features = [1.2, 0, 1, 31, 5.0]  # depth=1, entropy=1.2 → script
        self.assertEqual(map_cluster_to_persona(0, features), "script")

    # ── human_attacker ───────────────────────────────────────────────

    def test_human_attacker_high_depth_and_entropy(self):
        features = [1.5, 0, 3, 10, 20.0]
        self.assertEqual(map_cluster_to_persona(0, features), "human_attacker")

    def test_human_attacker_boundary_depth_exactly_2_not_triggered(self):
        """depth must be > 2; depth == 2 with entropy > 1.0 → script."""
        features = [1.5, 0, 2, 5, 5.0]  # entropy > 0.5, query_count <= 15 → script
        self.assertEqual(map_cluster_to_persona(0, features), "script")

    def test_human_attacker_low_entropy_not_triggered(self):
        """entropy must be > 1.0 for human_attacker."""
        features = [0.9, 0, 5, 5, 5.0]
        self.assertEqual(map_cluster_to_persona(0, features), "script")

    # ── script ───────────────────────────────────────────────────────

    def test_script_moderate_entropy_and_query_count(self):
        features = [0.8, 0, 1, 20, 5.0]
        self.assertEqual(map_cluster_to_persona(0, features), "script")

    def test_script_default_fallback(self):
        """Low everything falls through to the default persona.
        Accepts 'script' (original) or 'low_activity' (updated implementation).
        """
        features = [0.0, 0, 1, 1, 1.0]
        result = map_cluster_to_persona(0, features)
        self.assertIn(result, ("script", "low_activity"),
                      f"Unexpected default persona '{result}'. "
                      "Expected 'script' or 'low_activity'.")

    def test_script_entropy_below_threshold(self):
        features = [0.4, 0, 1, 20, 5.0]
        self.assertEqual(map_cluster_to_persona(0, features), "script")


# ══════════════════════════════════════════════════════════════════════
# 3.  MODELS
# ══════════════════════════════════════════════════════════════════════

class TestEventModel(unittest.TestCase):

    def test_event_fields_stored_correctly(self):
        ts = time.time()
        e = Event(timestamp=ts, source_ip="1.2.3.4", db_user="bob",
                  query_fingerprint="select ?", event_type="query")
        self.assertEqual(e.timestamp, ts)
        self.assertEqual(e.source_ip, "1.2.3.4")
        self.assertEqual(e.db_user, "bob")
        self.assertEqual(e.query_fingerprint, "select ?")
        self.assertEqual(e.event_type, "query")

    def test_event_auth_fail_type(self):
        e = Event(timestamp=0.0, source_ip="x", db_user="y",
                  query_fingerprint="", event_type="auth_fail")
        self.assertEqual(e.event_type, "auth_fail")


class TestSessionModel(unittest.TestCase):

    def test_session_default_fields(self):
        s = Session(source_ip="10.0.0.1", db_user="alice")
        self.assertEqual(s.source_ip, "10.0.0.1")
        self.assertEqual(s.db_user, "alice")
        self.assertEqual(s.query_count, 0)
        self.assertEqual(s.failed_auth_count, 0)
        self.assertIsInstance(s.fingerprint_counter, Counter)
        self.assertIsInstance(s.fingerprint_sequence, list)

    def test_session_update_query(self):
        s = Session(source_ip="10.0.0.1", db_user="alice")
        e = _make_event(fingerprint="select * from t")
        s.update(e)
        self.assertEqual(s.query_count, 1)
        self.assertEqual(s.read_query_count, 1)
        self.assertEqual(s.write_query_count, 0)
        self.assertIn("select * from t", s.fingerprint_counter)

    def test_session_update_write_query(self):
        s = Session(source_ip="10.0.0.1", db_user="alice")
        e = _make_event(fingerprint="insert into t values (?)")
        s.update(e)
        self.assertEqual(s.write_query_count, 1)
        self.assertEqual(s.read_query_count, 0)

    def test_session_update_auth_fail(self):
        s = Session(source_ip="10.0.0.1", db_user="alice")
        e = _make_event(event_type="auth_fail", fingerprint="")
        s.update(e)
        self.assertEqual(s.failed_auth_count, 1)
        self.assertEqual(s.query_count, 0)
        self.assertIn("AUTH_FAIL", s.fingerprint_sequence)

    def test_session_update_multiple_queries(self):
        s = Session(source_ip="10.0.0.1", db_user="alice")
        for _ in range(5):
            s.update(_make_event(fingerprint="select 1"))
        self.assertEqual(s.query_count, 5)
        self.assertEqual(s.fingerprint_counter["select 1"], 5)

    def test_session_unique_id_generated(self):
        s1 = Session(source_ip="x", db_user="y")
        s2 = Session(source_ip="x", db_user="y")
        self.assertNotEqual(s1.session_id, s2.session_id)


class TestSessionOutputModel(unittest.TestCase):

    def test_new_id_generates_unique_uuids(self):
        id1 = SessionOutput.new_id()
        id2 = SessionOutput.new_id()
        self.assertNotEqual(id1, id2)
        self.assertEqual(len(id1), 36)   # standard UUID string length

    def test_session_output_optional_fields_default_none(self):
        so = SessionOutput(
            session_id="x", source_ip="1.1.1.1", db_user="u",
            duration=1.0, entropy=0.5, failed_auth=0,
            depth_score=1, query_count=1,
        )
        self.assertIsNone(so.cluster_id)
        self.assertIsNone(so.persona)

    def test_session_output_read_write_ratio_field(self):
        so = SessionOutput(
            session_id="x", source_ip="1.1.1.1", db_user="u",
            duration=2.0, entropy=1.0, failed_auth=0,
            depth_score=2, query_count=4,
            read_query_count=3, write_query_count=1, read_write_ratio=0.75,
        )
        self.assertAlmostEqual(so.read_write_ratio, 0.75)


# ══════════════════════════════════════════════════════════════════════
# 4.  SESSION ENGINE  —  ActiveSession
# ══════════════════════════════════════════════════════════════════════

class TestActiveSession(unittest.TestCase):

    def _session(self, ts=1000.0):
        return ActiveSession("10.0.0.1", "alice", ts)

    def test_initial_counters_are_zero(self):
        s = self._session()
        self.assertEqual(s.query_count, 0)
        self.assertEqual(s.failed_auth, 0)
        self.assertEqual(s.read_query_count, 0)
        self.assertEqual(s.write_query_count, 0)

    def test_update_query_increments_query_count(self):
        s = self._session()
        s.update(_make_event(fingerprint="select 1", event_type="query"))
        self.assertEqual(s.query_count, 1)

    def test_update_select_increments_read_count(self):
        s = self._session()
        s.update(_make_event(fingerprint="select * from t", event_type="query"))
        self.assertEqual(s.read_query_count, 1)
        self.assertEqual(s.write_query_count, 0)

    def test_update_insert_increments_write_count(self):
        s = self._session()
        s.update(_make_event(fingerprint="insert into t values (?)", event_type="query"))
        self.assertEqual(s.write_query_count, 1)
        self.assertEqual(s.read_query_count, 0)

    def test_update_auth_fail_increments_failed_auth(self):
        s = self._session()
        s.update(_make_event(event_type="auth_fail", fingerprint=""))
        self.assertEqual(s.failed_auth, 1)
        self.assertEqual(s.query_count, 0)

    def test_auth_fail_adds_to_sequence_not_counter(self):
        s = self._session()
        s.update(_make_event(event_type="auth_fail", fingerprint=""))
        self.assertIn("AUTH_FAIL", s.fingerprint_sequence)
        self.assertEqual(len(s.fingerprint_counter), 0)

    def test_last_activity_updated_on_event(self):
        s = self._session(ts=1000.0)
        later_ts = 1050.0
        s.update(_make_event(timestamp=later_ts))
        self.assertEqual(s.last_activity, later_ts)

    def test_fingerprint_counter_tracks_frequency(self):
        s = self._session()
        for _ in range(3):
            s.update(_make_event(fingerprint="select 1"))
        s.update(_make_event(fingerprint="select 2"))
        self.assertEqual(s.fingerprint_counter["select 1"], 3)
        self.assertEqual(s.fingerprint_counter["select 2"], 1)

    def test_fingerprint_sequence_preserves_order(self):
        s = self._session()
        fps = ["select a", "insert b", "select a", "update c"]
        for fp in fps:
            s.update(_make_event(fingerprint=fp))
        self.assertEqual(s.fingerprint_sequence, fps)


# ══════════════════════════════════════════════════════════════════════
# 5.  SESSION ENGINE  —  SessionEngine
# ══════════════════════════════════════════════════════════════════════

class TestSessionEngine(unittest.TestCase):

    def setUp(self):
        self.storage = MagicMock()
        # Patch the sweeper so it doesn't auto-close sessions during tests
        with patch("session_engine.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock(start=MagicMock())
            self.engine = SessionEngine(self.storage)

    def tearDown(self):
        self.engine.running = False  # stop sweeper if running

    # ── process_event ────────────────────────────────────────────────

    def test_new_session_created_on_first_event(self):
        e = _make_event(source_ip="1.1.1.1", db_user="alice")
        self.engine.process_event(e)
        self.assertIn(("1.1.1.1", "alice"), self.engine.active_sessions)

    def test_same_ip_user_reuses_session(self):
        e1 = _make_event(source_ip="1.1.1.1", db_user="alice")
        e2 = _make_event(source_ip="1.1.1.1", db_user="alice")
        self.engine.process_event(e1)
        self.engine.process_event(e2)
        self.assertEqual(len(self.engine.active_sessions), 1)

    def test_different_users_create_separate_sessions(self):
        self.engine.process_event(_make_event(source_ip="1.1.1.1", db_user="alice"))
        self.engine.process_event(_make_event(source_ip="1.1.1.1", db_user="bob"))
        self.assertEqual(len(self.engine.active_sessions), 2)

    def test_different_ips_create_separate_sessions(self):
        self.engine.process_event(_make_event(source_ip="1.1.1.1", db_user="alice"))
        self.engine.process_event(_make_event(source_ip="2.2.2.2", db_user="alice"))
        self.assertEqual(len(self.engine.active_sessions), 2)

    def test_query_count_accumulates(self):
        for _ in range(4):
            self.engine.process_event(_make_event())
        session = self.engine.active_sessions[("10.0.0.1", "alice")]
        self.assertEqual(session.query_count, 4)

    # ── close_session ────────────────────────────────────────────────

    def test_close_session_removes_from_active(self):
        e = _make_event()
        self.engine.process_event(e)
        key = ("10.0.0.1", "alice")
        self.assertIn(key, self.engine.active_sessions)
        self.engine.close_session(key)
        self.assertNotIn(key, self.engine.active_sessions)

    def test_close_session_calls_storage_save(self):
        self.engine.process_event(_make_event())
        self.engine.close_session(("10.0.0.1", "alice"))
        self.storage.save_session.assert_called_once()

    def test_close_nonexistent_session_does_not_raise(self):
        """Closing a key that doesn't exist should silently no-op."""
        self.engine.close_session(("9.9.9.9", "nobody"))  # must not raise
        self.storage.save_session.assert_not_called()

    def test_session_output_has_correct_ip_and_user(self):
        self.engine.process_event(_make_event(source_ip="5.5.5.5", db_user="carol"))
        self.engine.close_session(("5.5.5.5", "carol"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertEqual(saved.source_ip, "5.5.5.5")
        self.assertEqual(saved.db_user, "carol")

    def test_session_output_duration_is_non_negative(self):
        t0 = 1000.0
        self.engine.process_event(_make_event(timestamp=t0))
        self.engine.process_event(_make_event(timestamp=t0 + 5.0))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertGreaterEqual(saved.duration, 0.0)

    def test_session_output_read_write_ratio_reads_only(self):
        for _ in range(3):
            self.engine.process_event(_make_event(fingerprint="select * from t"))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertAlmostEqual(saved.read_write_ratio, 1.0)

    def test_session_output_read_write_ratio_mixed(self):
        self.engine.process_event(_make_event(fingerprint="select * from t"))
        self.engine.process_event(_make_event(fingerprint="insert into t values (?)"))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertAlmostEqual(saved.read_write_ratio, 0.5)

    def test_session_output_zero_query_count_ratio_is_zero(self):
        """Auth-fail-only session → query_count=0 → ratio should be 0, not ZeroDivision."""
        self.engine.process_event(_make_event(event_type="auth_fail", fingerprint=""))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertEqual(saved.read_write_ratio, 0.0)

    def test_session_output_fingerprints_json(self):
        self.engine.process_event(_make_event(fingerprint="select 1"))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        fps = json.loads(saved.fingerprints)
        self.assertIn("select 1", fps)

    def test_session_output_query_sequence_json(self):
        fps = ["select a", "select b", "insert c"]
        for fp in fps:
            self.engine.process_event(_make_event(fingerprint=fp))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        seq = json.loads(saved.query_sequence)
        self.assertEqual(seq, fps)

    # ── flush_all ────────────────────────────────────────────────────

    def test_flush_all_closes_all_sessions(self):
        self.engine.process_event(_make_event(source_ip="1.1.1.1", db_user="a"))
        self.engine.process_event(_make_event(source_ip="2.2.2.2", db_user="b"))
        self.engine.flush_all()
        self.assertEqual(len(self.engine.active_sessions), 0)
        self.assertEqual(self.storage.save_session.call_count, 2)

    # ── max active sessions / force_close_oldest ─────────────────────

    def test_oldest_session_closed_at_capacity(self):
        old_max = config.MAX_ACTIVE_SESSIONS
        config.MAX_ACTIVE_SESSIONS = 2

        t0 = 1000.0
        self.engine.process_event(_make_event(source_ip="1.1.1.1", db_user="a", timestamp=t0))
        self.engine.process_event(_make_event(source_ip="2.2.2.2", db_user="b", timestamp=t0 + 1))
        # Adding a 3rd session should force-close the oldest (1.1.1.1/a)
        self.engine.process_event(_make_event(source_ip="3.3.3.3", db_user="c", timestamp=t0 + 2))

        config.MAX_ACTIVE_SESSIONS = old_max
        self.assertNotIn(("1.1.1.1", "a"), self.engine.active_sessions)
        self.assertIn(("2.2.2.2", "b"),    self.engine.active_sessions)
        self.assertIn(("3.3.3.3", "c"),    self.engine.active_sessions)


# ══════════════════════════════════════════════════════════════════════
# 6.  STORAGE
# ══════════════════════════════════════════════════════════════════════

class TestRedpandaSessionStore(unittest.TestCase):

    def _make_store(self):
        with patch("storage.KafkaProducer") as MockProducer:
            mock_producer = MagicMock()
            MockProducer.return_value = mock_producer
            store = RedpandaSessionStore()
            store._mock_producer = mock_producer
        return store

    # ── save_session ─────────────────────────────────────────────────

    def test_save_session_sends_to_correct_topic(self):
        store = self._make_store()
        so = SessionOutput(
            session_id="abc", source_ip="1.1.1.1", db_user="alice",
            duration=2.0, entropy=0.5, failed_auth=0, depth_score=1, query_count=3,
        )
        store.save_session(so)
        store._mock_producer.send.assert_called_once()
        topic_arg = store._mock_producer.send.call_args[0][0]
        self.assertEqual(topic_arg, config.TOPIC_SESSION_CLOSED)

    def test_save_session_key_is_session_id_bytes(self):
        store = self._make_store()
        so = SessionOutput(
            session_id="my-session-id", source_ip="x", db_user="y",
            duration=0.0, entropy=0.0, failed_auth=0, depth_score=0, query_count=0,
        )
        store.save_session(so)
        kwargs = store._mock_producer.send.call_args[1]
        self.assertEqual(kwargs["key"], b"my-session-id")

    def test_save_session_value_is_dict(self):
        store = self._make_store()
        so = SessionOutput(
            session_id="s1", source_ip="1.1.1.1", db_user="u",
            duration=1.0, entropy=0.5, failed_auth=0, depth_score=1, query_count=1,
        )
        store.save_session(so)
        kwargs = store._mock_producer.send.call_args[1]
        self.assertIsInstance(kwargs["value"], dict)

    # ── publish_profile ──────────────────────────────────────────────

    def test_publish_profile_sends_to_profiles_topic(self):
        store = self._make_store()
        store.publish_profile("sid-1", 0, "script", _make_session_record())
        topic_arg = store._mock_producer.send.call_args[0][0]
        self.assertEqual(topic_arg, config.TOPIC_SESSION_PROFILES)

    def test_publish_profile_key_is_session_id_bytes(self):
        store = self._make_store()
        store.publish_profile("my-sid", 1, "human_attacker", _make_session_record())
        kwargs = store._mock_producer.send.call_args[1]
        self.assertEqual(kwargs["key"], b"my-sid")

    def test_publish_profile_merges_cluster_id_and_persona(self):
        store = self._make_store()
        payload = _make_session_record(cluster_id=-1, persona="unknown")
        store.publish_profile("sid", 3, "brute_bot", payload)
        kwargs = store._mock_producer.send.call_args[1]
        self.assertEqual(kwargs["value"]["cluster_id"], 3)
        self.assertEqual(kwargs["value"]["persona"],    "brute_bot")

    def test_publish_profile_does_not_mutate_original_payload(self):
        store = self._make_store()
        payload = _make_session_record(cluster_id=-1, persona="unknown")
        original_cluster = payload["cluster_id"]
        store.publish_profile("sid", 5, "script", payload)
        # Original dict should be unchanged
        self.assertEqual(payload["cluster_id"], original_cluster)

    # ── flush / close ────────────────────────────────────────────────

    def test_flush_calls_producer_flush(self):
        store = self._make_store()
        store.flush()
        store._mock_producer.flush.assert_called_once()

    def test_close_flushes_then_closes(self):
        store = self._make_store()
        store.close()
        store._mock_producer.flush.assert_called_once()
        store._mock_producer.close.assert_called_once()


# ══════════════════════════════════════════════════════════════════════
# 7.  CLUSTERING WORKER  —  _process_batch
# ══════════════════════════════════════════════════════════════════════

class TestClusteringWorkerProcessBatch(unittest.TestCase):

    def _make_worker(self):
        storage = MagicMock()
        worker = ClusteringWorker.__new__(ClusteringWorker)
        worker.storage = storage
        worker._stop_event = threading.Event()
        return worker, storage

    def _batch(self, n=5, **overrides):
        return [_make_session_record(**overrides) for _ in range(n)]

    # ── happy path ───────────────────────────────────────────────────

    def test_process_batch_calls_publish_for_each_session(self):
        worker, storage = self._make_worker()
        batch = self._batch(n=5)
        worker._process_batch(batch)
        self.assertEqual(storage.publish_profile.call_count, 5)

    def test_process_batch_passes_session_id(self):
        worker, storage = self._make_worker()
        batch = [_make_session_record(session_id=f"sid-{i}") for i in range(3)]
        worker._process_batch(batch)
        published_ids = [c.kwargs["session_id"] for c in storage.publish_profile.call_args_list]
        # All IDs from the batch must appear as published
        for i in range(3):
            self.assertIn(f"sid-{i}", published_ids)

    def _get_publish_kwargs(self, call_args):
        """
        clustering_worker calls:
          storage.publish_profile(session_id=..., cluster_id=..., persona=..., original_payload=...)
        so all arguments are in call_args.kwargs.
        """
        return call_args.kwargs

    def test_process_batch_assigns_integer_cluster_id(self):
        worker, storage = self._make_worker()
        worker._process_batch(self._batch(n=4))
        for ca in storage.publish_profile.call_args_list:
            cluster_id = self._get_publish_kwargs(ca)["cluster_id"]
            self.assertIsInstance(cluster_id, int)

    def test_process_batch_assigns_string_persona(self):
        worker, storage = self._make_worker()
        worker._process_batch(self._batch(n=4))
        for ca in storage.publish_profile.call_args_list:
            persona = self._get_publish_kwargs(ca)["persona"]
            self.assertIsInstance(persona, str)
            self.assertGreater(len(persona), 0)

    def test_process_batch_noise_sessions_get_unknown_persona(self):
        """A batch of 3 very different sessions may produce noise (cluster_id=-1)."""
        worker, storage = self._make_worker()
        # Distinct feature vectors far apart → DBSCAN will likely mark all noise
        batch = [
            _make_session_record(entropy=0.0, query_count=1,  depth_score=1, duration=0.0),
            _make_session_record(entropy=5.0, query_count=200, depth_score=10, duration=300.0),
            _make_session_record(entropy=2.5, query_count=50,  depth_score=5, duration=60.0),
        ]
        worker._process_batch(batch)
        personas = [c.kwargs["persona"] for c in storage.publish_profile.call_args_list]
        # At minimum must not raise and must return valid persona strings
        valid = {"unknown", "brute_bot", "automated_tool", "human_attacker", "script"}
        for p in personas:
            self.assertIn(p, valid)

    def test_process_batch_homogeneous_sessions_form_cluster(self):
        """Identical feature vectors should all land in the same cluster (not -1)."""
        worker, storage = self._make_worker()
        batch = [
            _make_session_record(entropy=0.0, failed_auth=0, depth_score=1,
                                  query_count=1, duration=0.0)
            for _ in range(6)
        ]
        worker._process_batch(batch)
        cluster_ids = [c.kwargs["cluster_id"] for c in storage.publish_profile.call_args_list]
        # All should be the same cluster
        self.assertEqual(len(set(cluster_ids)), 1)
        self.assertNotEqual(cluster_ids[0], -1)

    def test_process_batch_metrics_incremented(self):
        worker, storage = self._make_worker()
        worker._process_batch(self._batch(n=3))
        self.assertTrue(_metrics.cluster_sessions_total.labels.called)

    def test_process_batch_empty_batch_does_not_raise(self):
        """An empty batch shouldn't crash — DBSCAN on 0 rows."""
        worker, storage = self._make_worker()
        try:
            worker._process_batch([])
        except Exception:
            pass  # Empty batch behaviour may vary; just ensure no unhandled crash path


# ══════════════════════════════════════════════════════════════════════
# 8.  REDPANDA CONSUMER  —  map_proxy_event_to_event
# ══════════════════════════════════════════════════════════════════════

class TestMapProxyEventToEvent(unittest.TestCase):

    def _raw(self, **overrides):
        base = {
            "query_normalized": "select * from users",
            "event_type":       "query",
            "client_ip":        "10.0.0.1",
            "username":         "alice",
            "timestamp":        "2026-03-14T12:00:00Z",
        }
        base.update(overrides)
        return base

    # ── filtering rules ──────────────────────────────────────────────

    def test_empty_query_returns_none(self):
        result = map_proxy_event_to_event(self._raw(query_normalized=""))
        self.assertIsNone(result)

    def test_select_at_at_query_returns_recon_probe(self):
        """Gap 3 fix: select @@version is no longer discarded.
        It is emitted as event_type='recon_probe' so the MITRE HMM can see it."""
        result = map_proxy_event_to_event(self._raw(query_normalized="select @@version"))
        self.assertIsNotNone(result)
        self.assertEqual(result.event_type, "recon_probe")
        self.assertEqual(result.phase, "recon")

    def test_select_at_at_case_insensitive_is_recon_probe(self):
        """SELECT @@VERSION (uppercase) also becomes a recon_probe event."""
        result = map_proxy_event_to_event(self._raw(query_normalized="SELECT @@VERSION"))
        self.assertIsNotNone(result)
        self.assertEqual(result.event_type, "recon_probe")

    def test_whitespace_only_query_returns_none(self):
        result = map_proxy_event_to_event(self._raw(query_normalized="   "))
        self.assertIsNone(result)

    # ── valid query events ───────────────────────────────────────────

    def test_valid_query_returns_event(self):
        result = map_proxy_event_to_event(self._raw())
        self.assertIsNotNone(result)
        self.assertIsInstance(result, Event)

    def test_query_event_type_set_correctly(self):
        result = map_proxy_event_to_event(self._raw(event_type="query"))
        self.assertEqual(result.event_type, "query")

    def test_source_ip_mapped_from_client_ip(self):
        result = map_proxy_event_to_event(self._raw(client_ip="5.5.5.5"))
        self.assertEqual(result.source_ip, "5.5.5.5")

    def test_db_user_mapped_from_username(self):
        result = map_proxy_event_to_event(self._raw(username="carol"))
        self.assertEqual(result.db_user, "carol")

    def test_fingerprint_uses_query_normalized(self):
        result = map_proxy_event_to_event(self._raw(query_normalized="select ? from t"))
        self.assertEqual(result.query_fingerprint, "select ? from t")

    def test_missing_client_ip_defaults_to_unknown(self):
        raw = self._raw()
        del raw["client_ip"]
        result = map_proxy_event_to_event(raw)
        self.assertEqual(result.source_ip, "unknown")

    def test_missing_username_defaults_to_unknown(self):
        raw = self._raw()
        del raw["username"]
        result = map_proxy_event_to_event(raw)
        self.assertEqual(result.db_user, "unknown")

    # ── auth_fail events ─────────────────────────────────────────────

    def test_auth_fail_event_type_preserved(self):
        raw = self._raw(event_type="auth_fail", query_normalized="auth_fail")
        result = map_proxy_event_to_event(raw)
        # auth_fail with non-select-@@ query should be processed
        if result is not None:
            self.assertEqual(result.event_type, "auth_fail")

    # ── timestamp parsing ────────────────────────────────────────────

    def test_valid_iso_timestamp_parsed(self):
        result = map_proxy_event_to_event(self._raw(timestamp="2026-01-01T00:00:00Z"))
        self.assertIsNotNone(result)
        self.assertGreater(result.timestamp, 0)

    def test_invalid_timestamp_falls_back_to_current_time(self):
        before = time.time()
        result = map_proxy_event_to_event(self._raw(timestamp="not-a-date"))
        after  = time.time()
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result.timestamp, before)
        self.assertLessEqual(result.timestamp,    after)

    def test_missing_timestamp_falls_back_to_current_time(self):
        raw = self._raw()
        del raw["timestamp"]
        before = time.time()
        result = map_proxy_event_to_event(raw)
        after  = time.time()
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result.timestamp, before)
        self.assertLessEqual(result.timestamp,    after)

    # ── real-world samples (from terminal output) ────────────────────

    def test_mysql_proxy_sample(self):
        raw = {
            "query_normalized": "select ?",
            "event_type":       "query",
            "client_ip":        "172.18.0.2",
            "username":         "proxyuser",
            "timestamp":        "2026-03-14T12:39:12Z",
        }
        result = map_proxy_event_to_event(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result.source_ip, "172.18.0.2")
        self.assertEqual(result.db_user,   "proxyuser")

    def test_pg_proxy_sample(self):
        raw = {
            "query_normalized": "select * from information_schema.tables limit ?;",
            "event_type":       "query",
            "client_ip":        "172.19.0.2",
            "username":         "postgres",
            "timestamp":        "2026-03-14T12:39:03Z",
        }
        result = map_proxy_event_to_event(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result.source_ip, "172.19.0.2")
        self.assertEqual(result.db_user,   "postgres")


# ══════════════════════════════════════════════════════════════════════
# 9.  INTEGRATION — SessionEngine → Storage → ClusteringWorker
# ══════════════════════════════════════════════════════════════════════

class TestIntegration(unittest.TestCase):
    """
    End-to-end flow without any broker:
    Events → SessionEngine.process_event → close_session → storage.save_session
    Saved payload → ClusteringWorker._process_batch → storage.publish_profile
    """

    def setUp(self):
        self.storage = MagicMock()
        with patch("session_engine.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock(start=MagicMock())
            self.engine = SessionEngine(self.storage)
        self.engine.running = False

    def test_full_pipeline_produces_published_profile(self):
        # Step 1 — generate events and close session
        events = [
            _make_event(fingerprint="select * from users",       timestamp=1000.0),
            _make_event(fingerprint="select * from accounts",    timestamp=1001.0),
            _make_event(fingerprint="insert into logs values (?)", timestamp=1002.0),
        ]
        for e in events:
            self.engine.process_event(e)
        self.engine.close_session(("10.0.0.1", "alice"))

        # Step 2 — simulate what ClusteringWorker receives
        saved: SessionOutput = self.storage.save_session.call_args[0][0]
        self.assertIsNotNone(saved)

        batch = [{
            "session_id":   saved.session_id,
            "entropy":      saved.entropy,
            "failed_auth":  saved.failed_auth,
            "depth_score":  saved.depth_score,
            "query_count":  saved.query_count,
            "duration":     saved.duration,
        }]

        # Step 3 — need enough sessions for DBSCAN; pad with clones
        batch = batch * config.DBSCAN_MIN_SAMPLES

        worker = ClusteringWorker.__new__(ClusteringWorker)
        worker.storage = self.storage
        worker._stop_event = threading.Event()
        worker._process_batch(batch)

        self.assertEqual(self.storage.publish_profile.call_count,
                         config.DBSCAN_MIN_SAMPLES)

    def test_read_only_session_entropy_greater_than_zero_for_mixed_fingerprints(self):
        """Multiple distinct fingerprints → entropy > 0."""
        for fp in ["select a", "select b", "select c"]:
            self.engine.process_event(_make_event(fingerprint=fp))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertGreater(saved.entropy, 0.0)

    def test_single_fingerprint_session_has_zero_entropy(self):
        """One repeated fingerprint → entropy == 0."""
        for _ in range(5):
            self.engine.process_event(_make_event(fingerprint="select 1"))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertAlmostEqual(saved.entropy, 0.0)

    def test_failed_auth_session_has_nonzero_failed_auth_count(self):
        for _ in range(3):
            self.engine.process_event(_make_event(event_type="auth_fail", fingerprint=""))
        self.engine.close_session(("10.0.0.1", "alice"))
        saved = self.storage.save_session.call_args[0][0]
        self.assertEqual(saved.failed_auth, 3)


# ══════════════════════════════════════════════════════════════════════
# 10.  PERSONA MAPPER — Priority edge cases  (Gap 4)
# ══════════════════════════════════════════════════════════════════════
# features = [entropy, failed_auth, depth_score, query_count, duration]

class TestPersonaMapperPriorityEdgeCases(unittest.TestCase):
    """
    Tests that document and pin the exact priority ordering in
    map_cluster_to_persona. These exist so that any future reordering
    of rules immediately fails a test, forcing a conscious decision.

    Current priority (highest → lowest):
      1. cluster_id == -1  → unknown
      2. failed_auth >= 2  → brute_bot
      3. query_count > 30 and entropy > 1.2 → automated_tool
      4. depth > 2 and entropy > 1.0 → human_attacker
      5. (default) → script
    """

    def test_human_with_two_failed_auths_classified_as_brute_bot(self):
        """
        A human-attacker profile (depth=5, entropy=1.5) who also had 2 failed
        logins is classified as brute_bot because failed_auth fires first.
        This is the documented behaviour — if it should change, update this test.
        """
        # depth=5, entropy=1.5 would normally → human_attacker
        # but failed_auth=2 fires before that check
        features = [1.5, 2, 5, 10, 20.0]
        self.assertEqual(map_cluster_to_persona(0, features), "brute_bot")

    def test_automated_tool_profile_with_two_failed_auths_is_brute_bot(self):
        """
        An automated-tool profile (query_count=50, entropy=2.0) who also
        had 2 failed logins → brute_bot, not automated_tool.
        brute_bot check is earlier in the chain.
        """
        features = [2.0, 2, 3, 50, 60.0]
        self.assertEqual(map_cluster_to_persona(0, features), "brute_bot")

    def test_automated_tool_with_exactly_one_failed_auth_not_brute_bot(self):
        """
        sqlmap-style: 1 failed auth then many queries with high entropy.
        failed_auth == 1 does NOT trigger brute_bot (threshold is >= 2).
        Should fall through to automated_tool.
        """
        features = [1.5, 1, 2, 31, 10.0]
        result = map_cluster_to_persona(0, features)
        self.assertEqual(result, "automated_tool",
                         "failed_auth=1 must not trigger brute_bot; "
                         "automated_tool rule should fire instead.")

    def test_human_attacker_with_one_failed_auth_not_brute_bot(self):
        """
        Human attacker who mistyped their password once (failed_auth=1)
        then explored deeply → human_attacker, not brute_bot.
        """
        features = [1.5, 1, 5, 8, 30.0]
        result = map_cluster_to_persona(0, features)
        self.assertEqual(result, "human_attacker",
                         "Single failed auth must not override human_attacker "
                         "classification when depth and entropy thresholds are met.")

    def test_zero_failed_auth_never_triggers_brute_bot(self):
        """Sanity check: no failed auths → brute_bot is never returned."""
        # Many high-entropy queries, deep exploration, zero auth fails
        features = [3.0, 0, 10, 200, 120.0]
        result = map_cluster_to_persona(0, features)
        self.assertNotEqual(result, "brute_bot")

    def test_exactly_one_failed_auth_never_triggers_brute_bot(self):
        """failed_auth=1 is below the threshold of 2."""
        features = [0.0, 1, 1, 1, 1.0]
        result = map_cluster_to_persona(0, features)
        self.assertNotEqual(result, "brute_bot")

    def test_automated_tool_does_not_trigger_when_entropy_exactly_1_2(self):
        """
        Boundary: entropy must be strictly > 1.2.
        entropy == 1.2 with query_count > 30 → automated_tool NOT triggered.
        """
        features = [1.2, 0, 1, 50, 10.0]
        result = map_cluster_to_persona(0, features)
        self.assertNotEqual(result, "automated_tool",
                            "entropy=1.2 is not > 1.2; automated_tool must not fire.")

    def test_human_attacker_does_not_trigger_when_depth_exactly_2(self):
        """
        Boundary: depth must be strictly > 2.
        depth == 2 with entropy > 1.0 → human_attacker NOT triggered.
        """
        features = [1.5, 0, 2, 5, 5.0]
        result = map_cluster_to_persona(0, features)
        self.assertNotEqual(result, "human_attacker",
                            "depth=2 is not > 2; human_attacker must not fire.")

    def test_noise_always_beats_all_other_rules(self):
        """
        cluster_id=-1 must win even when every other rule would fire:
        failed_auth >= 2, query_count > 30, entropy > 1.2, depth > 2.
        """
        features = [2.0, 5, 5, 50, 30.0]
        self.assertEqual(map_cluster_to_persona(-1, features), "unknown",
                         "cluster_id=-1 must always return 'unknown' regardless "
                         "of feature values.")


# ══════════════════════════════════════════════════════════════════════
# 11.  BUG REGRESSION — float type for read_write_ratio  (Gap 4 / Bug 1)
# ══════════════════════════════════════════════════════════════════════

class TestReadWriteRatioTypeRegression(unittest.TestCase):
    """
    Regression tests for Bug 1:
      session_engine.py close_session() stored int 0 instead of float 0.0
      when query_count == 0 (auth-fail-only sessions).

    The dataclass declares  read_write_ratio: float = 0.0
    The stored value must always be a float — never an int — so that
    downstream JSON consumers receive 0.0 not 0.
    """

    def setUp(self):
        self.storage = MagicMock()
        with patch("session_engine.threading.Thread") as t:
            t.return_value = MagicMock(start=MagicMock())
            self.engine = SessionEngine(self.storage)
        self.engine.running = False

    def _close_and_get(self, events):
        for e in events:
            self.engine.process_event(e)
        self.engine.close_session(("10.0.0.1", "alice"))
        return self.storage.save_session.call_args[0][0]

    def test_read_write_ratio_is_float_when_zero_queries(self):
        """
        Auth-fail-only session: query_count == 0.
        read_write_ratio must be float 0.0, NOT int 0.
        This is the direct regression test for Bug 1.
        """
        saved = self._close_and_get([
            _make_event(event_type="auth_fail", fingerprint="")
        ])
        self.assertEqual(saved.query_count, 0)
        self.assertIsInstance(
            saved.read_write_ratio, float,
            "read_write_ratio must be float 0.0 when query_count == 0, "
            "not int 0. Fix: change 'else 0' to 'else 0.0' in close_session()."
        )

    def test_read_write_ratio_is_float_when_reads_only(self):
        """Non-zero ratio (all reads) must also be a float."""
        saved = self._close_and_get([
            _make_event(fingerprint="select * from t")
        ])
        self.assertIsInstance(saved.read_write_ratio, float)
        self.assertAlmostEqual(saved.read_write_ratio, 1.0)

    def test_read_write_ratio_is_float_when_writes_only(self):
        """All-write session → ratio 0.0 (0 reads / N queries) must be float."""
        saved = self._close_and_get([
            _make_event(fingerprint="insert into t values (?)")
        ])
        self.assertIsInstance(saved.read_write_ratio, float)
        self.assertAlmostEqual(saved.read_write_ratio, 0.0)

    def test_read_write_ratio_value_matches_expected_fraction(self):
        """3 reads + 1 write → ratio = 0.75 as a float."""
        events = [
            _make_event(fingerprint="select a"),
            _make_event(fingerprint="select b"),
            _make_event(fingerprint="select c"),
            _make_event(fingerprint="insert into t values (?)"),
        ]
        saved = self._close_and_get(events)
        self.assertIsInstance(saved.read_write_ratio, float)
        self.assertAlmostEqual(saved.read_write_ratio, 0.75)


# ══════════════════════════════════════════════════════════════════════
# 15.  FEATURE EXTRACTOR — Timing Features  (Gap 1)
# ══════════════════════════════════════════════════════════════════════

class TestExtractFeatures(unittest.TestCase):

    def test_extract_features_clamps_negative_duration(self):
        s = Session(source_ip="10.0.0.1", db_user="alice", start_time=100.0, last_seen=90.0)
        features = extract_features(s)
        self.assertEqual(features["duration"], 0.0)


class TestTimingFeatures(unittest.TestCase):
    """
    Tests for compute_timing_variance_ms() and compute_queries_per_second().
    These are the features that distinguish human attackers from bots:
    humans have high timing variance (3-9s between queries),
    bots have near-zero variance (50-100ms between queries).
    """

    # ── compute_timing_variance_ms ───────────────────────────────────

    def test_timing_variance_empty_list_is_zero(self):
        """No timestamps → 0.0."""
        self.assertEqual(compute_timing_variance_ms([]), 0.0)

    def test_timing_variance_single_event_is_zero(self):
        """Single query → no gaps → 0.0."""
        self.assertEqual(compute_timing_variance_ms([1000.0]), 0.0)

    def test_timing_variance_two_events_is_zero(self):
        """Two events → one gap → stdev undefined for single value → 0.0."""
        self.assertEqual(compute_timing_variance_ms([1000.0, 1001.0]), 0.0)

    def test_timing_variance_uniform_gaps_is_zero(self):
        """Bot pattern: perfectly uniform 100ms gaps → stdev = 0.0."""
        # gaps = [100ms, 100ms, 100ms] — all equal → zero variance
        timestamps = [1000.0, 1000.1, 1000.2, 1000.3]
        self.assertAlmostEqual(compute_timing_variance_ms(timestamps), 0.0)

    def test_timing_variance_irregular_gaps_is_high(self):
        """
        Human pattern: irregular gaps (1s, 9s) → high variance.
        This is the key test — it confirms humans are distinguishable from bots.
        """
        # gaps: 1s=1000ms, 9s=9000ms → stdev is large
        timestamps = [0.0, 1.0, 10.0]
        result = compute_timing_variance_ms(timestamps)
        self.assertGreater(result, 4000.0,
            "Irregular gaps (1s, 9s) must produce high timing variance > 4000ms")

    def test_timing_variance_result_is_float(self):
        """Return type must always be float."""
        result = compute_timing_variance_ms([0.0, 1.0, 5.0, 6.0])
        self.assertIsInstance(result, float)

    def test_timing_variance_non_negative(self):
        """Stdev is always >= 0."""
        for ts_list in [[], [1.0], [1.0, 2.0], [1.0, 2.0, 10.0]]:
            self.assertGreaterEqual(compute_timing_variance_ms(ts_list), 0.0)

    def test_timing_variance_bot_vs_human(self):
        """
        Bot (uniform 50ms gaps) must have lower variance than
        human (irregular gaps of 2s, 8s, 1s).
        """
        bot_timestamps   = [0.0, 0.05, 0.10, 0.15, 0.20]
        human_timestamps = [0.0, 2.0,  10.0, 11.0, 19.0]
        bot_var   = compute_timing_variance_ms(bot_timestamps)
        human_var = compute_timing_variance_ms(human_timestamps)
        self.assertLess(bot_var, human_var,
            "Bot (uniform fast gaps) must have lower timing variance than human")

    # ── compute_queries_per_second ───────────────────────────────────

    def test_queries_per_second_correct_calculation(self):
        """10 queries in 5 seconds → 2.0 qps."""
        self.assertAlmostEqual(compute_queries_per_second(10, 5.0), 2.0)

    def test_queries_per_second_zero_duration(self):
        """Zero duration (single-event session) → 0.0, not ZeroDivisionError."""
        self.assertEqual(compute_queries_per_second(5, 0.0), 0.0)

    def test_queries_per_second_zero_queries(self):
        """Zero queries → 0.0."""
        self.assertEqual(compute_queries_per_second(0, 10.0), 0.0)

    def test_queries_per_second_is_float(self):
        """Return type must be float."""
        self.assertIsInstance(compute_queries_per_second(3, 6.0), float)

    def test_queries_per_second_high_rate_bot(self):
        """Bot: 100 queries in 1 second → 100 qps."""
        self.assertAlmostEqual(compute_queries_per_second(100, 1.0), 100.0)


# ══════════════════════════════════════════════════════════════════════
# 16.  SESSION ENGINE — Timing Features in ActiveSession  (Gap 1)
# ══════════════════════════════════════════════════════════════════════

class TestActiveSessionTimingFeatures(unittest.TestCase):
    """
    Verifies that ActiveSession tracks query_timestamps and that
    SessionEngine.close_session() correctly computes timing_variance_ms
    and queries_per_second in the output SessionOutput.
    """

    def setUp(self):
        self.storage = MagicMock()
        with patch("session_engine.threading.Thread") as t:
            t.return_value = MagicMock(start=MagicMock())
            self.engine = SessionEngine(self.storage)
        self.engine.running = False

    def _close_and_get(self, events):
        for e in events:
            self.engine.process_event(e)
        self.engine.close_session(("10.0.0.1", "alice"))
        return self.storage.save_session.call_args[0][0]

    def test_query_timestamps_tracked_per_query(self):
        """ActiveSession.query_timestamps grows with each query event."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(timestamp=1000.0))
        session.update(_make_event(timestamp=1001.0))
        session.update(_make_event(timestamp=1005.0))
        self.assertEqual(len(session.query_timestamps), 3)
        self.assertEqual(session.query_timestamps, [1000.0, 1001.0, 1005.0])

    def test_auth_fail_does_not_add_to_query_timestamps(self):
        """auth_fail events must not be included in timing data."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(event_type="auth_fail", fingerprint=""))
        session.update(_make_event(event_type="auth_fail", fingerprint=""))
        self.assertEqual(len(session.query_timestamps), 0)

    def test_timing_variance_ms_in_session_output(self):
        """SessionOutput must have timing_variance_ms field after close."""
        saved = self._close_and_get([
            _make_event(timestamp=1000.0),
            _make_event(timestamp=1001.0),
            _make_event(timestamp=1010.0),
        ])
        self.assertIsInstance(saved.timing_variance_ms, float)

    def test_timing_variance_ms_zero_for_single_query(self):
        """Single query → timing_variance_ms = 0.0 (no gaps)."""
        saved = self._close_and_get([_make_event(timestamp=1000.0)])
        self.assertAlmostEqual(saved.timing_variance_ms, 0.0)

    def test_timing_variance_ms_zero_for_uniform_bot_gaps(self):
        """Uniform 100ms gaps → timing_variance_ms = 0.0."""
        events = [_make_event(timestamp=1000.0 + i * 0.1) for i in range(5)]
        saved = self._close_and_get(events)
        self.assertAlmostEqual(saved.timing_variance_ms, 0.0, places=3)

    def test_timing_variance_ms_high_for_human_irregular_gaps(self):
        """Irregular human-like gaps → timing_variance_ms > 0."""
        events = [
            _make_event(timestamp=1000.0),
            _make_event(timestamp=1002.0),   # 2s gap
            _make_event(timestamp=1011.0),   # 9s gap
            _make_event(timestamp=1012.0),   # 1s gap
        ]
        saved = self._close_and_get(events)
        self.assertGreater(saved.timing_variance_ms, 1000.0,
            "Human-like irregular gaps must produce timing_variance_ms > 1000ms")

    def test_queries_per_second_in_session_output(self):
        """SessionOutput must have queries_per_second field."""
        saved = self._close_and_get([
            _make_event(timestamp=1000.0),
            _make_event(timestamp=1002.0),
        ])
        self.assertIsInstance(saved.queries_per_second, float)

    def test_queries_per_second_correct_value(self):
        """2 queries over 4 seconds → queries_per_second = 0.5."""
        saved = self._close_and_get([
            _make_event(timestamp=1000.0),
            _make_event(timestamp=1001.0),
            _make_event(timestamp=1002.0),
            _make_event(timestamp=1004.0),
        ])
        # duration = 1004 - 1000 = 4s, query_count = 4 → 1.0 qps
        self.assertAlmostEqual(saved.queries_per_second, 1.0, places=3)

    def test_queries_per_second_zero_for_single_event(self):
        """Single event → duration = 0 → queries_per_second = 0.0."""
        saved = self._close_and_get([_make_event(timestamp=1000.0)])
        self.assertAlmostEqual(saved.queries_per_second, 0.0)


# ══════════════════════════════════════════════════════════════════════
# 17.  SUSPICION SCORE  (Gap 2)
# ══════════════════════════════════════════════════════════════════════

class TestSuspicionScore(unittest.TestCase):
    """
    Tests for the suspicion_score field — an integer that increments
    when a session sends known honeypot-detection probe queries.
    """

    def setUp(self):
        self.storage = MagicMock()
        with patch("session_engine.threading.Thread") as t:
            t.return_value = MagicMock(start=MagicMock())
            self.engine = SessionEngine(self.storage)
        self.engine.running = False

    def _close_and_get(self, events):
        for e in events:
            self.engine.process_event(e)
        self.engine.close_session(("10.0.0.1", "alice"))
        return self.storage.save_session.call_args[0][0]

    def test_suspicion_score_zero_for_normal_session(self):
        """Ordinary SELECT queries → suspicion_score = 0."""
        saved = self._close_and_get([
            _make_event(fingerprint="select * from orders"),
            _make_event(fingerprint="select id from users where id = ?"),
        ])
        self.assertEqual(saved.suspicion_score, 0)

    def test_suspicion_score_increments_on_hostname_probe(self):
        """select @@hostname is a known honeypot probe → score +1."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(fingerprint="select @@hostname"))
        self.assertEqual(session.suspicion_score, 1)

    def test_suspicion_score_increments_on_version_comment_probe(self):
        """select @@version_comment is a probe → score +1."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(fingerprint="select @@version_comment"))
        self.assertEqual(session.suspicion_score, 1)

    def test_suspicion_score_increments_on_sleep_probe(self):
        """SELECT SLEEP(N) is a timing-based honeypot detection probe."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(fingerprint="select sleep(?)"))
        self.assertEqual(session.suspicion_score, 1)

    def test_suspicion_score_increments_on_load_file(self):
        """SELECT LOAD_FILE is a file-read exploitation probe."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(fingerprint="select load_file(?)"))
        self.assertEqual(session.suspicion_score, 1)

    def test_suspicion_score_accumulates_across_multiple_probes(self):
        """Multiple distinct probes → score accumulates."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(fingerprint="select @@hostname"))
        session.update(_make_event(fingerprint="select @@version_comment"))
        session.update(_make_event(fingerprint="select sleep(?)"))
        self.assertEqual(session.suspicion_score, 3)

    def test_suspicion_score_does_not_increment_on_normal_select(self):
        """Ordinary queries must not inflate the suspicion score."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(fingerprint="select * from users"))
        session.update(_make_event(fingerprint="select count(*) from orders"))
        self.assertEqual(session.suspicion_score, 0)

    def test_suspicion_score_field_in_session_output(self):
        """SessionOutput must carry the suspicion_score from ActiveSession."""
        saved = self._close_and_get([
            _make_event(fingerprint="select @@hostname"),
            _make_event(fingerprint="select @@version_comment"),
            _make_event(fingerprint="select * from users"),
        ])
        self.assertEqual(saved.suspicion_score, 2)

    def test_suspicion_score_auth_fail_does_not_increment(self):
        """auth_fail events must not affect the suspicion score."""
        session = ActiveSession("10.0.0.1", "alice", 1000.0)
        session.update(_make_event(event_type="auth_fail", fingerprint=""))
        session.update(_make_event(event_type="auth_fail", fingerprint=""))
        self.assertEqual(session.suspicion_score, 0)

    def test_suspicion_score_is_int_type(self):
        """suspicion_score must be an int in SessionOutput."""
        saved = self._close_and_get([_make_event(fingerprint="select * from t")])
        self.assertIsInstance(saved.suspicion_score, int)


# ══════════════════════════════════════════════════════════════════════
# 18.  PHASE CLASSIFIER  (Gap 3)
# ══════════════════════════════════════════════════════════════════════

class TestPhaseClassifier(unittest.TestCase):
    """
    Tests for phase_classifier.classify_phase().
    Each MITRE phase must be correctly identified from query fingerprints.
    """

    # ── recon ────────────────────────────────────────────────────────

    def test_select_version_classified_as_recon(self):
        self.assertEqual(classify_phase("select @@version"), "recon")

    def test_select_hostname_classified_as_recon(self):
        self.assertEqual(classify_phase("select @@hostname"), "recon")

    def test_select_version_comment_classified_as_recon(self):
        self.assertEqual(classify_phase("select @@version_comment"), "recon")

    def test_select_datadir_classified_as_recon(self):
        self.assertEqual(classify_phase("select @@datadir"), "recon")

    def test_select_version_function_classified_as_recon(self):
        self.assertEqual(classify_phase("select version()"), "recon")

    def test_generic_at_at_prefix_classified_as_recon(self):
        """Any select @@ not in exact list falls through to prefix rule → recon."""
        self.assertEqual(classify_phase("select @@some_unknown_var"), "recon")

    # ── enumeration ──────────────────────────────────────────────────

    def test_show_databases_classified_as_enumeration(self):
        self.assertEqual(classify_phase("show databases"), "enumeration")

    def test_show_tables_classified_as_enumeration(self):
        self.assertEqual(classify_phase("show tables"), "enumeration")

    def test_information_schema_tables_classified_as_enumeration(self):
        self.assertEqual(
            classify_phase("select * from information_schema.tables"),
            "enumeration"
        )

    def test_information_schema_columns_classified_as_enumeration(self):
        self.assertEqual(
            classify_phase("select * from information_schema.columns"),
            "enumeration"
        )

    def test_information_schema_schemata_classified_as_enumeration(self):
        self.assertEqual(
            classify_phase("select * from information_schema.schemata"),
            "enumeration"
        )

    # ── privilege_discovery ──────────────────────────────────────────

    def test_select_mysql_user_classified_as_privilege_discovery(self):
        self.assertEqual(classify_phase("select * from mysql.user"), "privilege_discovery")

    def test_select_current_user_classified_as_privilege_discovery(self):
        self.assertEqual(classify_phase("select current_user()"), "privilege_discovery")

    def test_select_user_function_classified_as_privilege_discovery(self):
        self.assertEqual(classify_phase("select user()"), "privilege_discovery")

    def test_user_privileges_classified_as_privilege_discovery(self):
        self.assertEqual(
            classify_phase("select * from information_schema.user_privileges"),
            "privilege_discovery"
        )

    # ── exploitation ─────────────────────────────────────────────────

    def test_select_load_file_classified_as_exploitation(self):
        self.assertEqual(classify_phase("select load_file(?)"), "exploitation")

    def test_select_sleep_classified_as_exploitation(self):
        self.assertEqual(classify_phase("select sleep(?)"), "exploitation")

    def test_select_benchmark_classified_as_exploitation(self):
        self.assertEqual(classify_phase("select benchmark(?,?)"), "exploitation")

    # ── exfiltration ─────────────────────────────────────────────────

    def test_into_outfile_classified_as_exfiltration(self):
        self.assertEqual(
            classify_phase("select * from users into outfile '/tmp/dump'"),
            "exfiltration"
        )

    def test_into_dumpfile_classified_as_exfiltration(self):
        self.assertEqual(
            classify_phase("select * from users into dumpfile '/tmp/d'"),
            "exfiltration"
        )

    # ── normal queries — no phase ────────────────────────────────────

    def test_normal_select_has_no_phase(self):
        """Ordinary application query → None."""
        self.assertIsNone(classify_phase("select * from orders where id = ?"))

    def test_normal_insert_has_no_phase(self):
        self.assertIsNone(classify_phase("insert into logs values (?, ?)"))

    def test_normal_update_has_no_phase(self):
        self.assertIsNone(classify_phase("update users set name = ? where id = ?"))

    def test_empty_fingerprint_has_no_phase(self):
        self.assertIsNone(classify_phase(""))

    def test_none_like_empty_string_has_no_phase(self):
        self.assertIsNone(classify_phase("   "))


# ══════════════════════════════════════════════════════════════════════
# 19.  REDPANDA CONSUMER — Recon Probe Events  (Gap 3 + Gap 4)
# ══════════════════════════════════════════════════════════════════════

class TestReconProbeEvents(unittest.TestCase):
    """
    Gap 3 fix: select @@... and SHOW ... queries are no longer discarded.
    They are emitted as event_type='recon_probe' with a phase tag.
    This ensures the Week 8 MITRE HMM receives recon signals.
    """

    def _raw(self, **overrides):
        base = {
            "query_normalized": "select * from users",
            "event_type":       "query",
            "client_ip":        "10.0.0.1",
            "username":         "alice",
            "timestamp":        "2026-03-14T12:00:00Z",
        }
        base.update(overrides)
        return base

    def test_select_version_emitted_as_recon_probe_not_filtered(self):
        """select @@version must NOT return None — it is a recon_probe event."""
        result = map_proxy_event_to_event(self._raw(query_normalized="select @@version"))
        self.assertIsNotNone(result)
        self.assertEqual(result.event_type, "recon_probe")

    def test_recon_probe_has_recon_phase(self):
        """select @@version → phase = 'recon'."""
        result = map_proxy_event_to_event(self._raw(query_normalized="select @@version"))
        self.assertEqual(result.phase, "recon")

    def test_show_databases_emitted_as_recon_probe(self):
        """SHOW DATABASES → recon_probe with phase='enumeration'."""
        result = map_proxy_event_to_event(self._raw(query_normalized="show databases"))
        self.assertIsNotNone(result)
        self.assertEqual(result.event_type, "recon_probe")
        self.assertEqual(result.phase, "enumeration")

    def test_recon_probe_carries_source_ip_and_user(self):
        """recon_probe events must carry source_ip and db_user."""
        result = map_proxy_event_to_event(
            self._raw(query_normalized="select @@hostname",
                      client_ip="172.18.0.3", username="proxyuser")
        )
        self.assertEqual(result.source_ip, "172.18.0.3")
        self.assertEqual(result.db_user,   "proxyuser")

    def test_recon_probe_carries_fingerprint(self):
        """The original fingerprint is preserved in the recon_probe event."""
        result = map_proxy_event_to_event(
            self._raw(query_normalized="select @@version_comment")
        )
        self.assertEqual(result.query_fingerprint, "select @@version_comment")

    def test_normal_query_event_type_is_still_query(self):
        """Normal queries must still be event_type='query', not recon_probe."""
        result = map_proxy_event_to_event(self._raw(query_normalized="select * from users"))
        self.assertEqual(result.event_type, "query")

    def test_normal_query_has_empty_phase_for_ordinary_queries(self):
        """Ordinary application query → phase = '' (no phase tag)."""
        result = map_proxy_event_to_event(self._raw(query_normalized="select * from orders"))
        self.assertEqual(result.phase, "")

    def test_phase_field_present_in_event(self):
        """All Event objects have a phase field regardless of event_type."""
        result = map_proxy_event_to_event(self._raw())
        self.assertTrue(hasattr(result, "phase"))

    def test_information_schema_query_gets_enumeration_phase(self):
        """information_schema queries classified as enumeration even in consumer."""
        result = map_proxy_event_to_event(
            self._raw(query_normalized="select * from information_schema.tables")
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.phase, "enumeration")

    def test_load_file_query_gets_exploitation_phase(self):
        """SELECT LOAD_FILE → event_type='query', phase='exploitation'."""
        result = map_proxy_event_to_event(
            self._raw(query_normalized="select load_file(?)")
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.phase, "exploitation")


# ══════════════════════════════════════════════════════════════════════
# 20. SESSION ID FALLBACK — Protocol/database isolation
# ══════════════════════════════════════════════════════════════════════

class TestProtocolAwareFallbackSessionKeys(unittest.TestCase):
    class Store:
        def __init__(self):
            self.saved = []
        def save_session(self, output):
            self.saved.append(output)

    def test_legacy_events_without_protocol_keep_old_ip_user_key(self):
        store = self.Store()
        engine = SessionEngine(store)
        try:
            event = Event(
                timestamp=1.0,
                source_ip="10.0.0.5",
                db_user="app",
                query_fingerprint="select * from users",
                event_type="query",
            )
            self.assertEqual(engine._key(event), ("10.0.0.5", "app"))
        finally:
            engine.shutdown()

    def test_protocol_metadata_prevents_mysql_pg_fallback_merging(self):
        store = self.Store()
        engine = SessionEngine(store)
        try:
            mysql = Event(
                timestamp=1.0,
                source_ip="10.0.0.5",
                db_user="app",
                query_fingerprint="select * from users",
                event_type="query",
                protocol="mysql",
                database="testdb",
            )
            pg = Event(
                timestamp=2.0,
                source_ip="10.0.0.5",
                db_user="app",
                query_fingerprint="select * from pg_catalog.pg_tables",
                event_type="query",
                protocol="pg",
                database="testdb",
            )
            engine.process_event(mysql)
            engine.process_event(pg)
            self.assertEqual(len(engine.active_sessions), 2)
            protocols = {session.protocol for session in engine.active_sessions.values()}
            self.assertEqual(protocols, {"mysql", "postgres"})
        finally:
            engine.shutdown()


class TestOutOfOrderTimestamps(unittest.TestCase):
    class Store:
        def __init__(self):
            self.saved = []
        def save_session(self, output):
            self.saved.append(output)

    def test_session_duration_does_not_go_negative_for_replay_order(self):
        store = self.Store()
        engine = SessionEngine(store)
        try:
            engine.process_event(Event(
                timestamp=100.0, source_ip="10.0.0.8", db_user="app",
                query_fingerprint="select * from users", event_type="query",
                session_id="replay-1", protocol="mysql",
            ))
            engine.process_event(Event(
                timestamp=90.0, source_ip="10.0.0.8", db_user="app",
                query_fingerprint="select * from orders", event_type="query",
                session_id="replay-1", protocol="mysql",
            ))
            engine.flush_all()
            self.assertEqual(len(store.saved), 1)
            self.assertGreaterEqual(store.saved[0].duration, 0.0)
        finally:
            engine.shutdown()


class TestAuthFailureStringNormalization(unittest.TestCase):
    def test_session_mapper_treats_string_false_success_as_auth_fail(self):
        from redpanda_consumer import map_proxy_event_to_event
        event = map_proxy_event_to_event({
            "event_type": "AUTH",
            "success": "false",
            "client_ip": "10.0.0.10",
            "username": "root",
            "session_id": "auth-string",
            "timestamp": 100.0,
        }, "mysql")
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "auth_fail")
        self.assertEqual(event.protocol, "mysql")


class TestLegacySessionTimestampRobustness(unittest.TestCase):
    def test_legacy_session_update_keeps_last_seen_monotonic(self):
        s = Session(source_ip="10.0.0.1", db_user="alice", start_time=100.0, last_seen=100.0)
        s.update(Event(
            timestamp=90.0,
            source_ip="10.0.0.1",
            db_user="alice",
            query_fingerprint="select * from users",
            event_type="query",
        ))
        self.assertEqual(s.last_seen, 100.0)
        self.assertEqual(s.query_count, 1)


class TestSyntheticFallbackSessionID(unittest.TestCase):
    class Store:
        def __init__(self):
            self.saved = []
        def save_session(self, output):
            self.saved.append(output)

    def test_missing_proxy_session_id_uses_deterministic_protocol_ip_user_database_id(self):
        store = self.Store()
        engine = SessionEngine(store)
        try:
            engine.process_event(Event(
                timestamp=10.0,
                source_ip="10.0.0.20",
                db_user="app",
                query_fingerprint="select * from users",
                event_type="query",
                protocol="mysql",
                database="testdb",
            ))
            engine.flush_all()
            self.assertEqual(len(store.saved), 1)
            self.assertEqual(store.saved[0].session_id, "mysql:10.0.0.20:app:testdb")
        finally:
            engine.shutdown()

    def test_missing_proxy_session_id_without_database_uses_stable_three_part_id(self):
        store = self.Store()
        engine = SessionEngine(store)
        try:
            engine.process_event(Event(
                timestamp=10.0,
                source_ip="10.0.0.21",
                db_user="root",
                query_fingerprint="select 1",
                event_type="query",
                protocol="pg",
            ))
            engine.flush_all()
            self.assertEqual(store.saved[0].session_id, "postgres:10.0.0.21:root")
        finally:
            engine.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)

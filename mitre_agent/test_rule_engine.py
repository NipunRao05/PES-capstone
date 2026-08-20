import sys
import unittest
from unittest.mock import MagicMock

sys.modules.setdefault("redis", MagicMock())
sys.modules.setdefault("kafka", MagicMock())
sys.modules.setdefault("kafka.errors", MagicMock())

from models import EvalContext
from rule_engine import RuleEngine
from consumer import MitreAgent


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()

    def test_database_subtechnique_metadata_is_enriched(self):
        result = self.engine.evaluate(EvalContext(
            fingerprint="show tables",
            phase="enumeration",
            event_type="query",
            depth_score=3,
            timing_variance_ms=100,
        ))
        self.assertTrue(result.matched_techniques)
        match = result.matched_techniques[0]
        self.assertEqual(match.technique_id, "T1213.006")
        self.assertEqual(match.technique_name, "Data from Information Repositories: Databases")
        self.assertEqual(match.tactic, "Collection")
        self.assertEqual(match.tactic_id, "TA0009")

    def test_repeated_schema_enumeration_reaches_medium_risk(self):
        result = self.engine.evaluate(EvalContext(
            fingerprint="show tables",
            phase="enumeration",
            event_type="query",
            depth_score=3,
            timing_variance_ms=100,
        ))
        self.assertGreaterEqual(result.new_risk_score, self.engine.thresholds["medium"])
        self.assertEqual(result.risk_level, "medium")
    def test_single_postgres_information_schema_tables_maps_database_collection(self):
        result = self.engine.evaluate(EvalContext(
            fingerprint="select * from information_schema.tables limit ?;",
            phase="enumeration",
            event_type="query",
            depth_score=1,
            timing_variance_ms=0,
        ))

        technique_ids = {m.technique_id for m in result.matched_techniques}

        self.assertIn("T1213.006", technique_ids)
        self.assertIn("table_enumeration", result.tags)
        self.assertEqual(result.deception_level, 2)
        self.assertEqual(result.new_risk_score, 7.0)
        self.assertEqual(result.risk_level, "medium")

    def test_trap_table_schema_qualified_match(self):
        table = MitreAgent._extract_table("select * from public.api_keys_backup where id = ?")
        self.assertEqual(table, "api_keys_backup")
        result = self.engine.evaluate(EvalContext(
            fingerprint="select * from public.api_keys_backup where id = ?",
            phase="data_discovery",
            event_type="query",
            table=table,
        ))
        self.assertTrue(result.is_trap_triggered)
        self.assertGreaterEqual(result.new_risk_score, self.engine.thresholds["critical"])
        self.assertEqual(result.deception_level, 4)
        self.assertEqual(result.matched_techniques[0].rule_id, "R001_trap_table_access")
        self.assertEqual(result.matched_techniques[0].technique_id, "T1213.006")

    def test_unknown_condition_does_not_match(self):
        # A malformed/unknown condition must fail closed, not accidentally match.
        self.assertFalse(self.engine._eval_session_condition("session.not_a_field > 0", EvalContext(
            fingerprint="select 1", phase="", event_type="query"
        )))

    def test_fingerprint_contains_is_case_insensitive(self):
        result = self.engine.evaluate(EvalContext(
            fingerprint="SELECT @@HOSTNAME",
            phase="recon",
            event_type="recon_probe",
            query_count=4,
            timing_variance_ms=10,
            suspicion_score=2,
        ))
        ids = {m.technique_id for m in result.matched_techniques}
        self.assertIn("T1082", ids)

    def test_brute_force_requires_more_than_two_failures(self):
        weak = self.engine.evaluate(EvalContext(
            fingerprint="", phase="", event_type="auth_fail", failed_auth=2
        ))
        strong = self.engine.evaluate(EvalContext(
            fingerprint="", phase="", event_type="auth_fail", failed_auth=3
        ))
        self.assertFalse(weak.matched_techniques)
        self.assertTrue(strong.matched_techniques)
        self.assertEqual(strong.matched_techniques[0].technique_id, "T1110.001")


class TestMitreConsumerHelpers(unittest.TestCase):
    def test_parse_query_event_uses_query_normalized_when_fingerprint_empty(self):
        raw = {
            "session_id": "s1",
            "timestamp": "2026-05-24T12:00:00Z",
            "client_ip": "10.0.0.9",
            "username": "postgres",
            "query_normalized": "select * from pg_database",
            "fingerprint": "",
        }
        event = MitreAgent._parse_query_event(raw, "pg")
        self.assertEqual(event.fingerprint, "select * from pg_database")
        self.assertEqual(event.protocol, "postgres")

    def test_session_state_first_seen_uses_event_timestamp_for_qps(self):
        raw = {
            "session_id": "s2",
            "timestamp": 100.0,
            "client_ip": "10.0.0.9",
            "username": "root",
            "query_normalized": "select @@version",
        }
        event = MitreAgent._parse_query_event(raw, "mysql")
        # Construct SessionState directly to avoid broker setup and verify the
        # timestamp contract used by _get_or_create_session.
        from consumer import SessionState
        state = SessionState(event.session_id, event.client_ip, event.username,
                             event.protocol, event.database, first_seen=event.timestamp)
        self.assertEqual(state.first_seen, 100.0)




    def test_consumer_group_id_is_source_specific(self):
        import consumer as consumer_module
        self.assertEqual(consumer_module.GROUP_ID, "mitre-agent")
        self.assertEqual(f"{consumer_module.GROUP_ID}-mysql", "mitre-agent-mysql")
        self.assertEqual(f"{consumer_module.GROUP_ID}-pg", "mitre-agent-pg")

    def test_health_server_handle_survives_start_stop(self):
        import consumer as consumer_module
        import socket
        import threading
        import urllib.request

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        old_addr = consumer_module.HEALTH_ADDR
        consumer_module.HEALTH_ADDR = f"127.0.0.1:{port}"
        try:
            agent = object.__new__(MitreAgent)
            agent._lock = threading.Lock()
            agent._sessions = {}
            agent._running = True
            agent._health_server = None

            agent._start_health_server()
            self.assertIsNotNone(agent._health_server)
            body = urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2).read()
            self.assertIn(b'"status"', body)
            agent._stop_health_server()
            self.assertIsNone(agent._health_server)
        finally:
            consumer_module.HEALTH_ADDR = old_addr

    def test_profile_only_sequence_does_not_duplicate_classified_phases(self):
        class Store:
            def __init__(self):
                self.sessions = []
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def update_from_session(self, session):
                pass

        agent = object.__new__(MitreAgent)
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.decode_sequence.return_value = ["discovery"]
        agent.hmm_scorer.score_sequence.return_value = 0.42
        agent.rule_engine = RuleEngine()
        agent.store = Store()
        agent.actor_tracker = Tracker()

        agent._publish_profile_only_session({
            "session_id": "s3",
            "source_ip": "10.0.0.7",
            "db_user": "app",
            "persona": "script",
            "protocol": "pg",
            "query_sequence": '["select * from information_schema.tables"]',
            "duration": 1.0,
        })
        self.assertEqual(len(agent.store.sessions), 1)
        self.assertEqual(agent.store.sessions[0].attack_path, ["enumeration"])
        agent.hmm_scorer.score_sequence.assert_called_once_with(["enumeration"])

    def test_profile_only_string_noise_cluster_gets_low_baseline_risk(self):
        class Store:
            def __init__(self):
                self.sessions = []
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def update_from_session(self, session):
                pass

        agent = object.__new__(MitreAgent)
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.decode_sequence.return_value = []
        agent.hmm_scorer.score_sequence.return_value = 0.0
        agent.rule_engine = RuleEngine()
        agent.store = Store()
        agent.actor_tracker = Tracker()

        agent._publish_profile_only_session({
            "session_id": "string-noise",
            "source_ip": "10.0.0.7",
            "db_user": "app",
            "persona": "unknown",
            "protocol": "pg",
            "query_count": 1,
            "cluster_id": "-1",
            "query_sequence": "[]",
        })
        self.assertEqual(agent.store.sessions[0].final_risk_score, 0.5)

    def test_profile_only_fractional_enumeration_depth_keeps_database_technique(self):
        class Store:
            def __init__(self):
                self.sessions = []
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def update_from_session(self, session):
                pass

        agent = object.__new__(MitreAgent)
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.decode_sequence.return_value = ["discovery"]
        agent.hmm_scorer.score_sequence.return_value = 0.5
        agent.rule_engine = RuleEngine()
        agent.store = Store()
        agent.actor_tracker = Tracker()

        agent._publish_profile_only_session({
            "session_id": "fractional-depth",
            "source_ip": "10.0.0.7",
            "db_user": "app",
            "persona": "unknown",
            "protocol": "pg",
            "depth_score": 2.5,
            "query_sequence": '["select * from information_schema.tables"]',
        })
        technique_ids = {m["technique_id"] for m in agent.store.sessions[0].techniques_matched}
        self.assertIn("T1213.006", technique_ids)

    def test_profile_only_bruteforce_preserves_mitre_technique(self):
        class Store:
            def __init__(self):
                self.sessions = []
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def __init__(self):
                self.updated = []
            def update_from_session(self, session):
                self.updated.append(session)

        agent = object.__new__(MitreAgent)
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.decode_sequence.return_value = ["credential_access"]
        agent.hmm_scorer.score_sequence.return_value = 0.77
        agent.rule_engine = RuleEngine()
        agent.store = Store()
        agent.actor_tracker = Tracker()

        agent._publish_profile_only_session({
            "session_id": "auth-only",
            "source_ip": "10.0.0.44",
            "db_user": "root",
            "persona": "brute_bot",
            "protocol": "mysql",
            "query_sequence": '["AUTH_FAIL", "AUTH_FAIL", "AUTH_FAIL"]',
            "failed_auth": 3,
            "duration": 2.0,
        })

        self.assertEqual(len(agent.store.sessions), 1)
        session = agent.store.sessions[0]
        technique_ids = {m["technique_id"] for m in session.techniques_matched}
        self.assertIn("T1110.001", technique_ids)
        self.assertEqual(session.attack_path, ["credential_access", "credential_access", "credential_access"])
        self.assertTrue(session.attack_graph["nodes"])
        self.assertEqual(len(agent.actor_tracker.updated), 1)




class TestMitreHealthReadiness(unittest.TestCase):
    def test_readyz_reports_unready_until_consumers_connected(self):
        import consumer as consumer_module
        import socket
        import threading
        import urllib.error
        import urllib.request

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        old_addr = consumer_module.HEALTH_ADDR
        consumer_module.HEALTH_ADDR = f"127.0.0.1:{port}"
        try:
            agent = object.__new__(MitreAgent)
            agent._lock = threading.Lock()
            agent._sessions = {}
            agent._running = True
            agent._health_server = None
            agent._consumer_status = {"mysql": True, "pg": False, "profiles": True}

            agent._start_health_server()
            self.assertIsNotNone(agent._health_server)
            health = urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2).read()
            self.assertIn(b'"ready": false', health)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=2)
            self.assertEqual(ctx.exception.code, 503)
            agent._consumer_status["pg"] = True
            ready = urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=2).read()
            self.assertIn(b'"ready": true', ready)
            agent._stop_health_server()
        finally:
            consumer_module.HEALTH_ADDR = old_addr

class TestMitreReplayTiming(unittest.TestCase):
    def _agent_for_state_tests(self):
        import threading
        class Store:
            def __init__(self):
                self.events = []
                self.sessions = []
            def publish_event(self, event):
                self.events.append(event)
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def update_from_session(self, session):
                pass
        agent = object.__new__(MitreAgent)
        agent.rule_engine = RuleEngine()
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.score_sequence.return_value = 0.0
        agent.hmm_scorer.decode_sequence.return_value = []
        agent.hmm_scorer.w_hmm = 1.0
        agent.store = Store()
        agent.actor_tracker = Tracker()
        agent._sessions = {}
        agent._lock = threading.Lock()
        return agent

    def test_timing_variance_sorts_replayed_timestamps(self):
        self.assertEqual(MitreAgent._timing_variance_ms([100.0, 90.0, 97.0]), 2000.0)

    def test_live_qps_uses_earliest_seen_timestamp_when_replayed_out_of_order(self):
        agent = self._agent_for_state_tests()
        base = {
            "session_id": "replay-s1",
            "client_ip": "10.0.0.5",
            "username": "root",
            "query_normalized": "select * from users",
            "protocol": "mysql",
        }
        agent._handle_query_event({**base, "timestamp": 100.0}, "mysql")
        agent._handle_query_event({**base, "timestamp": 90.0, "query_normalized": "select * from orders"}, "mysql")
        state = agent._sessions["replay-s1"]
        self.assertEqual(state.first_seen, 90.0)
        self.assertAlmostEqual(state.qps, 0.2)

    def test_session_profile_duration_overrides_wall_clock_for_replay(self):
        from consumer import SessionState
        agent = self._agent_for_state_tests()
        state = SessionState(
            session_id="closed-replay",
            client_ip="10.0.0.6",
            username="postgres",
            protocol="postgres",
            database="testdb",
            first_seen=100.0,
        )
        state.query_count = 1
        agent._sessions["closed-replay"] = state
        agent._handle_session_profile({
            "session_id": "closed-replay",
            "source_ip": "10.0.0.6",
            "db_user": "postgres",
            "duration": 3.25,
            "entropy": 0.0,
            "depth_score": 1,
            "timing_variance_ms": 0.0,
            "queries_per_second": 0.31,
            "suspicion_score": 0,
            "persona": "script",
        })
        self.assertEqual(len(agent.store.sessions), 1)
        self.assertEqual(agent.store.sessions[0].duration_s, 3.25)
        self.assertNotIn("closed-replay", agent._sessions)

class TestMitreProfileOnlyRobustness(unittest.TestCase):
    def _agent(self):
        class Store:
            def __init__(self):
                self.sessions = []
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def update_from_session(self, session):
                pass
        agent = object.__new__(MitreAgent)
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.decode_sequence.return_value = []
        agent.hmm_scorer.score_sequence.return_value = 0.0
        agent.rule_engine = RuleEngine()
        agent.store = Store()
        agent.actor_tracker = Tracker()
        return agent

    def test_profile_only_bad_numeric_fields_do_not_kill_summary(self):
        agent = self._agent()
        agent._publish_profile_only_session({
            "session_id": "bad-profile",
            "source_ip": "10.0.0.99",
            "db_user": "app",
            "duration": "not-a-number",
            "failed_auth": "nan?",
            "suspicion_score": None,
            "depth_score": "",
            "query_count": "bad",
            "query_sequence": "[]",
        })
        self.assertEqual(len(agent.store.sessions), 1)
        self.assertEqual(agent.store.sessions[0].duration_s, 0.0)
        self.assertEqual(agent.store.sessions[0].final_risk_score, 0.0)

    def test_profile_only_negative_duration_is_clamped(self):
        agent = self._agent()
        agent._publish_profile_only_session({
            "session_id": "negative-duration",
            "source_ip": "10.0.0.99",
            "db_user": "app",
            "duration": -42,
            "query_sequence": "[]",
        })
        self.assertEqual(agent.store.sessions[0].duration_s, 0.0)

class TestMitreMalformedLiveProfile(unittest.TestCase):
    def test_live_session_profile_bad_numeric_fields_do_not_kill_consumer(self):
        import threading
        from consumer import SessionState

        class Store:
            def __init__(self):
                self.sessions = []
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def update_from_session(self, session):
                pass

        agent = object.__new__(MitreAgent)
        agent.rule_engine = RuleEngine()
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.score_sequence.return_value = 0.0
        agent.hmm_scorer.decode_sequence.return_value = []
        agent.hmm_scorer.w_hmm = 1.0
        agent.store = Store()
        agent.actor_tracker = Tracker()
        agent._sessions = {
            "bad-live-profile": SessionState(
                session_id="bad-live-profile",
                client_ip="10.0.0.5",
                username="app",
                protocol="",
                database="",
                first_seen=100.0,
            )
        }
        agent._lock = threading.Lock()

        agent._handle_session_profile({
            "session_id": "bad-live-profile",
            "source_ip": "10.0.0.5",
            "db_user": "app",
            "duration": "bad",
            "entropy": "not-a-number",
            "depth_score": "nope",
            "timing_variance_ms": None,
            "queries_per_second": "nan?",
            "suspicion_score": "bad",
            "persona": "",
            "protocol": "pg",
            "database": "testdb",
        })
        self.assertEqual(len(agent.store.sessions), 1)
        session = agent.store.sessions[0]
        self.assertEqual(session.duration_s, 0.0)
        self.assertEqual(session.protocol, "postgres")
        self.assertEqual(session.database, "testdb")
        self.assertEqual(session.persona, "unknown")
        self.assertNotIn("bad-live-profile", agent._sessions)


    def test_parse_query_event_treats_string_false_success_as_auth_fail(self):
        event = MitreAgent._parse_query_event({
            "event_type": "AUTH",
            "success": "false",
            "session_id": "auth-string",
            "timestamp": 100.0,
            "client_ip": "10.0.0.1",
            "username": "root",
        }, "mysql")
        self.assertEqual(event.event_type, "auth_fail")

    def test_parse_query_event_treats_string_false_auth_success_as_auth_fail(self):
        event = MitreAgent._parse_query_event({
            "event_type": "query",
            "auth_success": "false",
            "session_id": "auth-string-2",
            "timestamp": 100.0,
            "client_ip": "10.0.0.1",
            "username": "root",
        }, "mysql")
        self.assertEqual(event.event_type, "auth_fail")

    def test_parse_query_event_tolerates_bad_byte_counters(self):
        event = MitreAgent._parse_query_event({
            "session_id": "bytes-bad",
            "timestamp": 100.0,
            "client_ip": "10.0.0.1",
            "username": "root",
            "query_normalized": "select 1",
            "bytes_in": "not-an-int",
            "bytes_out": None,
        }, "mysql")
        self.assertEqual(event.bytes_in, 0)
        self.assertEqual(event.bytes_out, 0)


class TestSyntheticFallbackSessionID(unittest.TestCase):
    def test_missing_proxy_session_id_matches_session_module_database_aware_convention(self):
        event = MitreAgent._parse_query_event({
            "timestamp": 100.0,
            "client_ip": "10.0.0.20",
            "username": "app",
            "database": "testdb",
            "query_normalized": "select * from users",
        }, "mysql")
        self.assertEqual(event.session_id, "mysql:10.0.0.20:app:testdb")

    def test_missing_proxy_session_id_without_database_uses_three_part_convention(self):
        event = MitreAgent._parse_query_event({
            "timestamp": 100.0,
            "client_ip": "10.0.0.21",
            "username": "root",
            "query_normalized": "select 1",
        }, "pg")
        self.assertEqual(event.session_id, "postgres:10.0.0.21:root")


class TestActorLevelBruteForce(unittest.TestCase):
    def _agent(self):
        import threading
        class Store:
            def __init__(self):
                self.events = []
                self.sessions = []
            def publish_event(self, event):
                self.events.append(event)
            def publish_session(self, session):
                self.sessions.append(session)
        class Tracker:
            def __init__(self):
                self.updated = []
            def update_from_session(self, session):
                self.updated.append(session)
        agent = object.__new__(MitreAgent)
        agent.rule_engine = RuleEngine()
        agent.hmm_scorer = MagicMock()
        agent.hmm_scorer.score_sequence.return_value = 0.0
        agent.hmm_scorer.decode_sequence.return_value = []
        agent.hmm_scorer.w_hmm = 1.0
        agent.store = Store()
        agent.actor_tracker = Tracker()
        agent._sessions = {}
        agent._auth_fail_windows = {}
        agent._auth_fail_alert_buckets = set()
        agent._lock = threading.Lock()
        return agent

    def test_separate_failed_login_sessions_trigger_actor_bruteforce_event(self):
        agent = self._agent()
        for idx in range(3):
            agent._handle_query_event({
                "event_type": "auth",
                "success": False,
                "session_id": f"auth-{idx}",
                "timestamp": 100.0 + idx,
                "client_ip": "10.0.0.44",
                "username": "root",
                "database": "testdb",
                "protocol": "mysql",
            }, "mysql")
        self.assertTrue(agent.store.events)
        brute = agent.store.events[-1]
        self.assertEqual(brute.technique_id, "T1110.001")
        self.assertEqual(brute.rule_id, "R009_brute_force")
        self.assertGreaterEqual(brute.risk_score, 3.0)
        self.assertEqual(brute.protocol, "mysql")
        self.assertEqual(brute.database, "testdb")

    def test_profile_only_single_failures_accumulate_to_bruteforce_session(self):
        agent = self._agent()
        for idx in range(3):
            agent._publish_profile_only_session({
                "session_id": f"profile-auth-{idx}",
                "source_ip": "10.0.0.45",
                "db_user": "proxyuser",
                "database": "testdb",
                "protocol": "mysql",
                "failed_auth": 1,
                "query_sequence": '["AUTH_FAIL"]',
                "created_at": 200.0 + idx,
                "persona": "low_activity",
            })
        self.assertEqual(len(agent.store.sessions), 3)
        last = agent.store.sessions[-1]
        technique_ids = {m["technique_id"] for m in last.techniques_matched}
        self.assertIn("T1110.001", technique_ids)
        self.assertGreaterEqual(last.final_risk_score, 5.0)
        self.assertIn("credential_access", last.attack_path)
        self.assertEqual(len(agent.store.events), 1)
        self.assertEqual(agent.store.events[0].technique_id, "T1110.001")
        self.assertEqual(agent.store.events[0].rule_id, "R009_brute_force")
        self.assertIn("actor_window", agent.store.events[0].tags)

    def test_profile_only_bruteforce_alert_is_throttled_per_actor_window(self):
        agent = self._agent()
        for idx in range(5):
            agent._publish_profile_only_session({
                "session_id": f"profile-auth-dupe-{idx}",
                "source_ip": "10.0.0.46",
                "db_user": "proxyuser",
                "database": "testdb",
                "protocol": "mysql",
                "failed_auth": 1,
                "query_sequence": '["AUTH_FAIL"]',
                "created_at": 300.0 + idx,
                "persona": "low_activity",
            })
        self.assertEqual(len(agent.store.events), 1)


if __name__ == "__main__":
    unittest.main()

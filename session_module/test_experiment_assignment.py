import concurrent.futures
import json
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from authoritative_state import AuthoritativeStateStore, start_state_api
from experiment_assignment import (
    ASSIGNMENT_VERSION,
    CONTROL_VERSION,
    ExperimentAssignmentController,
    InMemoryExperimentPersistence,
)


def controller(backend=None, *, max_events=10_000):
    return ExperimentAssignmentController(
        backend or InMemoryExperimentPersistence(),
        persistence_required=True,
        max_processed_events=max_events,
    )


def proxy_event(session_id="d1-session", source_ip="198.51.100.10", protocol="postgres"):
    return {
        "event_type": "session_start",
        "session_id": session_id,
        "timestamp": "2026-09-01T10:00:00Z",
        "protocol": protocol,
        "source_ip": source_ip,
        "username": "synthetic_user",
        "database": "synthetic_db",
    }


class ExperimentAssignmentTests(unittest.TestCase):
    def test_hmac_assignment_is_deterministic_and_persists_no_raw_cohort(self):
        backend = InMemoryExperimentPersistence()
        first = controller(backend).assign("session-a", "postgresql", "198.51.100.7")
        second = controller(backend).assign("session-b", "pg", "198.51.100.7")

        self.assertEqual(first["assigned_arm"], second["assigned_arm"])
        self.assertEqual(first["cohort_hmac"], second["cohort_hmac"])
        self.assertEqual(first["assignment_version"], ASSIGNMENT_VERSION)
        self.assertEqual(len(first["cohort_hmac"]), 64)
        self.assertNotIn("198.51.100.7", json.dumps(backend.list_assignments(10)))
        self.assertFalse(first["dynamic_execution_enabled"])
        self.assertFalse(first["new_dynamic_commits_allowed"])

    def test_session_assignment_is_sticky_across_restart_and_forced_arm_change(self):
        backend = InMemoryExperimentPersistence()
        first_controller = controller(backend)
        original = first_controller.assign("sticky", "postgres", "203.0.113.4")
        forced = "D" if original["assigned_arm"] != "D" else "A"
        first_controller.set_forced_arm(forced, "operator", "controlled D1 test")

        restarted = controller(backend)
        restored = restarted.assign("sticky", "postgres", "different-untrusted-value")
        new_session = restarted.assign("new-session", "postgres", "203.0.113.5")

        self.assertEqual(restored["assigned_arm"], original["assigned_arm"])
        self.assertEqual(restored["cohort_hmac"], original["cohort_hmac"])
        self.assertEqual(new_session["assigned_arm"], forced)
        self.assertEqual(new_session["assignment_source"], "OPERATOR_FORCED")

    def test_safe_mode_is_global_persistent_and_does_not_rewrite_assignment(self):
        backend = InMemoryExperimentPersistence()
        first_controller = controller(backend)
        assignment = first_controller.assign("safe-session", "mysql", "192.0.2.9")
        first_controller.set_safe_mode(True, "operator", "freeze dynamic decisions")

        restarted = controller(backend)
        restored = restarted.get_assignment("safe-session")
        self.assertEqual(restored["assigned_arm"], assignment["assigned_arm"])
        self.assertEqual(restored["effective_mode"], "SAFE_MODE")
        self.assertTrue(restored["safe_mode"])
        blocked = restarted.claim_event(
            "safe-session", "advance-while-safe", 0, advance_revision=True
        )
        self.assertEqual(blocked["status"], "SAFE_MODE")
        self.assertEqual(restored["world_revision"], 0)

        restarted.set_safe_mode(False, "operator", "prepare duplicate priority test")
        accepted = restarted.claim_event(
            "safe-session", "accepted-before-freeze", 0, advance_revision=True
        )
        self.assertEqual(accepted["status"], "ACCEPTED")
        restarted.set_safe_mode(True, "operator", "freeze again")
        replay = restarted.claim_event(
            "safe-session", "accepted-before-freeze", 0, advance_revision=True
        )
        self.assertEqual(replay["status"], "DUPLICATE")
        self.assertEqual(replay["world_revision"], 1)

    def test_duplicate_event_and_stale_revision_are_rejected_atomically(self):
        ctl = controller()
        ctl.assign("revision-session", "postgres", "198.51.100.20")

        accepted = ctl.claim_event(
            "revision-session", "event-1", 0, advance_revision=True
        )
        duplicate = ctl.claim_event(
            "revision-session", "event-1", 0, advance_revision=True
        )
        stale = ctl.claim_event(
            "revision-session", "event-2", 0, advance_revision=True
        )
        next_event = ctl.claim_event(
            "revision-session", "event-2", 1, advance_revision=True
        )

        self.assertEqual(accepted["status"], "ACCEPTED")
        self.assertEqual(accepted["world_revision"], 1)
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(duplicate["world_revision"], 1)
        self.assertEqual(stale["status"], "STALE_REVISION")
        self.assertEqual(next_event["status"], "ACCEPTED")
        self.assertEqual(next_event["world_revision"], 2)
        self.assertEqual(
            ctl.get_assignment("revision-session")["processed_event_count"], 2
        )

    def test_processed_event_history_is_bounded(self):
        ctl = controller(max_events=3)
        ctl.assign("bounded", "postgres", "198.51.100.21")
        for index in range(5):
            result = ctl.claim_event("bounded", f"event-{index}", 0)
            self.assertEqual(result["status"], "ACCEPTED")
        self.assertEqual(ctl.get_assignment("bounded")["processed_event_count"], 3)
        self.assertEqual(
            ctl.claim_event("bounded", "event-4", 0)["status"], "DUPLICATE"
        )

    def test_concurrent_first_assignment_has_one_persisted_result(self):
        backend = InMemoryExperimentPersistence()
        ctl = controller(backend)

        def assign(value):
            return ctl.assign("concurrent", "postgres", value)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(assign, [f"cohort-{index}" for index in range(20)]))
        persisted = ctl.get_assignment("concurrent")
        self.assertEqual(backend.count_assignments(), 1)
        self.assertTrue(all(item["assigned_arm"] == persisted["assigned_arm"] for item in results))
        self.assertTrue(all(item["cohort_hmac"] == persisted["cohort_hmac"] for item in results))

    def test_unavailable_persistence_fails_closed_to_static_safe_mode(self):
        ctl = ExperimentAssignmentController(None, persistence_required=True)
        assignment = ctl.assign("fallback", "postgres", "198.51.100.8")
        self.assertEqual(assignment["assigned_arm"], "A")
        self.assertEqual(assignment["effective_mode"], "SAFE_MODE")
        self.assertFalse(assignment["persisted"])
        self.assertFalse(ctl.readiness_ok())
        self.assertFalse(ctl.status()["dynamic_execution_enabled"])

    def test_rollback_enables_safe_mode_and_forces_new_static_assignments(self):
        ctl = controller()
        ctl.set_forced_arm("D", "operator", "prepare bounded test")
        result = ctl.rollback_safe("operator", "return to deterministic baseline")
        self.assertTrue(result["safe_mode"])
        self.assertEqual(result["forced_arm"], "A")
        self.assertEqual(result["control_version"], CONTROL_VERSION)
        assignment = ctl.assign("after-rollback", "postgres", "198.51.100.9")
        self.assertEqual(assignment["assigned_arm"], "A")
        self.assertEqual(assignment["effective_mode"], "SAFE_MODE")


class ExperimentStateIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.backend = InMemoryExperimentPersistence()
        self.controller = controller(self.backend)
        self.store = AuthoritativeStateStore(
            max_sessions=20, experiment_controller=self.controller
        )

    def test_authoritative_projection_exposes_only_hashed_cohort(self):
        self.store.apply_proxy_event(proxy_event())
        state = self.store.get("d1-session")
        self.assertEqual(state["experiment_assignment_version"], ASSIGNMENT_VERSION)
        self.assertIn(state["experiment_arm"], {"A", "B", "C", "D"})
        self.assertEqual(len(state["experiment_cohort_hmac"]), 64)
        self.assertTrue(state["experiment_persisted"])
        self.assertNotIn("198.51.100.10", json.dumps(self.backend.list_assignments(10)))

    def test_mitre_first_does_not_preempt_proxy_cohort_assignment(self):
        self.store.apply_mitre_event({
            "session_id": "mitre-first",
            "timestamp": "2026-09-01T09:59:59Z",
            "phase": "discovery",
            "risk_score": 2.0,
        })
        before = self.store.get("mitre-first")
        self.assertEqual(before["experiment_arm"], "")
        self.assertIsNone(self.controller.get_assignment("mitre-first"))

        self.store.apply_proxy_event(proxy_event(
            session_id="mitre-first",
            source_ip="203.0.113.77",
            protocol="postgresql",
        ))
        after = self.store.get("mitre-first")
        assignment = self.controller.get_assignment("mitre-first")
        self.assertEqual(after["experiment_arm"], assignment["assigned_arm"])
        self.assertEqual(assignment["protocol"], "postgres")
        self.assertNotIn("203.0.113.77", json.dumps(self.backend.list_assignments(10)))

    def test_http_control_contract_is_strict_and_audited(self):
        self.store.apply_proxy_event(proxy_event())
        self.store.ready = True
        server = start_state_api(self.store, "127.0.0.1", 0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]

        with urlopen(f"http://127.0.0.1:{port}/experiment/status", timeout=2) as response:
            status = json.load(response)
        self.assertTrue(status["persistence_available"])
        self.assertFalse(status["dynamic_execution_enabled"])

        request = Request(
            f"http://127.0.0.1:{port}/experiment/control/safe-mode",
            data=json.dumps({
                "enabled": True,
                "actor": "test-operator",
                "reason": "D1 API validation",
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            control = json.load(response)
        self.assertTrue(control["safe_mode"])
        self.assertEqual(control["audit"][-1]["action"], "set_safe_mode")

        invalid = Request(
            f"http://127.0.0.1:{port}/experiment/control/forced-arm",
            data=b'{"arm":"Z","actor":"test","reason":"invalid"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(invalid, timeout=2)
        self.assertEqual(raised.exception.code, 400)

        unknown = Request(
            f"http://127.0.0.1:{port}/experiment/control/safe-mode",
            data=b'{"enabled":false,"actor":"test","reason":"x","unknown":1}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(unknown, timeout=2)
        self.assertEqual(raised.exception.code, 400)


if __name__ == "__main__":
    unittest.main()

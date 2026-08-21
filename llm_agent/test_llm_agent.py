import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import main


def evidence(session_id="benign-1", risk="low", trap=False):
    return {
        "session_id": session_id,
        "source_ip_hash": "hmac-sha256:test",
        "protocol": "postgres",
        "query_raw": "select 1",
        "query_normalized": "select ?",
        "trap_triggered": trap,
        "mitre_technique": ["T1213.006"] if trap else [],
        "risk_score": 12.0 if trap else 0.1,
        "risk_level": risk,
        "connection_events": [{"event_id": "c1", "event_type": "session_start", "timestamp": "2026-01-01T00:00:00Z"}],
        "queries": [{"event_id": "q1", "query_normalized": "select ?", "timestamp": "2026-01-01T00:00:01Z"}],
        "mitre_events": [],
        "scaling_events": [{"scale_event_id": "s1", "timestamp": "2026-01-01T00:00:02Z", "replica_target": 3 if trap else 1, "reason": "test"}],
        "trace": {"complete": True},
    }


def sandbox(session_id="trap-1"):
    return {
        "available": True,
        "hardening_report_id": "hardening-1",
        "session_id": session_id,
        "protocol": "postgres",
        "status": "verified",
        "recommendation_count": 1,
        "before": {"executed_count": 1},
        "recommendations": [{
            "issue": "Sensitive table readable",
            "severity": "high",
            "affected_object": "api_keys_backup",
            "recommended_fix": "Revoke SELECT from the exposed sandbox role.",
            "verification_step": "Replay and confirm access denied.",
        }],
        "verification": {"verified_count": 1, "after": {"failed_count": 1}},
    }


class ReportBuilderTests(unittest.TestCase):
    def test_benign_session_is_grounded_and_low(self):
        report = main.build_report(evidence())
        self.assertEqual(report["risk_level"], "low")
        self.assertFalse(report["safety"]["scaling_control"])
        self.assertFalse(report["safety"]["real_database_access"])
        self.assertIn("E2", {item["citation_id"] for item in report["citations"]})

    def test_trap_session_preserves_deterministic_risk(self):
        report = main.build_report(evidence("trap-1", "critical", True))
        self.assertEqual(report["risk_level"], "critical")
        self.assertIn("triggered a database deception trap", report["executive_summary"])
        self.assertEqual(report["decision_authority"], "none; risk and scaling facts are copied from deterministic modules")

    def test_matching_sandbox_result_is_included(self):
        report = main.build_report(evidence("trap-1", "critical", True), sandbox())
        self.assertTrue(report["sandbox_assessment"]["available"])
        self.assertEqual(report["sandbox_assessment"]["verified_count"], 1)
        self.assertIn("Revoke SELECT from the exposed sandbox role.", report["recommended_actions"])

    def test_other_session_sandbox_result_is_not_misattributed(self):
        report = main.build_report(evidence("trap-2", "critical", True), sandbox("trap-1"))
        self.assertFalse(report["sandbox_assessment"]["available"])

    def test_report_id_is_deterministic_for_same_evidence(self):
        first = main.build_report(evidence())
        second = main.build_report(evidence())
        self.assertEqual(first["report_id"], second["report_id"])
        self.assertEqual(first["evidence_snapshot_sha256"], second["evidence_snapshot_sha256"])

    def test_prior_report_links_do_not_change_report_identity(self):
        first_evidence = evidence()
        second_evidence = evidence()
        second_evidence["ai_report_id"] = "prior-report"
        second_evidence["ai_reports"] = [{"ai_report_id": "prior-report"}]
        second_evidence["last_seen"] = "2099-01-01T00:00:00Z"
        second_evidence["timestamp"] = "2099-01-01T00:00:00Z"
        self.assertEqual(
            main.build_report(first_evidence)["report_id"],
            main.build_report(second_evidence)["report_id"],
        )


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    @patch("main.link_report", return_value={"linked": True, "stored_new": True, "destination": "evidence-store"})
    @patch("main.fetch_json")
    def test_create_and_get_report(self, fetch, _link):
        fetch.side_effect = [evidence(), {"available": False}]
        created = self.client.post("/llm/report/session/benign-1", json={"include_sandbox": True})
        self.assertEqual(created.status_code, 200)
        self.assertTrue(created.json()["evidence_link"]["linked"])
        report_id = created.json()["report_id"]
        loaded = self.client.get(f"/llm/report/{report_id}")
        self.assertEqual(loaded.status_code, 200)
        self.assertEqual(loaded.json()["session_id"], "benign-1")

    @patch("main.fetch_json")
    def test_missing_evidence_returns_404(self, fetch):
        from fastapi import HTTPException
        fetch.side_effect = HTTPException(status_code=404, detail="session evidence not found")
        response = self.client.post("/llm/report/session/missing-1", json={})
        self.assertEqual(response.status_code, 404)

    def test_rejects_free_form_or_invalid_session_identifier(self):
        response = self.client.post(
            "/llm/report/session/benign-1",
            json={"prompt": "scan target"},
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch

from main import brief_to_markdown, build_brief, metric_values_consistent


class HardeningBriefTests(unittest.TestCase):
    def test_markdown_includes_before_after_hardening_verification(self):
        brief = {
            "report_id": "ai-report-1",
            "generated_at": "2026-08-20T00:00:00+00:00",
            "risk_level": "high",
            "summary": "Synthetic high-risk activity.",
            "scaling_interpretation": {
                "scale_pressure": 0.7,
                "current_replicas": 3,
                "trap_triggers": 1,
                "prometheus_trap_triggers": 1,
                "scaling_agent_trap_triggers": 1,
                "trap_metric_consistent": True,
                "trap_metric_source": "scaling-agent persisted state",
                "avg_actor_risk": 80,
                "control_mode": "manual",
                "safe_mode": True,
                "autoscaling_enabled": True,
                "manual_replica_target": 3,
                "max_replica_budget": 4,
                "decision": "scale-up pressure present",
            },
            "evidence": {
                "recent_scale_events": [],
                "sandbox_hardening": {
                    "available": True,
                    "hardening_report_id": "hardening-1",
                    "session_id": "session-1",
                    "status": "verified",
                    "recommendation_count": 1,
                    "verification": {
                        "before": {"executed_count": 1, "failed_count": 0},
                        "after": {"executed_count": 0, "failed_count": 1},
                        "verified_count": 1,
                    },
                },
            },
            "recommended_response": ["Review the verified fix."],
        }

        markdown = brief_to_markdown(brief)
        self.assertIn("## Sandbox Hardening Verification", markdown)
        self.assertIn("`hardening-1`", markdown)
        self.assertIn("Before: executed `1`, failed `0`", markdown)
        self.assertIn("After: executed `0`, failed `1`", markdown)
        self.assertIn("Status: `verified`", markdown)
        self.assertIn("Trap metric consistent: `True`", markdown)
        self.assertIn("Control mode: `manual`", markdown)
        self.assertIn("Safe mode: `True`", markdown)
        self.assertIn("Manual replica target: `3`", markdown)
        self.assertIn("Max replica budget: `4`", markdown)

    def test_trap_metric_consistency_requires_equal_present_values(self):
        self.assertTrue(metric_values_consistent("3", 3.0))
        self.assertFalse(metric_values_consistent("2", 3.0))
        self.assertFalse(metric_values_consistent(None, 0.0))

    @patch("main.prometheus_query")
    @patch("main.get_json")
    def test_brief_explains_manual_operator_control(self, get_json, prometheus_query):
        get_json.side_effect = [
            {
                "scale_pressure": 0.9,
                "current_replicas": 3,
                "trap_triggers": 1,
                "control_mode": "manual",
                "control": {
                    "safe_mode": True,
                    "autoscaling_enabled": True,
                    "manual_replica_target": 3,
                    "max_replica_budget": 4,
                },
            },
            {"events": []},
            {"available": False},
        ]
        prometheus_query.return_value = {"value": None, "status": "success"}

        brief = build_brief()

        interpretation = brief["scaling_interpretation"]
        self.assertEqual(interpretation["control_mode"], "manual")
        self.assertEqual(interpretation["manual_replica_target"], 3)
        self.assertIn("manual override active at 3 replicas", interpretation["decision"])
        self.assertTrue(any("manual replica target of 3" in item for item in brief["recommended_response"]))


if __name__ == "__main__":
    unittest.main()

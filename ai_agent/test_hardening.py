import unittest

from main import brief_to_markdown, metric_values_consistent


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

    def test_trap_metric_consistency_requires_equal_present_values(self):
        self.assertTrue(metric_values_consistent("3", 3.0))
        self.assertFalse(metric_values_consistent("2", 3.0))
        self.assertFalse(metric_values_consistent(None, 0.0))


if __name__ == "__main__":
    unittest.main()

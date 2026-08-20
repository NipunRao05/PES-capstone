import unittest

from pydantic import ValidationError

from main import HardeningRequest, build_hardening_recommendations, split_object_identifier


def replay_with(finding):
    return {
        "replay_id": "replay-test-1",
        "session_id": "session-test-1",
        "protocol": "postgres",
        "query_count": 1,
        "executed_count": 1 if finding["replay_mode"] == "executed" else 0,
        "simulated_count": 0,
        "blocked_count": 1 if finding["replay_mode"] == "blocked" else 0,
        "timeout_count": 1 if finding["replay_mode"] == "timed_out" else 0,
        "failed_count": 0,
        "findings": [finding],
    }


class HardeningRecommendationTests(unittest.TestCase):
    def test_hardening_request_rejects_caller_supplied_sql(self):
        with self.assertRaises(ValidationError):
            HardeningRequest(sql="GRANT ALL PRIVILEGES")

    def test_sensitive_read_generates_required_actionable_fields(self):
        replay = replay_with(
            {
                "query": "SELECT * FROM api_keys_backup",
                "query_normalized": "SELECT * FROM api_keys_backup",
                "classification": "read_only",
                "replay_mode": "executed",
                "would_succeed": True,
                "severity": "info",
                "affected_object": "api_keys_backup",
            }
        )
        recommendations = build_hardening_recommendations(replay)
        self.assertEqual(len(recommendations), 1)
        recommendation = recommendations[0]
        for field in (
            "issue",
            "evidence",
            "affected_object",
            "severity",
            "recommended_fix",
            "verification_step",
        ):
            self.assertIn(field, recommendation)
        self.assertEqual(recommendation["action"]["type"], "revoke_select")

    def test_metadata_enumeration_generates_manual_visibility_review(self):
        replay = replay_with(
            {
                "query": "SELECT table_name FROM information_schema.tables",
                "query_normalized": "SELECT table_name FROM information_schema.tables",
                "classification": "read_only",
                "replay_mode": "executed",
                "would_succeed": True,
                "severity": "info",
                "affected_object": "information_schema.tables",
            }
        )
        recommendation = build_hardening_recommendations(replay)[0]
        self.assertEqual(recommendation["action"]["type"], "manual_metadata_review")

    def test_timeout_generates_timeout_verification(self):
        replay = replay_with(
            {
                "query": "SELECT pg_sleep(5)",
                "query_normalized": "SELECT pg_sleep(5)",
                "classification": "resource_intensive_read",
                "replay_mode": "timed_out",
                "would_succeed": None,
                "severity": "medium",
                "affected_object": "",
            }
        )
        recommendation = build_hardening_recommendations(replay)[0]
        self.assertEqual(recommendation["action"]["type"], "verify_timeout_control")

    def test_destructive_block_generates_policy_verification(self):
        replay = replay_with(
            {
                "query": "DROP TABLE customers",
                "query_normalized": "DROP TABLE customers",
                "classification": "destructive_or_mutating",
                "replay_mode": "blocked",
                "would_succeed": None,
                "severity": "critical",
                "affected_object": "customers",
            }
        )
        recommendation = build_hardening_recommendations(replay)[0]
        self.assertEqual(recommendation["action"]["type"], "verify_policy_control")

    def test_fix_identifier_is_restricted_to_sandbox_schema(self):
        self.assertEqual(
            split_object_identifier("public.api_keys_backup", "postgres"),
            ("public", "api_keys_backup"),
        )
        with self.assertRaises(ValueError):
            split_object_identifier("production.customers", "postgres")
        with self.assertRaises(ValueError):
            split_object_identifier("customers; DROP TABLE orders", "postgres")


if __name__ == "__main__":
    unittest.main()

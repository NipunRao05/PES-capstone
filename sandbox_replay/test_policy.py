import unittest

from pydantic import ValidationError

from main import ReplayRequest, classify_query


class ReplayPolicyTests(unittest.TestCase):
    def test_replay_request_rejects_supplied_query_text(self):
        with self.assertRaises(ValidationError):
            ReplayRequest(mode="execute", query="DROP TABLE customers")

    def test_postgres_select_is_allowed(self):
        result = classify_query("SELECT * FROM api_keys_backup", "postgres")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["classification"], "read_only")

    def test_mysql_show_is_allowed(self):
        self.assertTrue(classify_query("SHOW TABLES", "mysql")["allowed"])

    def test_drop_is_blocked(self):
        result = classify_query("DROP TABLE api_keys_backup", "postgres")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["severity"], "critical")

    def test_delete_is_blocked(self):
        result = classify_query("DELETE FROM api_keys_backup", "mysql")
        self.assertFalse(result["allowed"])

    def test_multi_statement_is_blocked(self):
        result = classify_query("SELECT 1; DROP TABLE customers", "postgres")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["classification"], "unsafe_multi_statement")

    def test_file_access_function_is_blocked(self):
        result = classify_query("SELECT load_file('/etc/passwd')", "mysql")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["classification"], "unsafe_database_function")

    def test_sleep_is_allowed_only_with_timeout_classification(self):
        result = classify_query("SELECT pg_sleep(5)", "postgres")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["classification"], "resource_intensive_read")

    def test_cte_is_deny_by_default(self):
        result = classify_query("WITH x AS (SELECT 1) SELECT * FROM x", "postgres")
        self.assertFalse(result["allowed"])


if __name__ == "__main__":
    unittest.main()

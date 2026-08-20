import unittest

from main import bounded_text, redact_query, stable_id


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


if __name__ == "__main__":
    unittest.main()

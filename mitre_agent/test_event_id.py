import unittest

from models import make_mitre_event_id


class MitreEventIDTests(unittest.TestCase):
    def test_same_event_is_stable_within_normalized_timestamp_bucket(self):
        first = make_mitre_event_id(
            "session-1", "T1213.006", "R001", 1787217000.1, "query-hash"
        )
        replay = make_mitre_event_id(
            "session-1", "T1213.006", "R001", "2026-08-20T09:10:00.900Z", "query-hash"
        )
        self.assertEqual(first, replay)

    def test_identity_changes_when_evidence_changes(self):
        original = make_mitre_event_id(
            "session-1", "T1213.006", "R001", 1787217000, "query-hash"
        )
        changed = make_mitre_event_id(
            "session-1", "T1213.006", "R001", 1787217000, "other-query-hash"
        )
        self.assertNotEqual(original, changed)


if __name__ == "__main__":
    unittest.main()

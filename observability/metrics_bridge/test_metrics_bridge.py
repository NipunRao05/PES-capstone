import json
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.modules.setdefault("redis", MagicMock())
sys.modules.setdefault("requests", MagicMock())

import metrics_bridge as mb


class FakeRedis:
    def __init__(self, records):
        self.records = records
    def scan_iter(self, pattern, count=200):
        return iter(self.records.keys())
    def get(self, key):
        return self.records.get(key)


class TestMetricsBridge(unittest.TestCase):
    def test_prometheus_writer_declares_metric_once(self):
        pw = mb.PrometheusWriter()
        pw.gauge("x_metric", 1, labels={"a": "1"})
        pw.gauge("x_metric", 2, labels={"a": "2"})
        rendered = pw.render()
        self.assertEqual(rendered.count("# TYPE x_metric gauge"), 1)
        self.assertIn('x_metric{a="1"} 1', rendered)
        self.assertIn('x_metric{a="2"} 2', rendered)


    def test_prometheus_label_values_escape_newlines_and_quotes(self):
        pw = mb.PrometheusWriter()
        pw.gauge("x_label_escape", 1, labels={"persona": "bot\nquote\"slash\\"})
        rendered = pw.render()
        self.assertIn('persona="bot\\nquote\\"slash\\\\"', rendered)
        self.assertNotIn('bot\nquote', rendered)

    def test_redis_average_uses_successfully_parsed_actors(self):
        records = {
            "actor:1": json.dumps({
                "cumulative_risk": 10,
                "session_count": 2,
                "personas_seen": ["brute_bot"],
                "techniques_seen": ["T1110.001"],
                "phase_history": ["credential_access"],
            }),
            "actor:2": "not-json",
        }
        pw = mb.PrometheusWriter()
        with patch.object(mb, "_redis", FakeRedis(records)):
            mb.scrape_redis_mitre(pw)
        rendered = pw.render()
        self.assertIn("capstone_mitre_actor_count 2", rendered)
        self.assertIn("capstone_mitre_parsed_actor_count 1", rendered)
        self.assertIn("capstone_mitre_actor_parse_errors 1", rendered)
        self.assertIn("capstone_mitre_avg_actor_risk 10.0", rendered)

    def test_scaling_agent_exports_canonical_persisted_trap_counter(self):
        pw = mb.PrometheusWriter()
        with patch.object(mb, "_get_json", return_value={
            "trap_triggers": 7,
            "duplicate_events": 5,
            "processed_event_count": 2,
        }):
            data = mb.scrape_scaling_agent(pw)
        rendered = pw.render()
        self.assertEqual(data["trap_triggers"], 7)
        self.assertIn("capstone_mitre_trap_triggers_total 7", rendered)
        self.assertIn("capstone_scaling_trap_triggers 7", rendered)
        self.assertIn("capstone_scaling_duplicate_events_total 5", rendered)
        self.assertIn("capstone_scaling_processed_event_ids 2", rendered)

    def test_redis_trap_sum_is_diagnostic_not_canonical(self):
        records = {
            "actor:1": json.dumps({"trap_triggers": 3}),
            "actor:2": json.dumps({"trap_triggers": 2}),
        }
        pw = mb.PrometheusWriter()
        with patch.object(mb, "_redis", FakeRedis(records)):
            mb.scrape_redis_mitre(pw)
        rendered = pw.render()
        self.assertIn("capstone_mitre_actor_profile_trap_triggers 5", rendered)
        self.assertNotIn("capstone_mitre_trap_triggers_total", rendered)


if __name__ == "__main__":
    unittest.main()

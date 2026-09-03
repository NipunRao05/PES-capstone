import json
import unittest

from authoritative_state import AuthoritativeStateStore
from behavior_state import BehaviorStateStore, FEATURE_VERSION


def query(session_id, sql, timestamp, **overrides):
    event = {
        "session_id": session_id,
        "event_type": "query",
        "timestamp": timestamp,
        "protocol": "postgresql",
        "query_normalized": sql,
        "outcome_verified": True,
        "success": True,
        "authority": "backend",
    }
    event.update(overrides)
    return event


class BehaviorStateTests(unittest.TestCase):
    def test_benign_session_has_bounded_zero_interest_features(self):
        store = BehaviorStateStore()
        store.apply_proxy_event(query("benign", "select id from products", "2026-01-01T00:00:00Z"))
        state = store.get("benign")
        self.assertEqual(state["feature_version"], FEATURE_VERSION)
        self.assertEqual(state["protocol"], "postgres")
        self.assertEqual(state["query_count"], 1)
        self.assertEqual(state["catalog_query_count"], 0)
        self.assertEqual(state["trap_trigger_count"], 0)
        self.assertEqual(state["risk_score"], 0.0)

    def test_hostile_profile_produces_expected_structured_counts(self):
        store = BehaviorStateStore()
        events = [
            query("risk", "select * from information_schema.tables", "2026-01-01T00:00:00Z"),
            query("risk", "select * from api_keys_backup", "2026-01-01T00:00:10Z",
                  authority="deception"),
            query("risk", "select * from prod_credentials", "2026-01-01T00:00:20Z",
                  authority="deception"),
            query("risk", "select * from salary_executives", "2026-01-01T00:00:30Z",
                  authority="deception"),
            query("risk", "show grants", "2026-01-01T00:00:40Z"),
            query("risk", "grant all on hr.* to analyst", "2026-01-01T00:00:50Z"),
            query("risk", "drop table audit_log", "2026-01-01T00:01:00Z"),
        ]
        for event in events:
            store.apply_proxy_event(event)
        store.apply_mitre_event({
            "session_id": "risk", "timestamp": "2026-01-01T00:01:00Z",
            "phase": "data_discovery", "risk_score": 9,
            "technique_id": "T1213.006",
        })
        state = store.get("risk")
        self.assertEqual(state["catalog_query_count"], 1)
        self.assertGreaterEqual(state["metadata_query_count"], 2)
        self.assertEqual(state["credential_keyword_count"], 2)
        self.assertEqual(state["backup_keyword_count"], 1)
        self.assertEqual(state["sensitive_table_interest"], 1)
        self.assertEqual(state["role_enumeration_count"], 1)
        self.assertEqual(state["privilege_escalation_attempts"], 1)
        self.assertEqual(state["destructive_query_count"], 1)
        self.assertEqual(state["trap_trigger_count"], 3)
        self.assertEqual(state["mitre_technique_count"], 1)
        self.assertEqual(state["risk_score"], 0.75)
        self.assertEqual(state["session_duration_seconds"], 60.0)
        self.assertEqual(state["queries_per_minute"], 7.0)

    def test_same_events_in_different_order_generate_same_state(self):
        events = [
            query("stable", "select * from pg_catalog.pg_tables", "2026-01-01T00:00:00Z"),
            query("stable", "select * from backup_passwords", "2026-01-01T00:00:30Z",
                  authority="deception"),
            query("stable", "delete from customers where id = 1", "2026-01-01T00:01:00Z"),
        ]
        mitre = [
            {"session_id": "stable", "phase": "enumeration", "risk_score": 6,
             "technique_id": "T1087.002", "timestamp": "2026-01-01T00:00:20Z"},
            {"session_id": "stable", "phase": "exploitation", "risk_score": 8,
             "technique_id": "T1190", "timestamp": "2026-01-01T00:00:40Z"},
        ]
        first = BehaviorStateStore()
        second = BehaviorStateStore()
        for event in events:
            first.apply_proxy_event(event)
        for event in mitre:
            first.apply_mitre_event(event)
        for event in reversed(mitre):
            second.apply_mitre_event(event)
        for event in reversed(events):
            second.apply_proxy_event(event)
        self.assertEqual(first.get("stable"), second.get("stable"))

    def test_raw_sql_and_identity_fields_are_not_exposed(self):
        store = BehaviorStateStore()
        secret = "select 'do-not-retain-this-secret' from prod_credentials"
        store.apply_proxy_event(query("redacted", secret, "2026-01-01T00:00:00Z"))
        encoded = json.dumps(store.get("redacted"), sort_keys=True)
        self.assertNotIn("do-not-retain-this-secret", encoded)
        self.assertNotIn("query_normalized", encoded)
        self.assertNotIn("source_ip", encoded)
        self.assertNotIn("db_user", encoded)

    def test_string_literal_keywords_do_not_inflate_interest(self):
        store = BehaviorStateStore()
        store.apply_proxy_event(query(
            "literal", "select 'password backup token' from products",
            "2026-01-01T00:00:00Z",
        ))
        state = store.get("literal")
        self.assertEqual(state["credential_keyword_count"], 0)
        self.assertEqual(state["backup_keyword_count"], 0)

    def test_trap_requires_confirmed_deception_outcome(self):
        store = BehaviorStateStore()
        store.apply_proxy_event(query(
            "trap", "select * from api_keys_backup", "2026-01-01T00:00:00Z",
            outcome_verified=False, authority="deception",
        ))
        store.apply_proxy_event(query(
            "trap", "select * from api_keys_backup", "2026-01-01T00:00:01Z",
            authority="backend",
        ))
        self.assertEqual(store.get("trap")["trap_trigger_count"], 0)

    def test_declared_function_trap_does_not_need_a_name_list(self):
        store = BehaviorStateStore()
        store.apply_proxy_event(query(
            "function-trap", "select * from harmless_helper()",
            "2026-01-01T00:00:00Z", authority="deception",
            trap_triggered=True, trap_id="CUSTOM-FUNCTION-001",
        ))
        self.assertEqual(store.get("function-trap")["trap_trigger_count"], 1)

    def test_malformed_values_are_deterministic_and_bounded(self):
        store = BehaviorStateStore(max_sessions=1)
        store.apply_proxy_event({
            "session_id": "bad", "event_type": "query", "timestamp": "invalid",
            "protocol": "MYSQL-extra", "query_normalized": "x" * 100000,
        })
        store.apply_mitre_event({
            "session_id": "bad", "risk_score": float("nan"),
            "techniques_matched": [None, {}, {"technique_id": "T1"}],
        })
        state = store.get("bad")
        self.assertEqual(state["protocol"], "mysql")
        self.assertEqual(state["risk_score"], 0.0)
        self.assertEqual(state["session_duration_seconds"], 0.0)
        self.assertEqual(state["mitre_technique_count"], 1)

    def test_strategy_history_uses_structured_ids_only(self):
        store = BehaviorStateStore()
        store.apply_proxy_event(query(
            "strategy", "select 1", "2026-01-01T00:00:00Z", strategy_id="D1"
        ))
        store.apply_proxy_event(query(
            "strategy", "select 2", "2026-01-01T00:00:01Z", strategy_id="../bad"
        ))
        store.apply_proxy_event(query(
            "strategy", "select 3", "2026-01-01T00:00:02Z", strategy_id="D2"
        ))
        state = store.get("strategy")
        self.assertEqual(state["current_strategy"], "D2")
        self.assertEqual(state["previous_strategies"], ["D0", "D1"])

    def test_auth_fail_is_counted_without_query_text(self):
        store = BehaviorStateStore()
        store.apply_proxy_event({
            "session_id": "auth", "event_type": "auth", "success": "false",
            "timestamp": "2026-01-01T00:00:00Z", "protocol": "mysql",
        })
        state = store.get("auth")
        self.assertEqual(state["failed_auth_count"], 1)
        self.assertEqual(state["query_count"], 0)

    def test_authoritative_store_exposes_behavior_endpoint_data(self):
        store = AuthoritativeStateStore()
        store.apply_proxy_event(query(
            "integrated", "select * from pg_catalog.pg_tables",
            "2026-01-01T00:00:00Z",
        ), "PG")
        store.apply_mitre_event({
            "session_id": "integrated", "phase": "enumeration",
            "risk_score": 6, "technique_id": "T1213.006",
            "timestamp": "2026-01-01T00:00:01Z",
        })
        state = store.get_behavior("integrated")
        self.assertEqual(state["catalog_query_count"], 1)
        self.assertEqual(state["mitre_technique_count"], 1)
        self.assertEqual(len(store.list_behavior()), 1)


if __name__ == "__main__":
    unittest.main()

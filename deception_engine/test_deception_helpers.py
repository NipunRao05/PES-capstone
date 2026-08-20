import asyncio
import json
import sys
import unittest
from unittest.mock import MagicMock

sys.modules.setdefault("redis", MagicMock())

import api
from models import DecisionRequest


class TestLimitOffsetParsing(unittest.TestCase):
    def test_mysql_limit_offset_count_form(self):
        self.assertEqual(api._parse_limit_offset("select * from users limit 20, 10"), (10, 20))

    def test_limit_offset_keyword_form(self):
        self.assertEqual(api._parse_limit_offset("select * from users limit 25 offset 50"), (25, 50))

    def test_placeholder_limit_uses_safe_default(self):
        self.assertEqual(api._parse_limit_offset("select * from users limit ? offset ?"), (100, 0))

    def test_uppercase_limit_offset_is_parsed(self):
        self.assertEqual(api._parse_limit_offset("SELECT * FROM users LIMIT 10 OFFSET 20"), (10, 20))


class TestMutationCountConsistency(unittest.TestCase):
    def test_count_response_clamps_negative_delete_delta(self):
        old_schema = api._schema_loader
        old_generator = api._generator
        old_mutations = api._mutations
        old_exposure = api._exposure
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.get_table.return_value = {"row_count": 2, "exposure_depth": 1, "is_trap": False}
            api._generator = MagicMock()
            api._generator.generate_count.return_value = 2
            api._mutations = MagicMock()
            api._mutations.get_count_delta.return_value = -10
            api._exposure = MagicMock()

            req = DecisionRequest(
                session_id="s1",
                query_normalized="select count(*) from employees",
                fingerprint="select count(*) from employees",
                event_type="query",
                phase="",
                username="root",
                database="hr_production",
            )
            resp = asyncio.run(api._handle_count(req, req.query_normalized, "hr"))
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertEqual(payload["count"], 0)
            self.assertEqual(payload["rows"], [{"COUNT(*)": 0}])
        finally:
            api._schema_loader = old_schema
            api._generator = old_generator
            api._mutations = old_mutations
            api._exposure = old_exposure


class TestMutationUnknownTableHandling(unittest.TestCase):
    def test_unknown_insert_passthrough_does_not_record_empty_row(self):
        old_schema = api._schema_loader
        old_mutations = api._mutations
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.get_table.return_value = None
            api._mutations = MagicMock()

            req = DecisionRequest(
                session_id="s1",
                query_normalized="insert into definitely_unknown values (?)",
                fingerprint="insert into definitely_unknown values (?)",
                event_type="query",
                phase="",
                username="root",
                database="hr_production",
            )
            resp = asyncio.run(api._handle_mutation(req, req.query_normalized, "definitely_unknown", "hr"))
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertEqual(payload["mode"], "passthrough")
            api._mutations.record_insert.assert_not_called()
            api._mutations.record_update.assert_not_called()
            api._mutations.record_delete.assert_not_called()
        finally:
            api._schema_loader = old_schema
            api._mutations = old_mutations


class TestPostgresCatalogDeception(unittest.TestCase):
    def test_pg_database_query_uses_datname_column(self):
        old_schema = api._schema_loader
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.schema_for_database.return_value = "hr"
            req = DecisionRequest(
                session_id="s1",
                query_normalized="select datname from pg_database",
                fingerprint="select datname from pg_database",
                event_type="query",
                phase="recon",
                username="postgres",
                database="testdb",
                protocol="postgres",
            )
            resp = asyncio.run(api.decide(req))
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertEqual(payload["mode"], "fake")
            self.assertEqual(payload["columns"], ["datname"])
            self.assertIn("datname", payload["rows"][0])
        finally:
            api._schema_loader = old_schema

    def test_pg_tables_query_uses_pg_catalog_columns(self):
        old_schema = api._schema_loader
        old_exposure = api._exposure
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.get_tables_at_depth.return_value = ["employees"]
            api._schema_loader.get_trap_tables.return_value = []
            api._exposure = MagicMock()
            api._exposure.get_depth.return_value = 1
            req = DecisionRequest(
                session_id="s1",
                query_normalized="select schemaname, tablename from pg_tables",
                fingerprint="select schemaname, tablename from pg_tables",
                event_type="query",
                phase="enumeration",
                username="postgres",
                database="testdb",
                protocol="postgres",
            )
            resp = asyncio.run(api._handle_show_tables(req, "hr"))
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertEqual(payload["columns"], ["schemaname", "tablename"])
            self.assertEqual(payload["rows"], [{"schemaname": "public", "tablename": "employees"}])
        finally:
            api._schema_loader = old_schema
            api._exposure = old_exposure


class TestPostgresSystemInfoDeception(unittest.TestCase):
    def _req(self, query: str, username: str = "analyst", database: str = "customerdb") -> DecisionRequest:
        return DecisionRequest(
            session_id="pg-system",
            query_normalized=query,
            fingerprint=query,
            event_type="query",
            phase="recon",
            username=username,
            database=database,
            protocol="postgres",
        )

    def test_postgres_version_uses_native_column_name(self):
        resp = api._system_var_response(self._req("select version()"), "select version()")
        payload = json.loads(resp.body.decode("utf-8"))
        self.assertEqual(payload["mode"], "fake")
        self.assertEqual(payload["columns"], ["version"])
        self.assertIn("PostgreSQL", payload["rows"][0]["version"])

    def test_postgres_current_database_uses_request_database(self):
        resp = api._system_var_response(self._req("select current_database()", database="finance_prod"), "select current_database()")
        payload = json.loads(resp.body.decode("utf-8"))
        self.assertEqual(payload["columns"], ["current_database"])
        self.assertEqual(payload["rows"], [{"current_database": "finance_prod"}])

    def test_postgres_current_user_uses_request_username(self):
        resp = api._system_var_response(self._req("select current_user", username="readonly"), "select current_user")
        payload = json.loads(resp.body.decode("utf-8"))
        self.assertEqual(payload["columns"], ["current_user"])
        self.assertEqual(payload["rows"], [{"current_user": "readonly"}])



class TestPostgresSchemaAndCountShapes(unittest.TestCase):
    def test_information_schema_schemata_uses_schema_name_column(self):
        old_schema = api._schema_loader
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.schema_for_database.return_value = "hr"
            req = DecisionRequest(
                session_id="pg-schema",
                query_normalized="select schema_name from information_schema.schemata",
                fingerprint="select schema_name from information_schema.schemata",
                event_type="query",
                phase="enumeration",
                username="postgres",
                database="testdb",
                protocol="postgres",
            )
            resp = asyncio.run(api.decide(req))
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertEqual(payload["mode"], "fake")
            self.assertEqual(payload["columns"], ["schema_name"])
            self.assertIn("schema_name", payload["rows"][0])
        finally:
            api._schema_loader = old_schema

    def test_postgres_count_uses_count_column(self):
        old_schema = api._schema_loader
        old_generator = api._generator
        old_mutations = api._mutations
        old_exposure = api._exposure
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.get_table.return_value = {"row_count": 9, "exposure_depth": 1, "is_trap": False}
            api._generator = MagicMock()
            api._generator.generate_count.return_value = 9
            api._mutations = MagicMock()
            api._mutations.get_count_delta.return_value = 0
            api._exposure = MagicMock()

            req = DecisionRequest(
                session_id="pg-count",
                query_normalized="select count(*) from employees",
                fingerprint="select count(*) from employees",
                event_type="query",
                phase="enumeration",
                username="postgres",
                database="testdb",
                protocol="postgres",
            )
            resp = asyncio.run(api._handle_count(req, req.query_normalized, "hr"))
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertEqual(payload["columns"], ["count"])
            self.assertEqual(payload["rows"], [{"count": 9}])
        finally:
            api._schema_loader = old_schema
            api._generator = old_generator
            api._mutations = old_mutations
            api._exposure = old_exposure


class TestGeneratorDeterminismAndSafeSecrets(unittest.TestCase):
    def test_date_values_are_deterministic_without_wall_clock(self):
        from generator import DataGenerator
        gen = DataGenerator()
        cols = [
            {"name": "created_on", "type": "past_date", "years_back": 2},
            {"name": "expires_on", "type": "future_date", "days_ahead": 30},
            {"name": "created_at", "type": "past_datetime", "days_back": 10},
        ]
        first = gen.generate_rows(cols, row_count=10, session_id="s", table_name="t", limit=3, offset=0)
        second = gen.generate_rows(cols, row_count=10, session_id="s", table_name="t", limit=3, offset=0)
        self.assertEqual(first, second)
        for row in first:
            self.assertLessEqual(row["created_on"], "2024-01-01")
            self.assertGreaterEqual(row["expires_on"], "2024-01-01")

    def test_sensitive_financial_values_are_marked_as_decoys(self):
        from generator import DataGenerator
        gen = DataGenerator()
        cols = [
            {"name": "ssn", "type": "ssn"},
            {"name": "card", "type": "credit_card_number"},
            {"name": "iban", "type": "iban"},
            {"name": "routing", "type": "routing"},
        ]
        row = gen.generate_rows(cols, row_count=1, session_id="s", table_name="secrets", limit=1)[0]
        self.assertTrue(row["ssn"].startswith("DECOY_SSN_"))
        self.assertTrue(row["card"].startswith("DECOY_CC_"))
        self.assertTrue(row["iban"].startswith("DECOY_IBAN_"))
        self.assertTrue(row["routing"].startswith("DECOY_ROUTING_"))


class TestMutationStoreRobustness(unittest.TestCase):
    class FakeRedis:
        def __init__(self, payload):
            self.payload = payload
        def get(self, key):
            return self.payload

    def test_count_delta_malformed_value_falls_back_to_zero(self):
        from mutation_store import MutationStore
        store = MutationStore(self.FakeRedis(json.dumps({"count_delta": "not-an-int"})))
        self.assertEqual(store.get_count_delta("s", "t"), 0)

    def test_inserted_rows_filters_malformed_entries(self):
        from mutation_store import MutationStore
        store = MutationStore(self.FakeRedis(json.dumps({"inserts": [{"id": 1}, "bad", [1, 2]]})))
        self.assertEqual(store.get_inserted_rows("s", "t"), [{"id": 1}])


class TestExposureDepthRobustness(unittest.TestCase):
    class FakeRedis:
        def __init__(self, value):
            self.value = value
        def hget(self, key, field):
            return self.value

    def test_depth_is_clamped_to_valid_range(self):
        from exposure import ExposureTracker
        self.assertEqual(ExposureTracker(self.FakeRedis("999")).get_depth("s"), 3)
        self.assertEqual(ExposureTracker(self.FakeRedis("-5")).get_depth("s"), 1)


class TestHealthReadinessEndpoints(unittest.TestCase):
    def test_healthz_is_liveness_without_redis_ping(self):
        old_schema = api._schema_loader
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.get_schema_names.return_value = ["hr"]
            payload = asyncio.run(api.health())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["schemas"], ["hr"])
        finally:
            api._schema_loader = old_schema

    def test_readyz_requires_schemas_components_and_redis_ping(self):
        old_schema = api._schema_loader
        old_generator = api._generator
        old_exposure = api._exposure
        old_mutations = api._mutations
        old_redis = api._redis_client
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.get_schema_names.return_value = ["hr"]
            api._generator = MagicMock()
            api._exposure = MagicMock()
            api._mutations = MagicMock()
            api._redis_client = MagicMock()
            api._redis_client.ping.return_value = True
            resp = asyncio.run(api.readyz())
            self.assertEqual(resp.status_code, 200)
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertTrue(payload["ready"])

            api._redis_client.ping.side_effect = RuntimeError("down")
            resp = asyncio.run(api.readyz())
            self.assertEqual(resp.status_code, 503)
            payload = json.loads(resp.body.decode("utf-8"))
            self.assertFalse(payload["ready"])
        finally:
            api._schema_loader = old_schema
            api._generator = old_generator
            api._exposure = old_exposure
            api._mutations = old_mutations
            api._redis_client = old_redis

if __name__ == "__main__":
    unittest.main()

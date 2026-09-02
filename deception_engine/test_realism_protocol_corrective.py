import asyncio
import json
import sys
import unittest
from dataclasses import asdict
from datetime import datetime
from unittest.mock import MagicMock

sys.modules.setdefault("redis", MagicMock())

import api
from generator import DataGenerator
from models import DecisionRequest
from mutation_store import MutationStore
from schema_loader import SchemaLoader


class RedisMemory:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def setex(self, key, _ttl, value):
        self.values[key] = value

    def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)

    def exists(self, key):
        return int(key in self.values)

    def scan_iter(self, pattern, count=200):
        prefix = pattern.rstrip("*")
        return iter([key for key in self.values if key.startswith(prefix)])


class ExposureMemory:
    def __init__(self):
        self.depths = {}
        self.accesses = []

    def get_depth(self, session_id):
        return self.depths.get(session_id, 1)

    def record_table_access(self, session_id, table, table_depth):
        current = self.get_depth(session_id)
        self.accesses.append((session_id, table, table_depth))
        if table_depth == current and current < 3:
            self.depths[session_id] = current + 1
        return self.get_depth(session_id)


class CorrectivePassTests(unittest.TestCase):
    def setUp(self):
        self.old = (api._schema_loader, api._generator, api._exposure, api._mutations)
        self.old_rate = api.DECIDE_RATE_LIMIT_ENABLED
        api._schema_loader = SchemaLoader()
        api._generator = DataGenerator()
        api._exposure = ExposureMemory()
        api._mutations = MutationStore(RedisMemory())
        api.DECIDE_RATE_LIMIT_ENABLED = False

    def tearDown(self):
        api._schema_loader, api._generator, api._exposure, api._mutations = self.old
        api.DECIDE_RATE_LIMIT_ENABLED = self.old_rate

    def request(self, query, *, protocol="postgres", session="corrective", database="testdb"):
        req = DecisionRequest(
            session_id=session, query_normalized=query, fingerprint=query,
            event_type="query", phase="data_discovery", username="postgres",
            database=database, protocol=protocol, deception_level=1,
        )
        response = asyncio.run(api.decide(MagicMock(), asdict(req)))
        return json.loads(response.body.decode())

    def test_hidden_access_is_denied_without_progression_for_both_protocols(self):
        for protocol, state in (("postgres", "42P01"), ("mysql", "42S02")):
            for query in (
                "select * from api_keys_backup",
                "update api_keys_backup set notes = 'x' where id = 1",
                "delete from api_keys_backup where id = 1",
            ):
                result = self.request(query, protocol=protocol, session=f"{protocol}-{query[:6]}")
                self.assertEqual(result["mode"], "block")
                self.assertEqual(result["sqlstate"], state)
        self.assertEqual(api._exposure.accesses, [])

    def test_normal_progression_exposes_trap(self):
        self.assertEqual(self.request("select id from employees")["mode"], "fake")
        self.assertEqual(api._exposure.get_depth("corrective"), 2)
        self.assertEqual(self.request("select id from api_keys")["mode"], "fake")
        self.assertEqual(api._exposure.get_depth("corrective"), 3)
        trap = self.request("select id from api_keys_backup")
        self.assertEqual(trap["mode"], "fake")
        self.assertTrue(trap["is_trap"])

    def test_unsupported_or_malformed_sql_fails_closed(self):
        cases = (
            "select * from employees where salary > 100000",
            "select * from employees where",
            "select nonexistent_column from employees",
            "select * from employees limit banana",
            "select * from employees order by id desc",
            "select table_name from information_schema.tables where table_name in ('employees')",
        )
        for query in cases:
            with self.subTest(query=query):
                self.assertEqual(self.request(query)["mode"], "block")

    def test_mysql_metadata_and_qualified_table_are_coherent(self):
        tables = self.request("show tables", protocol="mysql")
        described = self.request("describe employees", protocol="mysql")
        shown = self.request("show columns from employees", protocol="mysql")
        qualified = self.request("select id from testdb.employees where id = 1", protocol="mysql")
        self.assertIn("employees", [next(iter(row.values())) for row in tables["rows"]])
        self.assertEqual(described["rows"], shown["rows"])
        self.assertEqual(described["rows"][0]["Field"], "id")
        self.assertEqual(qualified["rows"], [{"id": 1}])

    def test_postgres_catalogs_and_catalog_identity_are_coherent(self):
        info = self.request("select table_catalog, table_name from information_schema.tables")
        pg_tables = self.request("select schemaname, tablename from pg_catalog.pg_tables")
        pg_class = self.request(
            "select n.nspname as \"schema\", c.relname as \"name\" from pg_catalog.pg_class c"
        )
        self.assertEqual({row["table_name"] for row in info["rows"]}, {row["tablename"] for row in pg_tables["rows"]})
        self.assertEqual({row["table_name"] for row in info["rows"]}, {row["Name"] for row in pg_class["rows"]})
        self.assertEqual({row["table_catalog"] for row in info["rows"]}, {"testdb"})

    def test_temporal_generation_relations_hold_and_are_deterministic(self):
        loader = SchemaLoader()
        generator = DataGenerator()
        for table, earlier, later in (
            ("sessions", "login_at", "logout_at"),
            ("api_keys", "created_at", "last_used"),
        ):
            columns = loader.get_columns("hr", table)
            first = generator.generate_rows(columns, 100, "temporal", table, 100)
            second = generator.generate_rows(columns, 100, "temporal", table, 100)
            self.assertEqual(first, second)
            for row in first:
                if row[earlier] is not None and row[later] is not None:
                    self.assertLessEqual(
                        datetime.fromisoformat(row[earlier]), datetime.fromisoformat(row[later])
                    )

    def test_session_end_cleans_transient_exposure_and_mutations(self):
        exposure, mutations, generator = MagicMock(), MagicMock(), MagicMock()
        api._exposure, api._mutations, api._generator = exposure, mutations, generator
        result = asyncio.run(api.session_end({"session_id": "closed-session"}))
        self.assertEqual(result, {"status": "ok"})
        exposure.cleanup_session.assert_called_once_with("closed-session")
        mutations.cleanup_session.assert_called_once_with("closed-session")
        generator.cleanup_session.assert_called_once_with("closed-session")


if __name__ == "__main__":
    unittest.main()

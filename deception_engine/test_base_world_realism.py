import asyncio
import json
import re
import sys
import unittest
from dataclasses import asdict
from decimal import Decimal
from unittest.mock import MagicMock

sys.modules.setdefault("redis", MagicMock())

import api
from generator import DataGenerator
from models import DecisionRequest
from mutation_store import MutationStore
from schema_loader import SchemaLoader


class BaseWorldFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader = SchemaLoader()
        cls.generator = DataGenerator()
        cls.tables = cls.loader.get_all_tables("hr")
        cls.employee_count = cls.generator.generate_count(
            cls.tables["employees"]["row_count"], "realism-session", "employees"
        )
        cls.employees = cls.generator.generate_organization_rows(
            schema_name="hr",
            table_name="employees",
            schema_tables=cls.tables,
            employee_count=cls.employee_count,
            session_id="realism-session",
        )
        cls.departments = cls.generator.generate_organization_rows(
            schema_name="hr",
            table_name="departments",
            schema_tables=cls.tables,
            employee_count=cls.employee_count,
            session_id="realism-session",
        )


class TestOrganizationIntegrity(BaseWorldFixture):
    def test_department_role_salary_and_identity_constraints(self):
        role_bands = self.generator.HR_ROLE_BANDS
        employee_ids = [row["id"] for row in self.employees]
        names = [row["full_name"] for row in self.employees]
        emails = [row["email"] for row in self.employees]

        self.assertEqual(len(employee_ids), len(set(employee_ids)))
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(emails), len(set(emails)))
        self.assertEqual(
            [row["name"] for row in self.departments],
            list(dict.fromkeys(row["name"] for row in self.departments)),
        )

        for row in self.employees:
            key = (row["job_title"], row["seniority_level"])
            configured = {
                (title, level): (minimum, maximum)
                for title, level, minimum, maximum in role_bands[row["department"]]
            }
            self.assertIn(key, configured)
            minimum, maximum = configured[key]
            self.assertGreaterEqual(row["salary"], minimum)
            self.assertLessEqual(row["salary"], maximum)
            email_local = re.sub(r"[^a-z0-9.]", "", row["full_name"].lower().replace(" ", "."))
            self.assertEqual(row["email"], f"{email_local}@company.internal")

    def test_manager_hierarchy_is_valid_and_acyclic(self):
        by_id = {row["id"]: row for row in self.employees}
        for row in self.employees:
            manager_id = row["manager_id"]
            if manager_id is None:
                self.assertEqual(row["seniority_level"], 6)
                continue
            self.assertIn(manager_id, by_id)
            self.assertNotEqual(manager_id, row["id"])
            manager = by_id[manager_id]
            self.assertGreater(manager["seniority_level"], row["seniority_level"])
            self.assertLess(manager["hire_date"], row["hire_date"])
            if row["seniority_level"] < 5:
                self.assertEqual(manager["department"], row["department"])

            visited = {row["id"]}
            current = row
            while current["manager_id"] is not None:
                self.assertNotIn(current["manager_id"], visited)
                visited.add(current["manager_id"])
                current = by_id[current["manager_id"]]

    def test_department_heads_counts_and_budgets_are_derived(self):
        by_id = {row["id"]: row for row in self.employees}
        employee_counts = {}
        for employee in self.employees:
            employee_counts[employee["department"]] = employee_counts.get(employee["department"], 0) + 1

        for department in self.departments:
            manager = by_id[department["manager_id"]]
            self.assertEqual(manager["department"], department["name"])
            self.assertGreaterEqual(manager["seniority_level"], 5)
            self.assertEqual(department["head_count"], employee_counts[department["name"]])
            self.assertRegex(department["budget_usd"], r"^[0-9]+\.[0-9]{2}$")
            budget = Decimal(department["budget_usd"])
            fixed, per_person = self.generator._DEPARTMENT_BUDGET_MODEL[department["name"]]
            modeled = fixed + per_person * department["head_count"]
            self.assertGreaterEqual(budget, modeled * Decimal("0.96"))
            self.assertLessEqual(budget, modeled * Decimal("1.04"))

    def test_fake_bcrypt_values_are_syntactically_realistic(self):
        pattern = re.compile(r"^\$2[aby]\$12\$[./A-Za-z0-9]{53}$")
        for row in self.employees:
            value = row["password_hash"]
            self.assertEqual(len(value), 60)
            self.assertRegex(value, pattern)
            self.assertNotRegex(value, r"(.)\1{12,}")
            self.assertNotRegex(value, r"HONEYPOT|FAKE|DECOY", re.IGNORECASE)

    def test_same_seed_produces_identical_world(self):
        other = DataGenerator()
        self.assertEqual(
            self.employees,
            other.generate_organization_rows(
                "hr", "employees", self.tables, self.employee_count, "realism-session"
            ),
        )
        self.assertEqual(
            self.departments,
            other.generate_organization_rows(
                "hr", "departments", self.tables, self.employee_count, "realism-session"
            ),
        )


class TestMetadataCatalog(BaseWorldFixture):
    def test_every_visible_table_has_columns_with_schema_types(self):
        tables = self.loader.get_metadata_tables("hr", 3)
        columns = self.loader.get_metadata_columns("hr", 3)
        by_table = {}
        for row in columns:
            by_table.setdefault(row["table_name"], []).append(row)

        self.assertEqual({row["table_name"] for row in tables}, set(by_table))
        for table_name, table_def in self.tables.items():
            actual = by_table[table_name]
            self.assertEqual(
                [row["column_name"] for row in actual],
                [column["name"] for column in table_def["columns"]],
            )
            self.assertTrue(all(row["data_type"] for row in actual))

    def _metadata(self, query):
        old = (api._schema_loader, api._generator, api._exposure, api._mutations)
        old_rate_limit = api.DECIDE_RATE_LIMIT_ENABLED
        try:
            api._schema_loader = self.loader
            api._generator = self.generator
            api._exposure = MagicMock()
            api._exposure.get_depth.return_value = 1
            api._mutations = MagicMock()
            api.DECIDE_RATE_LIMIT_ENABLED = False
            req = DecisionRequest(
                session_id="metadata-session",
                query_normalized=query,
                fingerprint=query,
                event_type="query",
                phase="enumeration",
                username="postgres",
                database="testdb",
                protocol="postgres",
            )
            response = asyncio.run(api.decide(MagicMock(), asdict(req)))
            return json.loads(response.body.decode("utf-8"))
        finally:
            api._schema_loader, api._generator, api._exposure, api._mutations = old
            api.DECIDE_RATE_LIMIT_ENABLED = old_rate_limit

    def test_table_equality_like_and_ilike_filters(self):
        equal = self._metadata(
            "select table_name from information_schema.tables "
            "where table_schema='public' and table_name='employees'"
        )
        like = self._metadata(
            "select table_name from information_schema.tables where table_name like '%ment%'"
        )
        ilike = self._metadata(
            "select table_name from information_schema.tables where table_name ilike '%EMPLOYEE%'"
        )
        self.assertEqual(equal["rows"], [{"table_name": "employees"}])
        self.assertEqual({row["table_name"] for row in like["rows"]}, {"departments"})
        self.assertEqual(ilike["rows"], [{"table_name": "employees"}])

    def test_column_metadata_projection_filtering_and_repeatability(self):
        query = (
            "select column_name, data_type from information_schema.columns "
            "where table_schema='public' and table_name='employees'"
        )
        first = self._metadata(query)
        second = self._metadata(query)
        expected = [column["name"] for column in self.tables["employees"]["columns"]]
        self.assertEqual(first["columns"], second["columns"])
        self.assertEqual(first["rows"], second["rows"])
        self.assertEqual(first["columns"], ["column_name", "data_type"])
        self.assertEqual([row["column_name"] for row in first["rows"]], expected)
        self.assertNotIn("budget_usd", {row["column_name"] for row in first["rows"]})

        filtered = self._metadata(
            "select table_name, column_name from information_schema.columns "
            "where column_name ilike '%manager%'"
        )
        self.assertTrue(filtered["rows"])
        self.assertTrue(all("manager" in row["column_name"].lower() for row in filtered["rows"]))


class TestDeceptionCompatibility(BaseWorldFixture):
    def test_trap_assets_and_depths_are_unchanged(self):
        expected = {"api_keys_backup", "salary_executives", "prod_credentials"}
        self.assertEqual(set(self.loader.get_trap_tables("hr")), expected)
        for name in expected:
            definition = self.loader.get_table("hr", name)
            self.assertTrue(definition["is_trap"])
            self.assertEqual(definition["exposure_depth"], 3)

    def test_mutations_remain_isolated_by_session(self):
        class RedisMemory:
            def __init__(self):
                self.values = {}

            def get(self, key):
                return self.values.get(key)

            def setex(self, key, _ttl, value):
                self.values[key] = value

        store = MutationStore(RedisMemory())
        store.record_insert("session-a", "employees", {"id": 9001})
        self.assertEqual(store.get_count_delta("session-a", "employees"), 1)
        self.assertEqual(store.get_count_delta("session-b", "employees"), 0)
        self.assertEqual(store.get_inserted_rows("session-a", "employees"), [{"id": 9001}])
        self.assertEqual(store.get_inserted_rows("session-b", "employees"), [])


if __name__ == "__main__":
    unittest.main()

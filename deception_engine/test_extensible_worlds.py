import asyncio
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock

import api
from models import DecisionRequest
from schema_loader import SchemaLoader


class ExposureMemory:
    def __init__(self, depth: int = 1, active_sessions: int = 0):
        self.depths = {}
        self.default_depth = depth
        self.active_sessions = active_sessions

    def get_depth(self, session_id):
        return self.depths.get(session_id, self.default_depth)

    def record_table_access(self, session_id, _asset_name, asset_depth):
        current = self.get_depth(session_id)
        if asset_depth >= current and current < 3:
            current += 1
        self.depths[session_id] = current
        return current

    def active_session_count(self):
        return self.active_sessions


class TestExtensibleWorlds(unittest.TestCase):
    def test_repository_world_is_auto_discovered(self):
        loader = SchemaLoader()
        self.assertIn("research", loader.get_schema_names())
        self.assertEqual(loader.schema_for_database("research_prod"), "research")
        self.assertIn("research_production", loader.get_database_names())
        function = loader.get_function("research", "legacy_token_export")
        self.assertIsNotNone(function)
        self.assertTrue(function["is_trap"])
        self.assertEqual(function["strategy_id"], "D3")
        self.assertNotIn("legacy_token_export", loader.get_functions_at_depth("research", 1))
        self.assertIn("legacy_token_export", loader.get_functions_at_depth("research", 2))

    def test_function_rows_are_synthetic_and_session_stable(self):
        try:
            from generator import DataGenerator
        except ModuleNotFoundError as exc:
            self.skipTest(f"runtime dependency unavailable: {exc}")
        loader = SchemaLoader()
        function = loader.get_function("research", "legacy_token_export")
        generator = DataGenerator()
        kwargs = dict(
            columns=function["columns"], row_count=function["row_count"],
            session_id="world-test-session",
            table_name="function:research.legacy_token_export", limit=3,
        )
        first = generator.generate_rows(**kwargs)
        second = generator.generate_rows(**kwargs)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 3)
        self.assertTrue(all(row["access_token"] for row in first))

    def test_executable_sql_in_function_definition_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "unsafe.yaml").write_text(
                """
schema: unsafe
settings: {database_name: unsafe}
tables:
  records:
    columns: [{name: id, type: pk_int}]
functions:
  unsafe_helper:
    exposure_depth: 1
    row_count: 1
    is_trap: true
    trap_id: UNSAFE-1
    trap_kind: credential_function
    strategy_id: D3
    sql: SELECT secret FROM production
    columns: [{name: token, type: api_key}]
""",
                encoding="utf-8",
            )
            loader = SchemaLoader(Path(temp))
            self.assertNotIn("unsafe", loader.get_schema_names())
            self.assertFalse(loader.is_valid)
            self.assertIn("unsupported keys", loader.get_load_errors()[0])

    def test_invalid_table_generator_duplicate_column_and_fk_fail_closed(self):
        invalid_worlds = {
            "generator": """
schema: generator
tables:
  records:
    columns: [{name: id, type: production_secret}]
""",
            "duplicate": """
schema: duplicate
tables:
  records:
    columns: [{name: id, type: pk_int}, {name: id, type: sentence}]
""",
            "foreign_key": """
schema: foreign_key
tables:
  records:
    columns: [{name: owner_id, type: fk, ref: missing.id}]
""",
            "trap_metadata": """
schema: trap_metadata
tables:
  secret_notes:
    is_trap: true
    columns: [{name: id, type: pk_int}]
""",
        }
        for name, content in invalid_worlds.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                Path(temp, f"{name}.yaml").write_text(content, encoding="utf-8")
                loader = SchemaLoader(Path(temp))
                self.assertFalse(loader.is_valid)
                self.assertEqual(loader.get_schema_names(), [])
                self.assertTrue(loader.get_load_errors())

    def test_repository_traps_have_complete_unique_identity(self):
        loader = SchemaLoader()
        self.assertTrue(loader.is_valid, loader.get_load_errors())
        trap_ids = []
        for world in loader.get_schema_names():
            assets = [
                *loader.get_all_tables(world).values(),
                *loader.get_all_functions(world).values(),
            ]
            for definition in assets:
                if definition.get("is_trap") is not True:
                    continue
                trap_ids.append(definition["trap_id"])
                self.assertRegex(definition["strategy_id"], r"^D\d+$")
                self.assertRegex(definition["mitre_technique_id"], r"^T\d{4}(?:\.\d{3})?$")
                self.assertGreater(float(definition["risk_score"]), 0)
        self.assertEqual(len(trap_ids), len(set(trap_ids)))

    def test_duplicate_trap_identity_across_worlds_fails_closed(self):
        template = """
schema: {world}
settings: {{database_name: {world}}}
tables:
  token_archive:
    is_trap: true
    trap_id: SHARED-TRAP-001
    trap_kind: credential_table
    strategy_id: D3
    mitre_technique_id: T1555
    risk_score: 12
    columns: [{{name: id, type: pk_int}}]
"""
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "alpha.yaml").write_text(template.format(world="alpha"), encoding="utf-8")
            Path(temp, "beta.yaml").write_text(template.format(world="beta"), encoding="utf-8")
            loader = SchemaLoader(Path(temp))
            self.assertFalse(loader.is_valid)
            self.assertIn("alpha", loader.get_schema_names())
            self.assertNotIn("beta", loader.get_schema_names())
            self.assertIn("duplicate trap_id", loader.get_load_errors()[0])


class TestExtensibleWorldAPI(unittest.TestCase):
    def setUp(self):
        self.old = (
            api._schema_loader, api._generator, api._exposure, api._mutations,
            api.DECIDE_RATE_LIMIT_ENABLED, api.ACTIVE_WORLD, api._world_config_generation,
        )
        from generator import DataGenerator
        api._schema_loader = SchemaLoader()
        api._generator = DataGenerator()
        api._exposure = ExposureMemory()
        api._mutations = MagicMock()
        api._mutations.get_inserted_rows.return_value = []
        api._mutations.apply_rows.side_effect = lambda _session, _table, rows: rows
        api._mutations.get_count_delta.return_value = 0
        api.DECIDE_RATE_LIMIT_ENABLED = False
        api.ACTIVE_WORLD = "research"
        api._world_config_generation = 1

    def tearDown(self):
        (
            api._schema_loader, api._generator, api._exposure, api._mutations,
            api.DECIDE_RATE_LIMIT_ENABLED, api.ACTIVE_WORLD, api._world_config_generation,
        ) = self.old

    @staticmethod
    def request(query: str, *, session: str = "world-api", protocol: str = "postgres") -> dict:
        req = DecisionRequest(
            session_id=session, query_normalized=query, fingerprint=query,
            event_type="query", phase="data_discovery", username="analyst",
            database="testdb", protocol=protocol, deception_level=1,
        )
        response = asyncio.run(api.decide(MagicMock(), asdict(req)))
        return json.loads(response.body.decode("utf-8"))

    def test_hidden_function_is_native_error_and_never_a_trigger(self):
        result = self.request("select * from legacy_token_export()")
        self.assertEqual(result["mode"], "block")
        self.assertEqual(result["sqlstate"], "42883")
        self.assertFalse(result["trap_triggered"])
        self.assertEqual(api._exposure.get_depth("world-api"), 1)

    def test_table_progression_routine_discovery_and_function_trap(self):
        base = self.request("select id from projects limit 1")
        self.assertEqual(base["mode"], "fake")
        self.assertFalse(base["trap_triggered"])
        self.assertEqual(api._exposure.get_depth("world-api"), 2)

        metadata = self.request(
            "select routine_name from information_schema.routines "
            "where routine_name = 'legacy_token_export'"
        )
        self.assertEqual(metadata["rows"], [{"routine_name": "legacy_token_export"}])
        self.assertFalse(metadata["trap_triggered"])

        first = self.request(
            "select access_token from legacy_token_export() limit 1 offset 1"
        )
        second = self.request(
            "select access_token from legacy_token_export() limit 1 offset 1"
        )
        self.assertEqual(first["rows"], second["rows"])
        self.assertEqual(first["columns"], ["access_token"])
        self.assertEqual(len(first["rows"]), 1)
        self.assertTrue(first["rows"][0]["access_token"])
        self.assertTrue(first["trap_triggered"])
        self.assertEqual(first["world_id"], "research")
        self.assertEqual(first["asset_id"], "research.function.legacy_token_export")
        self.assertEqual(first["trap_id"], "RESEARCH-FUNCTION-TOKEN-001")
        self.assertEqual(first["strategy_id"], "D3")
        self.assertEqual(first["trap_mitre_technique_id"], "T1555")
        self.assertEqual(first["trap_risk_score"], 12.0)

    def test_table_wildcard_with_bounded_literal_alias_is_logical(self):
        result = self.request("select *, 1 as demo_probe from projects limit 1")
        self.assertEqual(result["mode"], "fake")
        self.assertIn("demo_probe", result["columns"])
        self.assertEqual(result["rows"][0]["demo_probe"], 1)
        self.assertEqual(result["column_types"][-1], "bigint")

    def test_function_unknown_projection_and_where_are_rejected(self):
        api._exposure.default_depth = 2
        unknown = self.request("select real_secret from legacy_token_export()")
        self.assertEqual(unknown["mode"], "block")
        self.assertEqual(unknown["sqlstate"], "42703")
        malformed = self.request(
            "select * from legacy_token_export() where environment = 'production'"
        )
        self.assertEqual(malformed["mode"], "block")
        self.assertEqual(malformed["sqlstate"], "42601")
        self.assertFalse(malformed["trap_triggered"])

    def test_trap_mutation_carries_structured_identity(self):
        api.ACTIVE_WORLD = "hr"
        api._exposure.default_depth = 3
        result = self.request(
            "update prod_credentials set notes = 'rotated' where id = 1",
            protocol="mysql",
        )
        self.assertEqual(result["mode"], "fake")
        self.assertTrue(result["trap_triggered"])
        self.assertEqual(result["trap_id"], "HR-TABLE-PROD-CREDENTIALS-001")
        self.assertEqual(result["strategy_id"], "D3")

    def test_generic_foreign_keys_always_reference_effective_parent_rows(self):
        api.ACTIVE_WORLD = "finance"
        api._exposure.default_depth = 3
        result = self.request("select from_account from transactions limit 100")
        parent = api._schema_loader.get_table("finance", "accounts")
        parent_count = api._generator.generate_count(
            parent["row_count"], "world-api", "accounts"
        )
        self.assertEqual(result["mode"], "fake")
        self.assertTrue(result["rows"])
        self.assertTrue(
            all(1 <= row["from_account"] <= parent_count for row in result["rows"])
        )

    def test_world_inventory_lists_traps_without_rows(self):
        inventory = asyncio.run(api.list_worlds())
        research = next(item for item in inventory["worlds"] if item["world_id"] == "research")
        self.assertEqual(research["table_count"], 3)
        self.assertEqual(research["function_count"], 1)
        self.assertEqual(research["traps"][0]["trap_id"], "RESEARCH-FUNCTION-TOKEN-001")
        self.assertNotIn("rows", research)

    def test_reload_rejects_active_sessions_and_invalid_candidate_atomically(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "demo.yaml")
            path.write_text(
                "schema: demo\nsettings: {database_name: demo}\n"
                "tables:\n  records:\n    columns: [{name: id, type: pk_int}]\n",
                encoding="utf-8",
            )
            old_loader = SchemaLoader(Path(temp))
            self.assertTrue(old_loader.is_valid)
            api._schema_loader = old_loader
            api.ACTIVE_WORLD = "demo"
            api._exposure = ExposureMemory(active_sessions=1)
            with self.assertRaises(api.HTTPException) as active:
                asyncio.run(api.reload_worlds())
            self.assertEqual(active.exception.status_code, 409)
            self.assertIs(api._schema_loader, old_loader)

            api._exposure.active_sessions = 0
            path.write_text(
                "schema: demo\ntables:\n  records:\n    columns: [{name: id, type: nope}]\n",
                encoding="utf-8",
            )
            with self.assertRaises(api.HTTPException) as invalid:
                asyncio.run(api.reload_worlds())
            self.assertEqual(invalid.exception.status_code, 400)
            self.assertIs(api._schema_loader, old_loader)

            path.write_text(
                "schema: demo\nsettings: {database_name: demo}\n"
                "tables:\n"
                "  records:\n    columns: [{name: id, type: pk_int}]\n"
                "  audit_notes:\n    columns: [{name: id, type: pk_int}, {name: note, type: sentence}]\n",
                encoding="utf-8",
            )
            result = asyncio.run(api.reload_worlds())
            self.assertEqual(result["status"], "reloaded")
            self.assertEqual(result["generation"], 2)
            self.assertIsNot(api._schema_loader, old_loader)
            self.assertIsNotNone(api._schema_loader.get_table("demo", "audit_notes"))


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from schema_loader import SchemaLoader


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
tables: {}
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


if __name__ == "__main__":
    unittest.main()

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.modules.setdefault("redis", MagicMock())
import api
from models import DecisionRequest
from models import DecisionResponse
from schema_loader import SchemaLoader
from strategy_registry import DEFAULT_REGISTRY_PATH, RegistryValidationError, StrategyRegistry


class TestStrategyRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = StrategyRegistry.load(DEFAULT_REGISTRY_PATH)

    def test_only_evidenced_strategies_are_mapped(self):
        payload = self.registry.to_dict()
        self.assertEqual(payload["registry_version"], "strategy-registry-v1")
        self.assertEqual(payload["default_strategy_id"], "D0")
        self.assertEqual([x["strategy_id"] for x in payload["strategies"]],
                         ["D0", "D1", "D2", "D3", "D4", "D5", "D6"])
        self.assertEqual(payload["unmapped_strategy_ids"], ["D7"])

    def test_required_metadata_is_present(self):
        required = {"strategy_id", "name", "description", "supported_protocols",
                    "required_state", "forbidden_state", "activation_conditions",
                    "compatible_personas", "schema_assets", "trap_assets",
                    "risk_level", "resource_cost", "validation_version", "approval_status"}
        for item in self.registry.to_dict()["strategies"]:
            self.assertTrue(required <= set(item), item["strategy_id"])

    def test_unverified_and_missing_strategies_fall_back_to_d0(self):
        self.assertEqual(self.registry.get("D5").approval_status, "REQUIRES_REVIEW")
        self.assertEqual(self.registry.resolve("D5").strategy_id, "D0")
        self.assertEqual(self.registry.resolve("D999").strategy_id, "D0")

    def test_existing_assets_map_deterministically(self):
        self.assertEqual(self.registry.strategy_for_asset("hr", "api_keys_backup").strategy_id, "D2")
        self.assertEqual(self.registry.strategy_for_asset("hr", "prod_credentials").strategy_id, "D3")
        self.assertEqual(self.registry.strategy_for_asset("hr", "salary_executives").strategy_id, "D4")
        self.assertEqual(self.registry.strategy_for_asset("hr", "departments").strategy_id, "D0")

    def test_registered_assets_exist_in_loaded_synthetic_schemas(self):
        schemas = SchemaLoader()
        schema_names = set(schemas.get_schema_names())
        all_traps = {
            table
            for schema_name in schema_names
            for table in schemas.get_trap_tables(schema_name)
        }
        for strategy in self.registry.to_dict()["strategies"]:
            for asset in strategy["schema_assets"]:
                if "." in asset:
                    schema_name, table = asset.split(".", 1)
                    self.assertIsNotNone(schemas.get_table(schema_name, table), asset)
                else:
                    self.assertIn(asset, schema_names, asset)
            for table in strategy["trap_assets"]:
                self.assertIn(table, all_traps, table)

    def test_invalid_registry_degrades_to_builtin_d0(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.yaml"
            path.write_text("strategies: []\n", encoding="utf-8")
            registry = StrategyRegistry.load_with_fallback(path)
        self.assertTrue(registry.degraded)
        self.assertEqual(registry.resolve("D6").strategy_id, "D0")
        self.assertTrue(registry.load_error)

    def test_external_asset_is_rejected(self):
        raw = self.registry.to_dict()
        raw["strategies"][1]["schema_assets"] = ["https://external.invalid/schema"]
        with self.assertRaises(RegistryValidationError):
            StrategyRegistry.from_dict(raw)


class TestStrategyRegistryApiIntegration(unittest.TestCase):
    def setUp(self):
        self.old_registry = api._strategy_registry
        api._strategy_registry = StrategyRegistry.load(DEFAULT_REGISTRY_PATH)

    def tearDown(self):
        api._strategy_registry = self.old_registry

    @staticmethod
    def decode(response):
        return json.loads(response.body.decode("utf-8"))

    def test_read_only_registry_endpoint_exposes_approval(self):
        payload = asyncio.run(api.list_strategies())
        self.assertIn("D6", payload["approved_strategy_ids"])
        self.assertNotIn("D5", payload["approved_strategy_ids"])

    def test_unapproved_response_annotation_is_forced_to_d0(self):
        payload = self.decode(api._json_response(
            DecisionResponse(mode="fake", strategy_id="D5")
        ))
        self.assertEqual(payload["strategy_id"], "D0")

    def test_catalog_response_is_d1(self):
        req = DecisionRequest("catalog", "select datname from pg_database",
            "select datname from pg_database", "query", "enumeration",
            "postgres", "testdb", "postgres")
        old = (api._schema_loader, api._generator, api._exposure, api._mutations)
        old_rate = api.DECIDE_RATE_LIMIT_ENABLED
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.schema_for_database.return_value = "hr"
            api._generator = MagicMock()
            api._exposure = MagicMock()
            api._exposure.get_depth.return_value = 3
            api._mutations = MagicMock()
            api.DECIDE_RATE_LIMIT_ENABLED = False
            payload = self.decode(asyncio.run(api.decide(MagicMock(), req.__dict__)))
            self.assertEqual(payload["strategy_id"], "D1")
            self.assertEqual(payload["strategy_registry_version"], "strategy-registry-v1")
        finally:
            api._schema_loader, api._generator, api._exposure, api._mutations = old
            api.DECIDE_RATE_LIMIT_ENABLED = old_rate

    def test_backup_trap_response_is_d2(self):
        req = DecisionRequest("backup", "select * from api_keys_backup",
            "select * from api_keys_backup", "query", "data_discovery",
            "guest", "hr_production", "mysql", "api_keys_backup")
        old = (api._schema_loader, api._generator, api._exposure, api._mutations)
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.get_table.return_value = {"row_count": 1, "exposure_depth": 3, "is_trap": True}
            api._schema_loader.get_columns.return_value = [{"name": "id", "type": "pk_int"}]
            api._generator = MagicMock()
            api._generator.generate_count.return_value = 1
            api._generator.generate_rows.return_value = [{"id": 1}]
            api._exposure = MagicMock()
            api._exposure.get_depth.return_value = 3
            api._mutations = MagicMock()
            api._mutations.get_count_delta.return_value = 0
            api._mutations.get_inserted_rows.return_value = []
            payload = self.decode(asyncio.run(api._handle_select(req, "api_keys_backup", "hr")))
            self.assertEqual(payload["strategy_id"], "D2")
        finally:
            api._schema_loader, api._generator, api._exposure, api._mutations = old

    def test_managed_mutation_response_is_d6_through_decide(self):
        req = DecisionRequest("mutation", "delete from employees where id = 1",
            "delete from employees where id = 1", "query", "data_discovery",
            "guest", "hr_production", "mysql", "employees")
        old = (api._schema_loader, api._generator, api._exposure, api._mutations)
        old_rate = api.DECIDE_RATE_LIMIT_ENABLED
        try:
            api._schema_loader = MagicMock()
            api._schema_loader.schema_for_database.return_value = "hr"
            api._schema_loader.get_table.return_value = {"row_count": 1}
            api._generator = MagicMock()
            api._generator.generate_count.return_value = 1
            api._exposure = MagicMock()
            api._exposure.get_depth.return_value = 1
            api._mutations = MagicMock()
            api._mutations.get_inserted_rows.return_value = []
            api._mutations.apply_rows.return_value = [{"id": 1}]
            api.DECIDE_RATE_LIMIT_ENABLED = False
            payload = self.decode(asyncio.run(api.decide(MagicMock(), req.__dict__)))
            self.assertEqual(payload["strategy_id"], "D6")
            api._mutations.record_delete.assert_called_once()
            api._generator.generate_rows.assert_not_called()
        finally:
            api._schema_loader, api._generator, api._exposure, api._mutations = old
            api.DECIDE_RATE_LIMIT_ENABLED = old_rate


if __name__ == "__main__":
    unittest.main()

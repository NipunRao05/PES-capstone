import json
from pathlib import Path

import pytest
import yaml

from base_world import WORLD_ID, WORLD_VERSION
from generator import DataGenerator, FAKE_TIME_ANCHOR
from schema_loader import SchemaLoader
from strategy_registry import StrategyRegistry


def test_manifest_is_single_hr_authority():
    manifest = yaml.safe_load((Path(__file__).parent / "schemas/hr.yaml").read_text())
    assert (WORLD_ID, WORLD_VERSION) == ("hr_base_v1", 1)
    assert manifest["settings"]["database_name"] == "testdb"
    assert manifest["organization"]["reference_date"] == FAKE_TIME_ANCHOR.isoformat()
    loader = SchemaLoader()
    for database in ("testdb", "finance", "crm_production", "unknown"):
        assert loader.schema_for_database(database) == "hr"
    assert set(loader.get_schema_names()) == {"hr", "finance", "crm"}


def test_hr_relationships_domains_and_structurally_invalid_lures():
    loader, generator = SchemaLoader(), DataGenerator()
    tables = loader.get_all_tables("hr")
    organization = generator.generate_organization_rows(schema_name="hr", table_name="employees",
        schema_tables=tables, employee_count=847, session_id="hr-v1-freeze")
    assert len(organization) == 847
    assert all(row["email"].endswith("@company.internal") for row in organization)
    assert all(row["manager_id"] is None or 1 <= row["manager_id"] <= 847 for row in organization)
    for name, definition in tables.items():
        assert generator.generate_count(definition["row_count"], "a", name) == definition["row_count"]
        assert generator.generate_count(definition["row_count"], "b", name) == definition["row_count"]
        rows = generator.generate_rows(columns=definition["columns"], row_count=definition["row_count"],
            session_id="hr-v1-freeze", table_name=name, limit=min(definition["row_count"], 30))
        for row in rows:
            for col in definition["columns"]:
                if col.get("ref") == "employees.id" and row[col["name"]] is not None:
                    assert 1 <= row[col["name"]] <= 847
            if "token" in row:
                assert row["token"].startswith("hrv1_")
                assert not row["token"].startswith(("AKIA", "ghp_", "sk_live_"))
            if "ssn" in row:
                assert row["ssn"].startswith("000-00-")
            if "account_number" in row:
                assert row["account_number"].startswith("ZZ00")
            if "password" in row:
                assert "DECOY" not in row["password"]
    payroll = generator.generate_rows(columns=tables["payroll"]["columns"], row_count=847,
        session_id="hr-v1-freeze", table_name="payroll", limit=40)
    payroll += generator.generate_rows(columns=tables["payroll"]["columns"], row_count=847, session_id="hr-v1-freeze", table_name="payroll", limit=40, offset=807)
    assert [row["employee_id"] for row in payroll] == list(range(1,41)) + list(range(808,848))


def test_hr_exposure_and_strategy_contract():
    loader, registry = SchemaLoader(), StrategyRegistry.load()
    assert loader.get_tables_at_depth("hr", 1) == ["employees", "departments", "sessions"]
    assert set(loader.get_tables_at_depth("hr", 2)) == {"employees", "departments", "sessions", "payroll", "api_keys"}
    for table, expected in {"api_keys_backup":"D2", "api_keys":"D3", "prod_credentials":"D3",
                            "employees":"D4", "payroll":"D4", "salary_executives":"D4"}.items():
        assert registry.strategy_for_asset("hr", table).strategy_id == expected
    assert registry.get("D5").approval_status == "REQUIRES_REVIEW"


def test_world_metadata_is_optional_for_legacy_but_validated_for_new_records():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evidence_store"))
    from strategy_traces import world_metadata
    assert world_metadata({}) == {}
    assert world_metadata({"world_id":""}) == {}
    assert world_metadata({"world_id":WORLD_ID,"world_version":WORLD_VERSION})["world_id"] == WORLD_ID
    for invalid in ({"world_id":WORLD_ID}, {"world_id":"../bad", "world_version":1}):
        with pytest.raises(ValueError):
            world_metadata(invalid)

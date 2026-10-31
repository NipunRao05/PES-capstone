"""Print the approved world inventory, never generated rows or lure values."""
import json
import sys
from configuration import ROOT, read_yaml


def main():
    world = read_yaml("deception_engine/schemas/hr.yaml")
    sys.path.insert(0, str(ROOT / "deception_engine"))
    from strategy_registry import StrategyRegistry
    registry = StrategyRegistry.load()
    print(json.dumps({"world_id": world["world_id"], "world_version": world["world_version"],
        "organization": world["organization"], "database":world["settings"]["database_name"], "schema":"public",
        "tables": [{"name":name,"exposure_depth":table["exposure_depth"],"nominal_rows":table["row_count"],
            "columns":[col["name"] for col in table["columns"]],"trap":table.get("is_trap",False),
            "strategy_id":registry.strategy_for_asset("hr",name).strategy_id}
            for name,table in world["tables"].items()]}, indent=2))


if __name__ == "__main__":
    main()

import copy
import pytest
from strategy_registry import StrategyRegistry, RegistryValidationError


def test_history_active_and_lock():
    raw = StrategyRegistry.load().to_dict()
    second = copy.deepcopy(raw["strategies"][2])
    second["strategy_version"] = 2
    raw["strategies"].append(second)
    raw["active_versions"]["D2"] = 2
    reg = StrategyRegistry.from_dict(raw)
    assert reg.get("D2").strategy_version == 2
    assert reg.get("D2", 1).strategy_version == 1
    assert reg.get("D2", 3) is None
    lock = {f"{s.strategy_id}:{s.strategy_version}": s.definition_digest() for s in reg._versions.values()}
    before = copy.deepcopy(lock)
    reg.validate_lock(lock)
    raw["strategies"][2]["supported_protocols"] = ["postgres"]
    with pytest.raises(RegistryValidationError, match="D2 v1"):
        StrategyRegistry.from_dict(raw).validate_lock(lock)
    assert lock == before
    raw["active_versions"]["D2"] = 3
    with pytest.raises(RegistryValidationError):
        StrategyRegistry.from_dict(raw)


def test_digest_and_bindings():
    raw = StrategyRegistry.load().to_dict()
    first = StrategyRegistry.from_dict(raw).get("D2").definition_digest()
    raw["strategies"][2]["description"] = "Editorial change"
    assert StrategyRegistry.from_dict(raw).get("D2").definition_digest() == first
    raw["strategies"][2]["action_binding"] = "unknown"
    with pytest.raises(RegistryValidationError):
        StrategyRegistry.from_dict(raw)
    reg = StrategyRegistry.load()
    assert reg.get("D2").action_binding == "backup_asset_read"
    assert reg.resolve("D5").strategy_id == "D0"
    assert reg.get("D7") is None

#!/usr/bin/env python3
"""Offline smoke checks for the capstone honeypot stack.

This script intentionally does not require Docker or Redpanda. It validates
syntax/configuration and exercises the session aggregation path with synthetic
proxy events so you can catch schema regressions before running Compose.
"""

from __future__ import annotations

import importlib
import json
import os
import py_compile
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _print(ok: bool, msg: str) -> None:
    prefix = "[OK]" if ok else "[FAIL]"
    print(f"{prefix} {msg}")


def compile_python() -> None:
    for subdir in ("session_module", "mitre_agent", "deception_engine", "observability/metrics_bridge"):
        for path in (ROOT / subdir).glob("*.py"):
            py_compile.compile(str(path), doraise=True)
    for path in (ROOT / "scripts").glob("*.py"):
        py_compile.compile(str(path), doraise=True)
    _print(True, "Python files compile")


def parse_json_dashboards() -> None:
    dashboard_dir = ROOT / "observability" / "grafana" / "dashboards"
    for path in dashboard_dir.glob("*.json"):
        json.loads(path.read_text())
    _print(True, "Grafana dashboard JSON parses")


def parse_yaml_configs() -> None:
    try:
        import yaml  # type: ignore
    except Exception:
        _print(True, "PyYAML not installed; skipped YAML parse")
        return

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError(f"duplicate YAML key {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )

    files = [ROOT / "docker-compose.yml"]
    files.extend(ROOT.glob("*/docker-compose.yml"))
    files.extend([
        ROOT / "observability" / "prometheus.yml",
        ROOT / "observability" / "promtail.yaml",
        ROOT / "observability" / "loki" / "loki-config.yaml",
        ROOT / "mitre_agent" / "rules" / "detection_rules.yaml",
        ROOT / "mitre_agent" / "rules" / "hmm_config.yaml",
        ROOT / "mitre_agent" / "rules" / "deception_profiles.yaml",
    ])
    files.extend((ROOT / "mitre_agent" / "rules" / "techniques").glob("*.yaml"))
    files.extend((ROOT / "deception_engine" / "schemas").glob("*.yaml"))
    files.extend((ROOT / "observability" / "grafana" / "provisioning").glob("**/*.yml"))
    files.extend((ROOT / "k8s").glob("*.yaml"))
    files.extend((ROOT / "k8s").glob("*.yml"))
    for path in files:
        text = path.read_text()
        list(yaml.load_all(text, Loader=UniqueKeyLoader))
    _print(True, "Compose/rules/observability YAML parses without duplicate keys")


class MemoryStore:
    def __init__(self) -> None:
        self.closed = []

    def save_session(self, output) -> None:
        self.closed.append(output)


def session_pipeline_smoke() -> None:
    os.environ.setdefault("SESSION_TIMEOUT", "9999")
    sys.path.insert(0, str(ROOT / "session_module"))
    try:
        # redpanda_consumer imports kafka-python at module import time, but the
        # offline smoke path only needs its pure mapping helper. Provide tiny
        # stubs so this check remains broker-free.
        kafka_stub = types.ModuleType("kafka")
        kafka_stub.KafkaConsumer = object
        kafka_stub.KafkaProducer = object
        kafka_errors_stub = types.ModuleType("kafka.errors")
        kafka_errors_stub.KafkaError = Exception
        sys.modules.setdefault("kafka", kafka_stub)
        sys.modules.setdefault("kafka.errors", kafka_errors_stub)

        models = importlib.import_module("models")
        engine_mod = importlib.import_module("session_engine")
        mapper_mod = importlib.import_module("redpanda_consumer")

        store = MemoryStore()
        engine = engine_mod.SessionEngine(store)
        try:
            raws = [
                {
                    "event_type": "auth",
                    "success": False,
                    "timestamp": "2026-05-23T10:00:00Z",
                    "client_ip": "10.0.0.10",
                    "username": "root",
                    "database": "testdb",
                    "session_id": "mysql-sess-1",
                    "protocol": "mysql",
                },
                {
                    "event_type": "query",
                    "timestamp": "2026-05-23T10:00:01Z",
                    "client_ip": "10.0.0.10",
                    "username": "root",
                    "database": "testdb",
                    "session_id": "mysql-sess-1",
                    "protocol": "mysql",
                    "query_normalized": "show databases",
                    "fingerprint": "show databases",
                },
                {
                    "event_type": "query",
                    "timestamp": "2026-05-23T10:00:02Z",
                    "client_ip": "10.0.0.11",
                    "username": "postgres",
                    "database": "testdb",
                    "session_id": "pg-sess-1",
                    "protocol": "postgres",
                    "query_normalized": "select * from api_keys_backup limit ?",
                    "fingerprint": "select * from api_keys_backup limit ?",
                },
            ]
            for raw in raws:
                label = "PG" if raw.get("protocol") == "postgres" else "MySQL"
                ev = mapper_mod.map_proxy_event_to_event(raw, label)
                assert ev is not None, f"mapper dropped smoke event: {raw}"
                engine.process_event(ev)
            engine.flush_all()
        finally:
            engine.running = False
            if engine.sweeper_thread.is_alive():
                engine.sweeper_thread.join(timeout=2)

        assert len(store.closed) == 2, f"expected 2 closed sessions, got {len(store.closed)}"
        by_id = {s.session_id: s for s in store.closed}
        assert by_id["mysql-sess-1"].failed_auth == 1
        assert by_id["mysql-sess-1"].protocol == "mysql"
        assert by_id["pg-sess-1"].protocol == "postgres"
        assert by_id["pg-sess-1"].query_count == 1
        _print(True, "Synthetic session pipeline produces closed sessions with protocol/auth fields")
    finally:
        sys.path = [p for p in sys.path if p != str(ROOT / "session_module")]
        for name in ("models", "session_engine", "redpanda_consumer", "storage", "clustering_worker", "config", "metrics", "kafka", "kafka.errors"):
            sys.modules.pop(name, None)


def mitre_rule_engine_smoke() -> None:
    sys.path.insert(0, str(ROOT / "mitre_agent"))
    try:
        for name in ("models", "rule_engine"):
            sys.modules.pop(name, None)
        models = importlib.import_module("models")
        rule_engine = importlib.import_module("rule_engine")
        engine = rule_engine.RuleEngine()
        ctx = models.EvalContext(
            fingerprint="select * from public.api_keys_backup where id = ?",
            phase="data_discovery",
            event_type="query",
            table="api_keys_backup",
        )
        result = engine.evaluate(ctx)
        assert result.is_trap_triggered, "expected trap-table rule to trigger"
        assert result.matched_techniques, "expected a MITRE technique match"
        assert result.matched_techniques[0].rule_id == "R001_trap_table_access"
        assert result.matched_techniques[0].technique_id == "T1213.006"
        _print(True, "MITRE rule engine trap-table smoke check passes")
    finally:
        sys.path = [p for p in sys.path if p != str(ROOT / "mitre_agent")]
        for name in ("models", "rule_engine"):
            sys.modules.pop(name, None)


def deception_protocol_smoke() -> None:
    sys.path.insert(0, str(ROOT / "deception_engine"))
    try:
        for name in ("models", "api"):
            sys.modules.pop(name, None)
        # api imports redis at module import time; provide a tiny stub because
        # this smoke path only exercises pure response construction.
        redis_stub = types.ModuleType("redis")
        redis_stub.Redis = object
        sys.modules.setdefault("redis", redis_stub)
        models = importlib.import_module("models")
        api = importlib.import_module("api")
        req = models.DecisionRequest(
            session_id="pg-smoke",
            query_normalized="select current_database()",
            fingerprint="select current_database()",
            event_type="query",
            phase="recon",
            username="postgres",
            database="analytics",
            protocol="postgres",
        )
        resp = api._system_var_response(req, req.query_normalized)
        payload = json.loads(resp.body.decode("utf-8"))
        assert payload["columns"] == ["current_database"]
        assert payload["rows"] == [{"current_database": "analytics"}]
        _print(True, "Deception engine returns protocol-native PostgreSQL system info")
    finally:
        sys.path = [p for p in sys.path if p != str(ROOT / "deception_engine")]
        for name in ("models", "api", "redis"):
            sys.modules.pop(name, None)



def rpk_summary_smoke() -> None:
    import subprocess
    sample = json.dumps({
        "topic": "mitre-events",
        "key": "session-1",
        "offset": 7,
        "value": json.dumps({
            "session_id": "session-1",
            "technique_id": "T1110.001",
            "rule_id": "R009_brute_force",
            "risk_score": 6.0,
            "risk_level": "medium",
            "phase": "credential_access",
            "protocol": "mysql",
            "database": "testdb",
        }),
    })
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "summarize_rpk_json.py")],
        input=sample,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "T1110.001" in proc.stdout
    assert "R009_brute_force" in proc.stdout

    session_sample = json.dumps({
        "topic": "mitre-sessions",
        "key": "session-2",
        "offset": 8,
        "value": json.dumps({
            "session_id": "session-2",
            "final_risk_score": 6.0,
            "risk_level": "medium",
            "persona": "brute_bot",
            "techniques_matched": ["T1110.001", {"technique_id": "T1213.006"}],
            "protocol": "mysql",
            "database": "testdb",
        }),
    })
    proc2 = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "summarize_rpk_json.py")],
        input=session_sample,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "T1110.001,T1213.006" in proc2.stdout

    combined = "\n".join([sample, session_sample])
    proc3 = subprocess.run(
        [
            sys.executable, str(ROOT / "scripts" / "assert_rpk_milestone.py"),
            "--technique", "T1110.001",
            "--technique", "T1213.006",
        ],
        input=combined,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "technique T1110.001" in proc3.stdout
    assert "technique T1213.006" in proc3.stdout
    _print(True, "RPK JSON summarizer and milestone assertion decode nested topic values")

def main() -> int:
    checks = [compile_python, parse_json_dashboards, parse_yaml_configs, session_pipeline_smoke, mitre_rule_engine_smoke, deception_protocol_smoke, rpk_summary_smoke]
    try:
        for check in checks:
            check()
    except Exception as exc:
        _print(False, str(exc))
        return 1
    _print(True, "offline smoke checks complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

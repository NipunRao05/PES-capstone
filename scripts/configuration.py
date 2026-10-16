
"""Canonical local configuration. No service imports, Docker calls or secret output."""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"
PROJECT = "capstone-main"
FEATURES = {
    "core": ("postgres_proxy", "mysql_proxy", "deception_engine"),
    "analysis": ("session_behavior", "evidence_store"),
    "deception": ("deceptive_principals",),
    "infrastructure": ("scaling", "sandbox_replay"),
    "observability": ("enabled", "prometheus", "grafana", "loki"),
    "optional_future": ("mitre", "live_learning", "dynamic_steering", "intervention", "generative_ai", "local_llm"),
}
SERVICES = {
    "analysis.session_behavior": ("session-module",),
    "analysis.evidence_store": ("evidence-store",),
    "infrastructure.scaling": ("scaling-agent",),
    "infrastructure.sandbox_replay": ("sandbox-replay-engine", "sandbox-replay-api", "sandbox-postgres", "sandbox-mysql"),
    "observability.prometheus": ("prometheus", "metrics-bridge", "json-exporter"),
    "observability.grafana": ("grafana",),
    "observability.loki": ("loki", "promtail"),
}
DEPENDENCIES = {
    "deception.deceptive_principals": ("core.deception_engine",),
    "infrastructure.scaling": ("analysis.session_behavior",),
    "infrastructure.sandbox_replay": ("analysis.evidence_store",),
    "observability.grafana": ("observability.prometheus",),
}
CATEGORIES = ("platform", "traffic", "deception", "sessions", "persistence", "evidence", "scaling")


class ConfigError(Exception):
    pass


def yaml_module():
    try:
        import yaml
        return yaml
    except ImportError:
        # Optional repository-local install; never download dependencies at startup.
        tooling = ROOT / ".runtime" / "tooling"
        if tooling.is_dir():
            sys.path.insert(0, str(tooling))
            try:
                import yaml
                return yaml
            except ImportError:
                pass
        raise ConfigError("Install config dependencies: python -m pip install --target .runtime/tooling -r scripts/config-requirements.txt") from None


def read_yaml(relative):
    yaml = yaml_module()

    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        result = {}
        for kn, vn in node.value:
            key = loader.construct_object(kn, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ConfigError(f"{relative}: duplicate or non-string mapping key")
            result[key] = loader.construct_object(vn, deep=deep)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        result = yaml.load((ROOT / relative).read_text(encoding="utf-8-sig"), Loader=UniqueLoader)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError):
        raise ConfigError(f"{relative}: unreadable or invalid YAML (details suppressed to protect secrets)") from None
    if not isinstance(result, dict):
        raise ConfigError(f"{relative}: expected mapping")
    return result


def keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ConfigError(f"{label}: expected exactly these keys: {', '.join(expected)}")


def integer(value, lo, hi, label):
    if type(value) is not int or not lo <= value <= hi:
        raise ConfigError(f"{label}: expected integer in {lo}..{hi}")


def boolean(value, label):
    if type(value) is not bool:
        raise ConfigError(f"{label}: expected YAML true or false")


def read_environment():
    """Literal dotenv subset; reject interpolation rather than guessing Compose semantics."""
    result = {}
    path = ROOT / ".env"
    if path.exists():
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError):
            raise ConfigError(".env: unreadable UTF-8 file") from None
        for number, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
            if not match or match[1] in result:
                raise ConfigError(f".env line {number}: invalid or duplicate single-line assignment")
            key, value = match.groups()
            literal = value.startswith("'")
            if value.startswith(("'", '"')):
                quote = value[0]
                end = value.find(quote, 1)
                if end < 0 or (value[end + 1:].strip() and not value[end + 1:].strip().startswith("#")):
                    raise ConfigError(f".env line {number}: invalid quoted value")
                value = value[1:end]
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
            if not literal and ("$" in value or "\\" in value):
                raise ConfigError(f".env line {number}: use single quotes for literal dollar signs/backslashes; interpolation is unsupported")
            result[key] = value
    result.update(os.environ)
    if result.get("COMPOSE_FILE", "").strip() or result.get("COMPOSE_PROFILES", "").strip():
        raise ConfigError("COMPOSE_FILE/COMPOSE_PROFILES overrides conflict with canonical features; unset them")
    if result.get("COMPOSE_PROJECT_NAME", PROJECT) != PROJECT:
        raise ConfigError("COMPOSE_PROJECT_NAME must be capstone-main to preserve existing volumes")
    return result


def load():
    raw = read_yaml("config/features.yaml")
    keys(raw, ("mode", *FEATURES), "config/features.yaml")
    if raw["mode"] != "deterministic_rule_based":
        raise ConfigError("mode: only deterministic_rule_based is currently supported")
    flags = {}
    for group, names in FEATURES.items():
        keys(raw[group], names, f"features.{group}")
        for name in names:
            value = raw[group][name]
            boolean(value, f"features.{group}.{name}")
            flags[f"{group}.{name}"] = value
    for name in FEATURES["core"]:
        if not flags[f"core.{name}"]:
            raise ConfigError(f"core.{name}: required by this baseline; core removal is unsupported")
    for name in FEATURES["optional_future"]:
        if flags[f"optional_future.{name}"]:
            raise ConfigError(f"optional_future.{name}: not supported in this mode; explicit future implementation/review required")
    # The parent switch masks children; their individual settings are preserved.
    for name in ("prometheus", "grafana", "loki"):
        flags[f"observability.{name}"] &= flags["observability.enabled"]
    for feature, dependencies in DEPENDENCIES.items():
        if flags[feature]:
            for dependency in dependencies:
                if not flags[dependency]:
                    raise ConfigError(f"{feature}=true requires {dependency}=true")

    policy = read_yaml("config/deception.yaml")
    keys(policy, ("session", "decision"), "config/deception.yaml")
    keys(policy["session"], ("timeout_seconds", "max_active", "queue_size"), "policy.session")
    for name, bounds in {"timeout_seconds": (1, 86400), "max_active": (1, 100000), "queue_size": (1, 1000000)}.items():
        integer(policy["session"][name], *bounds, f"policy.session.{name}")
    keys(policy["decision"], ("max_query_bytes", "rate_limit_enabled", "rate_window_seconds", "per_session", "per_client", "global_limit", "fail_open"), "policy.decision")
    for name in ("rate_limit_enabled", "fail_open"):
        boolean(policy["decision"][name], f"policy.decision.{name}")
    for name, bounds in {"max_query_bytes": (1, 1048576), "rate_window_seconds": (1, 3600), "per_session": (0, 1000000), "per_client": (0, 1000000), "global_limit": (0, 10000000)}.items():
        integer(policy["decision"][name], *bounds, f"policy.decision.{name}")

    obs = read_yaml("config/observability.yaml")
    keys(obs, ("scrape_interval_seconds", "scrape_timeout_seconds", "bridge_timeout_seconds", "log_level", "categories"), "config/observability.yaml")
    integer(obs["scrape_interval_seconds"], 5, 300, "scrape_interval_seconds")
    integer(obs["scrape_timeout_seconds"], 1, obs["scrape_interval_seconds"], "scrape_timeout_seconds")
    timeout = obs["bridge_timeout_seconds"]
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.1 <= timeout <= 3:
        raise ConfigError("bridge_timeout_seconds: expected finite number in 0.1..3")
    # Four sequential bridge requests at most: two proxies, scaling, principals.
    requests = 2 + int(flags["infrastructure.scaling"]) + int(flags["deception.deceptive_principals"])
    if timeout * requests + 1 >= obs["scrape_timeout_seconds"]:
        raise ConfigError("scrape_timeout_seconds must exceed bridge_timeout_seconds * enabled bridge requests + 1")
    if obs["log_level"] not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ConfigError("log_level: expected DEBUG, INFO, WARNING or ERROR")
    keys(obs["categories"], CATEGORIES, "observability.categories")
    for name, value in obs["categories"].items():
        boolean(value, f"categories.{name}")

    env = read_environment()
    expected_legacy = {
        "MITRE_ENABLED": False, "LOCAL_LLM_ENABLED": False, "ADAPTATION_ENABLED": False,
        "EXPERIMENT_ENABLED": False, "SCALING_ENABLED": flags["infrastructure.scaling"],
        "DECEPTIVE_PRINCIPALS_ENABLED": flags["deception.deceptive_principals"],
    }
    for name, expected in expected_legacy.items():
        if name in env and env[name].strip().lower() != str(expected).lower():
            raise ConfigError(f"{name}: conflicts with config/features.yaml; remove the legacy override")
    legacy_policy = {
        "SESSION_TIMEOUT": policy["session"]["timeout_seconds"],
        "MAX_ACTIVE_SESSIONS": policy["session"]["max_active"],
        "EVENT_QUEUE_MAX_SIZE": policy["session"]["queue_size"],
        "DECIDE_MAX_QUERY_BYTES": policy["decision"]["max_query_bytes"],
        "DECIDE_RATE_LIMIT_ENABLED": policy["decision"]["rate_limit_enabled"],
        "DECIDE_RATE_LIMIT_WINDOW_SECONDS": policy["decision"]["rate_window_seconds"],
        "DECIDE_RATE_LIMIT_PER_SESSION": policy["decision"]["per_session"],
        "DECIDE_RATE_LIMIT_PER_CLIENT": policy["decision"]["per_client"],
        "DECIDE_RATE_LIMIT_GLOBAL": policy["decision"]["global_limit"],
        "DECIDE_RATE_LIMIT_FAIL_OPEN": policy["decision"]["fail_open"],
    }
    for name, expected in legacy_policy.items():
        if name in env and env[name].strip().lower() != str(expected).lower():
            raise ConfigError(f"{name}: conflicts with config/deception.yaml; remove the legacy override")
    if env.get("ADAPTATION_OPERATOR_MODE", "SAFE_MODE") != "SAFE_MODE":
        raise ConfigError("ADAPTATION_OPERATOR_MODE: only SAFE_MODE is allowed")
    if env.get("ADAPTATION_ENDPOINT", ""):
        raise ConfigError("ADAPTATION_ENDPOINT: remove the legacy adaptive endpoint override")
    required = ["POSTGRES_PASSWORD", "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD"]
    if flags["observability.grafana"]:
        required.append("GRAFANA_ADMIN_PASSWORD")
    for name in required:
        value = env.get(name, "")
        if not value.strip() or value.lower().startswith("change_me"):
            raise ConfigError(f"{name}: missing or placeholder secret; set a nonempty local value")
    if flags["deception.deceptive_principals"]:
        try:
            valid = len(base64.b64decode(env.get("DECEPTIVE_PRINCIPAL_HMAC_SECRET", ""), validate=True)) >= 32
        except (ValueError, binascii.Error):
            valid = False
        if not valid:
            raise ConfigError("DECEPTIVE_PRINCIPAL_HMAC_SECRET: expected base64 decoding to at least 32 bytes")
    ports = []
    for name, default in (("PGPROXY_HOST_PORT", "5432"), ("MYSQLPROXY_HOST_PORT", "3306")):
        value = env.get(name) or default
        if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
            raise ConfigError(f"{name}: expected integer port in 1..65535")
        ports.append(int(value))
    reserved = {9090, 9091, 8001, 9092, 9644}
    for enabled, values in ((flags["analysis.session_behavior"], {8000, 8003}),
                            (flags["analysis.evidence_store"], {8011}),
                            (flags["infrastructure.scaling"], {9095}),
                            (flags["infrastructure.sandbox_replay"], {8012}),
                            (flags["observability.prometheus"], {9096, 9100}),
                            (flags["observability.grafana"], {3000}),
                            (flags["observability.loki"], {3100})):
        if enabled:
            reserved |= values
    if len(set(ports)) != 2 or set(ports) & reserved:
        raise ConfigError("Proxy host ports collide with each other or another enabled service")
    compose = read_yaml("docker-compose.yml")
    if not isinstance(compose.get("services"), dict):
        raise ConfigError("docker-compose.yml: services mapping required")
    return flags, policy, obs, env, compose


def build_model(flags, policy, obs, compose):
    model = copy.deepcopy(compose)
    model["name"] = PROJECT
    services = model["services"]
    excluded = {"mitre-agent", "ai-agent", "llm-agent", "llm-agent-api", "local-llm"}
    for feature, names in SERVICES.items():
        if not flags[feature]:
            excluded.update(names)
    if not flags["analysis.evidence_store"] and not flags["infrastructure.scaling"]:
        excluded.add("redis-mitre")
    for name in excluded:
        services.pop(name, None)
    # Optional pollers are gated below, so these dependencies can be removed.
    for name, service in services.items():
        service.pop("profiles", None)
        deps = service.get("depends_on", {})
        if isinstance(deps, list):
            service["depends_on"] = [n for n in deps if n in services]
        elif isinstance(deps, dict):
            service["depends_on"] = {n: rule for n, rule in deps.items() if n in services}
        else:
            raise ConfigError("Compose depends_on must be a list or mapping")
        environment = service.setdefault("environment", {})
        if not isinstance(environment, dict):
            raise ConfigError("Compose environment must use mapping syntax")
        if "MITRE_ENABLED" in environment:
            environment["MITRE_ENABLED"] = "false"
        if name in {"session-module", "evidence-store"}:
            environment.update(ADAPTATION_ENABLED="false", EXPERIMENT_ENABLED="false")
        if name in {"session-module", "metrics-bridge"}:
            # The session experiment store and MITRE bridge reader are dormant.
            dependencies = service.get("depends_on", {})
            if isinstance(dependencies, dict):
                dependencies.pop("redis-mitre", None)
            else:
                service["depends_on"] = [dep for dep in dependencies if dep != "redis-mitre"]
        if name == "session-module":
            environment.update(ADAPTATION_ENDPOINT="", ADAPTATION_OPERATOR_MODE="SAFE_MODE", EXPERIMENT_PERSISTENCE_REQUIRED="false",
                               SESSION_TIMEOUT=str(policy["session"]["timeout_seconds"]),
                               MAX_ACTIVE_SESSIONS=str(policy["session"]["max_active"]),
                               EVENT_QUEUE_MAX_SIZE=str(policy["session"]["queue_size"]))
        if name == "scaling-agent":
            environment["METRIC_SCALING_ENABLED"] = str(flags["observability.prometheus"]).lower()
        if name == "evidence-store":
            environment["SCALING_ENABLED"] = str(flags["infrastructure.scaling"]).lower()
            if not flags["analysis.session_behavior"]:
                environment["KAFKA_TOPICS"] = "mysql-query-events,pg-query-events,mysql-session-events,pg-session-events"
        if name == "metrics-bridge":
            environment.pop("SCALING_EVENTS_URL", None)
            for key, feature in (("SCALING_ENABLED", "infrastructure.scaling"), ("DECEPTIVE_PRINCIPALS_ENABLED", "deception.deceptive_principals")):
                environment[key] = str(flags[feature]).lower()
            environment["SCRAPE_TIMEOUT"] = str(obs["bridge_timeout_seconds"])
            environment["HONEYPOT_MODE"] = "deterministic_rule_based"
            environment["HONEYPOT_FEATURES"] = json.dumps(flags, sort_keys=True)
        if name in {"pgproxy", "mysqlproxy", "deception-engine"} and not flags["deception.deceptive_principals"]:
            environment["DECEPTIVE_PRINCIPAL_HMAC_SECRET"] = ""
        if name == "deception-engine":
            mapping = {"max_query_bytes": "DECIDE_MAX_QUERY_BYTES", "rate_limit_enabled": "DECIDE_RATE_LIMIT_ENABLED",
                       "rate_window_seconds": "DECIDE_RATE_LIMIT_WINDOW_SECONDS", "per_session": "DECIDE_RATE_LIMIT_PER_SESSION",
                       "per_client": "DECIDE_RATE_LIMIT_PER_CLIENT", "global_limit": "DECIDE_RATE_LIMIT_GLOBAL",
                       "fail_open": "DECIDE_RATE_LIMIT_FAIL_OPEN"}
            environment.update({target: str(policy["decision"][source]).lower() for source, target in mapping.items()})
        if name in {"deception-engine", "session-module", "evidence-store", "metrics-bridge", "sandbox-replay-engine"}:
            environment["LOG_LEVEL"] = obs["log_level"]
            environment["PYTHONPATH"] = "/opt/honeypot"
            environment["HONEYPOT_SERVICE"] = name
            service.setdefault("volumes", []).append("./shared:/opt/honeypot:ro")
        if name in {"pgproxy", "mysqlproxy", "scaling-agent"}:
            environment["LOG_LEVEL"] = obs["log_level"].lower().replace("warning", "warn")
        # Make broken template dependencies actionable rather than silently guessing addresses.
        for key, value in environment.items():
            if type(value) not in (str, int, float):
                raise ConfigError(f"Compose service {name}: {key} must be a scalar string/number")
            if key == "PORT" or key.endswith("_PORT"):
                text = str(value)
                if not re.fullmatch(r"[0-9]{1,5}", text) or not 1 <= int(text) <= 65535:
                    raise ConfigError(f"Compose service {name}: {key} must be a port in 1..65535")
            if key.endswith("_SECONDS"):
                try:
                    number = float(value)
                except (ValueError, TypeError):
                    raise ConfigError(f"Compose service {name}: {key} must be numeric") from None
                if not math.isfinite(number) or number <= 0:
                    raise ConfigError(f"Compose service {name}: {key} must be positive and finite")
            if key.endswith(("_URL", "_ADDR", "_HOST", "_BROKERS", "_BOOTSTRAP")) and not str(value).strip():
                raise ConfigError(f"Compose service {name}: {key} must not be empty")

    if "prometheus" in services:
        services["prometheus"]["volumes"] = [
            "prometheusdata:/prometheus",
            "./.runtime/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
            "./.runtime/alerts.yml:/etc/prometheus/active_alerts.yml:ro",
        ]
        services["prometheus"]["command"] = [
            value.replace("/etc/prometheus/config/prometheus.yml", "/etc/prometheus/prometheus.yml")
            for value in services["prometheus"]["command"]
        ]
    if "grafana" in services:
        services["grafana"]["volumes"] = [
            "./.runtime/grafana/provisioning:/etc/grafana/provisioning:ro",
            "./.runtime/grafana/dashboards:/var/lib/grafana/dashboards:ro",
            "grafanadata:/var/lib/grafana",
        ]
    # Compose may initialize declared volumes even when no retained service uses
    # them. In particular, disabled local LLM must not require its external volume.
    used_volumes = set()
    for service in services.values():
        for mount in service.get("volumes", []):
            source = mount.get("source") if isinstance(mount, dict) else mount.split(":", 1)[0]
            if source in model.get("volumes", {}):
                used_volumes.add(source)
    model["volumes"] = {name: value for name, value in model.get("volumes", {}).items() if name in used_volumes}
    return model


def monitoring(flags, obs):
    prometheus = read_yaml("observability/prometheus.yml")
    prometheus["global"] = {"scrape_interval": f'{obs["scrape_interval_seconds"]}s',
                            "evaluation_interval": f'{obs["scrape_interval_seconds"]}s',
                            "scrape_timeout": f'{obs["scrape_timeout_seconds"]}s'}
    prometheus["rule_files"] = ["/etc/prometheus/active_alerts.yml"]
    jobs = []
    for job in prometheus["scrape_configs"]:
        name = job["job_name"]
        if name in {"capstone-ai-ready", "capstone-llm-ready"}:
            continue
        if name.startswith("sandbox-") and not flags["infrastructure.sandbox_replay"]:
            continue
        jobs.append(job)
    for name, target, feature in (
        ("session-module", "session-module:8000", "analysis.session_behavior"),
        ("evidence-store", "evidence-store:8011", "analysis.evidence_store"),
        ("deception-engine", "deception-engine:8001", "core.deception_engine"),
    ):
        if flags[feature]:
            jobs.append({"job_name": name, "static_configs": [{"targets": [target]}]})
    prometheus["scrape_configs"] = jobs
    alerts = read_yaml("observability/capstone_alert_rules.yml")
    groups = []
    for group in alerts["groups"]:
        rules = []
        for rule in group["rules"]:
            component = rule.get("labels", {}).get("component", "")
            expr = rule.get("expr", "")
            if component in {"ai-agent", "llm-agent", "mitre-agent", "keda"} or rule.get("record", "").startswith("capstone_ai_"):
                continue
            if component == "evidence-store" and not flags["analysis.evidence_store"]:
                continue
            if component == "scaling-agent" and not flags["infrastructure.scaling"]:
                continue
            if component == "sandbox-replay" and not flags["infrastructure.sandbox_replay"]:
                continue
            if "capstone_mitre_" in expr or "capstone_attack_phase_" in expr:
                continue
            rules.append(rule)
        if rules:
            groups.append({**group, "rules": rules})
    return prometheus, {"groups": groups}


def render(flags, policy, obs, compose):
    """Return artifacts in memory. Secrets remain Compose placeholders."""
    if flags["observability.loki"]:
        read_yaml("observability/promtail.yaml")
        read_yaml("observability/loki/loki-config.yaml")
    model = build_model(flags, policy, obs, compose)
    artifacts = {"compose.yaml": model}
    if flags["observability.prometheus"]:
        prometheus, alerts = monitoring(flags, obs)
        artifacts.update({"prometheus.yml": prometheus, "alerts.yml": alerts})
    if flags["observability.grafana"]:
        from dashboard import make_dashboard
        artifacts["grafana/dashboards/operations_overview.json"] = make_dashboard(flags, obs)
        if flags["infrastructure.scaling"] and obs["categories"]["scaling"]:
            try:
                artifacts["grafana/dashboards/scaling_timeline.json"] = json.loads(
                    (ROOT / "observability/grafana/dashboards/scaling_timeline.json").read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                raise ConfigError("scaling_timeline.json: invalid dashboard JSON") from None
        datasources = read_yaml("observability/grafana/provisioning/datasources/prometheus.yml")
        datasources["datasources"] = [d for d in datasources["datasources"] if d["type"] != "loki" or flags["observability.loki"]]
        artifacts["grafana/provisioning/datasources/main.yml"] = datasources
        artifacts["grafana/provisioning/dashboards/main.yml"] = {
            "apiVersion": 1, "providers": [{"name": "Honeypot Operations", "folder": "", "type": "file",
                                          "disableDeletion": False, "editable": False,
                                          "options": {"path": "/var/lib/grafana/dashboards"}}]}
    # File bind mounts can retain the old inode after an atomic file replacement.
    # Changed content must recreate the consumer even when mount paths stay equal.
    for service, names in (
        ("prometheus", ["prometheus.yml", "alerts.yml"]),
        ("grafana", sorted(name for name in artifacts if name.startswith("grafana/"))),
    ):
        if service in model["services"]:
            content = json.dumps({name: artifacts[name] for name in names}, sort_keys=True)
            model["services"][service].setdefault("labels", {})["honeypot.config-hash"] = hashlib.sha256(content.encode()).hexdigest()
    return artifacts


def write_artifacts(artifacts):
    yaml = yaml_module()
    RUNTIME.mkdir(exist_ok=True)
    for relative, value in artifacts.items():
        target = RUNTIME / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(value, indent=2) if target.suffix == ".json" else yaml.safe_dump(value, sort_keys=False)
        text += "\n"
        if target.is_file() and target.read_text(encoding="utf-8") == text:
            continue
        temp = target.with_suffix(target.suffix + ".tmp")
        temp.write_text(text, encoding="utf-8")
        temp.replace(target)
    owned_optional = ("grafana/dashboards/scaling_timeline.json",)
    for relative in owned_optional:
        if relative not in artifacts:
            target = RUNTIME / relative
            if target.is_file():
                target.unlink()



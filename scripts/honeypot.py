#!/usr/bin/env python3
"""Read-only preflight for the existing Compose configuration; never starts services."""
from __future__ import annotations

import argparse
import base64
import binascii
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


class ConfigError(Exception):
    pass


def read_environment():
    """Support simple dotenv assignments, failing closed on unsupported syntax.

    Shell values take precedence. This deliberately does not implement Compose's
    full interpolation language; unsupported .env syntax must not be guessed.
    """
    values = {}
    path = ROOT / '.env'
    if path.exists():
        for number, line in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.fullmatch(r'(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
            if not match:
                raise ConfigError(f'.env line {number}: expected a single-line NAME=value assignment')
            key, value = match.groups()
            if key in values:
                raise ConfigError(f'.env line {number}: duplicate assignment')
            if value.startswith(('"', "'")):
                quote = value[0]
                end = value.find(quote, 1)
                if end < 0 or (value[end + 1:].strip() and not value[end + 1:].strip().startswith('#')):
                    raise ConfigError(f'.env line {number}: unsupported quoted value')
                value = value[1:end]
            else:
                value = re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
            if '$' in value or '\\' in value:
                raise ConfigError(f'.env line {number}: interpolation/escape syntax is unsupported by this preflight')
            values[key] = value
    values.update(os.environ)
    return values


def read_yaml(relative):
    try:
        import yaml
    except ImportError:
        raise ConfigError('PyYAML is required: python -m pip install -r scripts/config-requirements.txt') from None

    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ConfigError(f'{relative}: duplicate or non-string YAML key')
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        data = yaml.load((ROOT / relative).read_text(encoding='utf-8-sig'), Loader=UniqueLoader)
    except (OSError, UnicodeError, yaml.YAMLError):
        # Parser exceptions can contain source lines with secret values.
        raise ConfigError(f'{relative}: missing, unreadable or invalid YAML') from None
    if not isinstance(data, dict):
        raise ConfigError(f'{relative}: expected a YAML mapping')
    return data


def resolve(value, environment):
    if not isinstance(value, str):
        raise ConfigError('Expected a string Compose environment value')
    match = re.fullmatch(r'\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}', value)
    if match:
        key, default = match.groups()
        return environment.get(key) or default
    if '$' in value:
        raise ConfigError('Unsupported Compose interpolation in an inspected setting')
    return value


def boolean(value, name):
    normalized = value.strip().lower()
    if normalized not in {'true', 'false'}:
        raise ConfigError(f'{name}: use true or false explicitly')
    return normalized == 'true'


def inspect():
    env = read_environment()
    compose = read_yaml('docker-compose.yml')
    services = compose.get('services')
    if not isinstance(services, dict) or not services:
        raise ConfigError('docker-compose.yml: services must be a nonempty mapping')
    for name, service in services.items():
        if not isinstance(service, dict):
            raise ConfigError('docker-compose.yml: each service must be a mapping')
        profiles = service.get('profiles', [])
        if not isinstance(profiles, list) or any(not isinstance(p, str) for p in profiles):
            raise ConfigError('docker-compose.yml: profiles must be a list of strings')
        if not isinstance(service.get('environment', {}), dict):
            raise ConfigError('This preflight currently requires mapping-form service environment')
    for relative in ('observability/prometheus.yml', 'observability/capstone_alert_rules.yml',
                     'observability/promtail.yaml', 'observability/loki/loki-config.yaml'):
        read_yaml(relative)
    for name in ('POSTGRES_PASSWORD', 'MYSQL_ROOT_PASSWORD', 'MYSQL_PASSWORD', 'GRAFANA_ADMIN_PASSWORD'):
        value = env.get(name, '')
        if not value.strip() or value.lower().startswith('change_me'):
            raise ConfigError(f'{name}: required non-placeholder value is missing')
    secret = env.get('DECEPTIVE_PRINCIPAL_HMAC_SECRET', '')
    try:
        valid_secret = len(base64.b64decode(secret, validate=True)) >= 32
    except (ValueError, binascii.Error):
        valid_secret = False
    if not valid_secret:
        raise ConfigError('DECEPTIVE_PRINCIPAL_HMAC_SECRET: persistent principals require base64 decoding to at least 32 bytes')
    for name, default in (('PGPROXY_HOST_PORT', '5432'), ('MYSQLPROXY_HOST_PORT', '3306')):
        value = env.get(name) or default
        if not re.fullmatch(r'[0-9]+', value) or not 1 <= int(value) <= 65535:
            raise ConfigError(f'{name}: expected an integer port in 1..65535')
    mitre_values = {
        boolean(resolve(service['environment']['MITRE_ENABLED'], env), 'MITRE_ENABLED')
        for service in services.values() if 'MITRE_ENABLED' in service.get('environment', {})
    }
    if len(mitre_values) != 1:
        raise ConfigError('MITRE_ENABLED: missing or conflicting service settings')
    mitre = mitre_values.pop()
    local_llm = boolean(env.get('LOCAL_LLM_ENABLED', 'false'), 'LOCAL_LLM_ENABLED')
    profiles = {p.strip() for p in env.get('COMPOSE_PROFILES', '').split(',') if p.strip()}
    known_profiles = {p for service in services.values() for p in service.get('profiles', [])}
    if profiles - known_profiles:
        raise ConfigError('COMPOSE_PROFILES: contains an unknown profile')
    if mitre or local_llm or profiles:
        raise ConfigError('Deterministic baseline preflight requires MITRE_ENABLED=false, LOCAL_LLM_ENABLED=false and no COMPOSE_PROFILES')
    return services, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('config-check', 'config-status'))
    args = parser.parse_args()
    try:
        services, env = inspect()
        if args.command == 'config-status':
            print('source: existing docker-compose.yml + .env + shell overrides')
            print('runtime_health: not checked; CLI profile/service overrides are not inspected')
            print('target_mode: deterministic_rule_based')
            print('canonical_feature_model: pending integration')
            print('mitre: disabled')
            print('local_llm: disabled')
            session = services.get('session-module', {}).get('environment', {})
            mode = resolve(session.get('ADAPTATION_OPERATOR_MODE', ''), env)
            endpoint = resolve(session.get('ADAPTATION_ENDPOINT', ''), env)
            # Print only fixed labels, never arbitrary environment/source values.
            print('adaptation_operator_mode: ' + ('RULE_ADAPTIVE (cleanup pending)' if mode == 'RULE_ADAPTIVE' else 'other/unset (inspect source)'))
            print('adaptation_endpoint: ' + ('configured (cleanup pending)' if endpoint else 'unset'))
            for name in ('pgproxy', 'mysqlproxy', 'deception-engine', 'session-module', 'evidence-store',
                         'scaling-agent', 'sandbox-replay-engine', 'prometheus', 'grafana', 'loki',
                         'ai-agent', 'llm-agent', 'llm-agent-api'):
                service = services.get(name)
                state = 'absent' if service is None else ('profile-gated' if service.get('profiles') else 'default startup')
                print(f'{name}: {state}')
        else:
            print('CONFIGURATION PREFLIGHT PASSED (limited static checks only)')
        print('PENDING: canonical feature model, complete dependency/schema validation, adaptive/AI runtime gating.')
        print('No services started or contacted; this is not a deployment or functional validation.')
        return 0
    except ConfigError as exc:
        print(f'CONFIGURATION INVALID\n{exc}', file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print('CONFIGURATION INVALID\nCannot read configuration files; check permissions and UTF-8 encoding.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

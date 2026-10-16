
#!/usr/bin/env python3
"""Canonical offline preflight, safe status and explicitly requested Compose operations."""
import argparse
import os
import subprocess
import sys
from configuration import ConfigError, ROOT, PROJECT, load, render, write_artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("config-check", "config-status", "prepare", "compose"))
    parser.add_argument("compose_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.command != "compose" and args.compose_args:
            raise ConfigError("Unexpected command arguments")
        if args.command == "compose":
            if not args.compose_args or args.compose_args[0] not in {"up", "build", "pull", "ps", "logs", "stop", "down", "restart", "config"}:
                raise ConfigError("compose: choose up, build, pull, ps, logs, stop, down, restart or config --quiet")
            if args.compose_args[0] == "config" and args.compose_args != ["config", "--quiet"]:
                raise ConfigError("Only compose config --quiet is supported; expanded configuration can expose secrets")
            if args.compose_args[0] == "up" and "--remove-orphans" not in args.compose_args:
                args.compose_args.insert(1, "--remove-orphans")
            forbidden = {"--profile", "--env-file", "--project-directory", "--project-name", "-p", "-f", "--file", "--volumes", "-v"}
            if any(arg.split("=")[0] in forbidden for arg in args.compose_args[1:]):
                raise ConfigError("Compose source/profile overrides and volume deletion are not supported")
        flags, policy, obs, env, compose = load()
        artifacts = render(flags, policy, obs, compose)
        if args.command == "config-status":
            print("mode: deterministic_rule_based")
            print("source: config/features.yaml (resolved configuration, not runtime health)")
            for feature, enabled in flags.items():
                print(f"{feature}: {'enabled' if enabled else 'disabled'}")
            print("services: " + ", ".join(sorted(artifacts["compose.yaml"]["services"])))
        elif args.command == "config-check":
            print("CONFIGURATION VALID (offline checks; no services contacted)")
        elif args.command == "prepare":
            write_artifacts(artifacts)
            print("Prepared .runtime/ artifacts. Start through: python scripts/honeypot.py compose up -d --build --remove-orphans")
        else:
            write_artifacts(artifacts)
            child_env = dict(env)
            child_env.update(HONEYPOT_CONFIGURED=PROJECT, COMPOSE_PROFILES="", COMPOSE_FILE="", COMPOSE_PROJECT_NAME=PROJECT)
            # Secrets go to the child environment, never into generated YAML or argv.
            command = ["docker", "compose", "--project-directory", str(ROOT), "--env-file", str(ROOT / "config/empty.env"),
                       "-p", PROJECT, "-f", str(ROOT / ".runtime/compose.yaml"), *args.compose_args]
            return subprocess.call(command, cwd=ROOT, env=child_env)
        return 0
    except ConfigError as exc:
        print(f"CONFIGURATION INVALID\n{exc}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("Configuration/command unavailable; check file permissions, UTF-8 and Docker installation.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

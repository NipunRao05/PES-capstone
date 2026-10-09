# Configuration — first implementation checkpoint

Current target: `deterministic_rule_based`. This is a small, untested foundation,
not completion of canonical feature flags or runtime gating. No services were
restarted and no test/preflight commands were executed during this change.

## Existing sources and precedence

- `docker-compose.yml`: current service wiring, environment, ports and profiles.
- `.env`: local secrets/deployment overrides; ignored by Git. Never publish it.
- `.env.example`: placeholders only. Do not replace an existing `.env` with it.
- Service config/env readers still own their existing defaults, including
  `session_module/config.py`; canonical reconciliation remains pending.
- `observability/`: Prometheus targets/rules, metrics bridge, Loki, Promtail and
  Grafana provisioning/dashboards. No competing config directory was introduced.

The new helper reads root `.env`, then overlays the process environment (shell
wins), and inspects the existing root Compose file. It does not use the caller's
working directory. Simple `KEY=value`, `export KEY=value`, single/double quoted
single-line values, and comments are supported. Duplicate assignments, multiline
values, dollar interpolation and escapes are rejected rather than guessed. This
is a deliberate subset of Compose dotenv syntax, not a replacement Compose parser.
It does not inspect `--env-file`, Compose override files, CLI profiles, explicit
service selection or a running deployment.

## Manual commands (not executed by the agent)

Run from the repository root with Python 3.9+:

```powershell
python -m pip install -r scripts/config-requirements.txt
python scripts/honeypot.py config-check
python scripts/honeypot.py config-status
```

Both commands are read-only and work without starting Docker. Failure exits 1.
The checker stops on the first actionable error and never prints secret values
or YAML exception excerpts. Status performs the same checks before reporting.

Checks currently implemented:

- Existing Compose, Prometheus/rules, Promtail and Loki YAML parses with unique
  string mapping keys; basic Compose service/environment/profile shapes.
- Current required database/Grafana passwords exist and are not example values.
- Deceptive-principal HMAC is strict base64 decoding to at least 32 bytes.
  This preflight requires persistent principals for the intended baseline;
  existing services' fail-closed authentication semantics are unchanged.
- Proxy host-port overrides are integers in 1..65535.
- MITRE values agree across current Compose consumers and use explicit booleans.
- This baseline check requires MITRE and local LLM off, and no active optional
  Compose profile. It does not authorize future-feature activation.

A pass covers only these checks. It does not verify every service setting,
unknown schema key, numeric range, address, dependency, port collision or runtime
health. A pass also does not mean adaptive background work is disabled: status
explicitly reports the current adaptation wiring and AI defaults as cleanup debt.

## Findings and next small steps

| Finding in local source | State / next action |
| --- | --- |
| MITRE defaults false; `mitre` profile exists | Preserve and reconcile into one future canonical model |
| `local-ai` gates the local LLM container | Preserve; reconcile runtime flags and profiles |
| Session module sets RULE_ADAPTIVE and a next-strategy endpoint | Audit worker lifecycle before disabling it comprehensively |
| ai-agent, llm-agent and llm-agent-api start by default | Coordinate profiles, dependencies, scrape targets and alerts |
| Evidence Store depends on scaling-agent | Audit polling/readiness before making scaling optional |
| AI/LLM scrapes and absent-series alerts are unconditional | Gate together with their services |
| KEDA absent-series alert runs in local Compose rules | Separate physical-cluster monitoring from local deployment |
| Per-session metrics feed several existing dashboards | Replace producer and dashboard queries together; do not just remove labels |
| Grafana defaults to live_attack_feed.json | Build the requested Operations & Research Overview after metric audit |
| Loki used container ID as an indexed label | Removed in this pass; Docker discovery still uses it internally |
| Loki service label used container instance name | Prefer stable Compose service name, retaining fallback for non-Compose containers |
| Loki promoted technique_id to a label | Removed; structured log body remains available |
| Full normalized logs / secret-redaction audit | Pending; label cleanup alone does not provide redaction |

Prometheus owns aggregates; Redpanda owns domain events; Evidence Store owns
historical/correlated evidence; Loki owns operational logs; Grafana visualizes.
Do not use session/principal IDs, usernames, client IPs, queries, arbitrary object
names or secrets as metric labels. Do not invent replica counts or metric values.

## Continuation

Next: derive the feature dependency table from code and implement one canonical
model that drives Compose, service workers, readiness, scrapes and alerts together.
Only then add policy/observability YAML where it replaces scattered settings.
Keep all future adaptive/AI features disabled and preserve source. Authentication,
principal persistence and protocol behavior must remain unchanged.

Then migrate per-session telemetry plus dependent panels, normalize logs safely,
and build the primary dashboard. Leave functional testing to the user. No
commits/pushes or dynamic-development work are authorized by this document.

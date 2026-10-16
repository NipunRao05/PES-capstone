# Deterministic configuration and observability

Implementation checkpoint: 2026-10-16. The configuration launcher, runtime gates,
aggregate telemetry, structured logging and primary dashboard are implemented.
The user subsequently authorized live validation. The default local stack now
passes the bounded checks in VERIFICATION_RESULTS.md; use RUN_LOCAL.md for startup
and your own checks. Historical validation is not current runtime evidence.

## Configuration ownership

| File | Responsibility |
| --- | --- |
| config/features.yaml | Sole feature authority and supported mode |
| config/deception.yaml | Session bounds and existing deterministic decision/rate-limit policy |
| config/observability.yaml | Collection timing, producer log level and dashboard categories |
| .env | Local secrets and supported deployment overrides; never commit |
| .env.example | Placeholder reference, not a replacement for existing local configuration |
| docker-compose.yml | Service/build/address template consumed by the launcher |
| scripts/configuration.py | Offline validation and effective deployment generation |
| scripts/honeypot.py | Check, status, prepare and guarded Compose entry point |
| scripts/dashboard.py | Feature-aware primary dashboard definition |
| .runtime/ | Ignored generated Compose/monitoring files and optional local Python dependencies |

Existing Compose, environment readers and observability sources were reused.
Internal Docker service addresses remain in the Compose template; supported host
port overrides remain in .env. There is no configuration server or hot reload.
The root Compose file now requires the launcher; old direct Compose startup
instructions elsewhere in historical documents are superseded by this document.
Generated files are disposable outputs, not another configuration authority.

## Feature defaults and effects

The only supported mode is deterministic_rule_based. All core components must
remain enabled in this baseline. Dependencies are checked, never auto-enabled.

| Feature | Default | Dependency and runtime effect |
| --- | --- | --- |
| core.postgres_proxy | true | Required; PostgreSQL proxy and controlled backend retained |
| core.mysql_proxy | true | Required; MySQL proxy and controlled backend retained |
| core.deception_engine | true | Required; deterministic decision service and its Redis retained |
| analysis.session_behavior | true | Session processing, authoritative projection and native metrics |
| analysis.evidence_store | true | Kafka evidence ingestion and persistent correlated records |
| deception.deceptive_principals | true | Requires deception_engine and valid stable HMAC; false clears principal HMAC inputs using existing disable semantics |
| infrastructure.scaling | true | Requires session_behavior; false removes scaler and evidence scaling poller |
| infrastructure.sandbox_replay | true | Requires evidence_store; false removes replay services and sandbox databases |
| observability.enabled | true | Parent switch; false masks all three observability children |
| observability.prometheus | true | Prometheus, metrics bridge and JSON exporter; false also disables scaler's Prometheus polling |
| observability.grafana | true | Requires prometheus; generated provisioning and default dashboard |
| observability.loki | true | Loki and Promtail; optional Grafana log datasource/row |
| optional_future.mitre | false | Activation rejected in this mode; source retained |
| optional_future.live_learning | false | Activation rejected; no live learned selection |
| optional_future.dynamic_steering | false | Activation rejected; deferred development |
| optional_future.intervention | false | Activation rejected; deferred development |
| optional_future.generative_ai | false | Activation rejected; AI/LLM services omitted |
| optional_future.local_llm | false | Activation rejected; runtime and external model-volume requirement omitted |

Edit canonical YAML, run config-check and config-status, then apply with the
launcher’s compose up command. A container restart alone does not apply changed
Compose environment or feature membership. Switching off a dependency while its
consumer stays enabled is an error. Observability categories only hide dashboard
sections; they do not override feature flags or disable domain event production.

The launcher excludes disabled services, dependencies, readiness probes and
feature-specific dashboards/alerts. Source profiles such as MITRE, local AI and
future-ai remain for historical/future work but are not an activation mechanism.
Nonempty COMPOSE_PROFILES or COMPOSE_FILE and a different COMPOSE_PROJECT_NAME
are rejected. The fixed project name capstone-main preserves existing volume
identity. Unused volume declarations are omitted without deleting stored volumes.

The launcher automatically adds --remove-orphans to compose up: containers from
the same project that are absent from the effective model are removed. This is
how previously running optional services are deactivated. Named data volumes are
retained. Volume deletion flags are rejected; do not manually delete data volumes
to resolve a configuration error.

## Compatibility and deterministic behavior

Shell environment overrides .env for deployment values. Canonical features and
policy override the service template; compatible legacy flags are accepted only
when they agree. Conflicting MITRE_ENABLED, LOCAL_LLM_ENABLED, ADAPTATION_ENABLED,
EXPERIMENT_ENABLED, SCALING_ENABLED or DECEPTIVE_PRINCIPALS_ENABLED fail preflight.
Existing session/decision policy overrides must likewise agree with canonical
policy. ADAPTATION_OPERATOR_MODE must be SAFE_MODE; ADAPTATION_ENDPOINT must be
unset. A legacy environment flag cannot silently enable a disabled feature.
Unused future settings may remain in .env but are not forwarded to removed services.

Literal single-line dotenv assignments, export prefixes and quoted values are
supported. Duplicate keys, malformed quotes, multiline values and interpolation
are rejected. Use single quotes around literal dollar signs or backslashes.
Unknown canonical YAML keys and duplicate/non-string YAML mapping keys are errors.
Unknown .env keys are retained for existing deployment/tool compatibility; they
are not new feature definitions.

The session process does not construct the asynchronous adaptation worker or the
experiment persistence/controller in this mode. It preserves authoritative state
projection and passive outcome accounting. Evidence Store does not poll adaptive
state; its scaling poller and readiness dependency exist only when scaling is
selected. Session processing no longer waits for the dormant experiment Redis.
Metrics bridge no longer waits for or reads MITRE Redis in deterministic mode.
Existing SQL handling, deterministic rule responses, backend passthrough and
virtual-authentication security semantics are preserved by the code changes.
No synthetic principal is converted into a physical database account.

## Preflight and startup

Use a Python environment with scripts/config-requirements.txt installed. The
loader can also use an installation in .runtime/tooling. This checkout already
has that ignored local dependency; no service dependencies were installed.
With a working Python executable available as python:

~~~powershell
# Only needed when the configuration dependency is unavailable:
python -m pip install --target .runtime/tooling -r scripts/config-requirements.txt

# Offline commands; no Docker startup or service requests:
python scripts/honeypot.py config-check
python scripts/honeypot.py config-status
python scripts/honeypot.py prepare

# Docker validation and startup (executed during the live verification pass):
python scripts/honeypot.py compose config --quiet
python scripts/honeypot.py compose up -d --build
python scripts/honeypot.py compose ps
~~~

On this machine, if python resolves to the Windows Store alias, the available
bundled interpreter can be used explicitly:

~~~powershell
$py = 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $py scripts/honeypot.py config-check
& $py scripts/honeypot.py config-status
& $py scripts/honeypot.py compose config --quiet
& $py scripts/honeypot.py compose up -d --build
& $py scripts/honeypot.py compose ps
~~~

Preflight checks canonical file shapes, strict booleans, supported mode, feature
dependencies, policy ranges, scrape timing, log levels, relevant YAML/JSON files,
Compose environment scalar shapes, numeric ports/timers and nonempty service
addresses. Proxy host ports must be distinct and not collide with enabled fixed
ports. Enabled database/Grafana passwords must be nonempty and not example
placeholders. Principals require strict base64 decoding to at least 32 bytes.
Disabled optional features do not require their secrets. Errors name settings
and constraints without printing values. This is offline configuration checking,
not a complete Docker schema validator or connectivity/password verification.

Current local preflight passes. During authorized validation, existing PostgreSQL
and MySQL account passwords were aligned with .env, preserving data and the
principal HMAC. Changing .env alone does not update initialized database accounts.
Keep the HMAC stable; rotation requires a deliberate registry migration. Never
paste secrets into Git or status output.

config-status lists resolved mode, features and selected services, never health
or secret values. prepare writes generated files without resolving secret
placeholders. compose passes secrets in the child environment, not argv or
written YAML. Only compose config --quiet is accepted because ordinary Compose
config output can reveal resolved secrets. All wrapper commands, including
ps/stop/down, require valid configuration; ordinary Docker container controls
remain an operator option if configuration needs repair before using the wrapper.

## Observability ownership and metrics

Prometheus owns aggregate observations; Redpanda carries domain events; Evidence
Store owns detailed/correlated history; Loki owns operational logs; Grafana
visualizes them. Native Redpanda and Python process collectors are reused.
The bridge handles existing proxy/scaling JSON snapshots and principal aggregates;
it no longer appends duplicated native scaling metrics or per-session scaling
series. MITRE/AI scrapes, alerts and source dashboards remain dormant.

| Group | Producers and meaning |
| --- | --- |
| Configuration/health | honeypot_runtime_info and honeypot_feature_enabled are configured facts; up is scrape health; capstone_bridge_scrape_success reports source fetches; backend_healthy reports backend reachability; honeypot_dependency_up reports Redis/evidence consumer connectivity |
| Traffic | capstone_pgproxy_* and capstone_mysqlproxy_* connection/rejection/backend counters; honeypot_query_outcomes_total and honeypot_authentication_total count newly accepted evidence by bounded protocol/outcome labels |
| Deception | honeypot_decision_requests_total and honeypot_decision_seconds measure decision HTTP handling, not end-to-end SQL success; proxy deception_fallbacks_total counts failed decision transport/status/decode paths; honeypot_trap_interactions_total requires verified successful trap evidence |
| Sessions | active_sessions, sessions_closed_total, duration/query-count/depth histograms, honeypot_session_pipeline_seconds, actual honeypot_session_queue_depth and Kafka publish outcomes |
| Persistence | deceptive_principals_created_total, deceptive_principals_reused_total, deceptive_principal_return_sessions_total and deceptive_persistence_reengagement_rate retain registry semantics; honeypot_first_reuse_seconds observes explicit first-return evidence only |
| Evidence | honeypot_evidence_ingest_total and ingest_seconds measure processing attempts; session_links_total, principal_evidence_total and behavior_profiles_total count newly stored evidence |
| Scaling | capstone_scaling_desired_replicas is the logical target, never a physical pod count; pressure, up/down counters, safe/autoscaling state, budget and rolling scorer aggregates retain their authoritative producer |

New evidence counters are process-local and reset on restart. Ingest attempts
include idempotent re-deliveries; accepted-record counters increment only when a
record is newly appended. These increments are not transactional with Redis and
are not an exactly-once durable research ledger. Detailed persisted evidence is
the source for historical analysis. Session histograms describe sessions closed
by the behavior engine, not necessarily complete socket lifetimes.

Persistence created/reused totals count distinct successfully created attacker
principals and distinct such principals successfully authenticating in a different
session. Re-engagement is reused / created, safely zero with no created principals.
No username/principal labels are exported. First-reuse timing can have no samples
until an explicit first-return event arrives.

Removed unbounded session/cluster labels; protocol, authority, success, event and
classification values use bounded sets. No query, arbitrary object, principal,
username or client IP is added to Prometheus labels. The generic trap signal
counter replaces the misleading MITRE name. Compatibility aliases for existing
aggregate trap and replica-target consumers remain. Scorer sample count is a
gauge for a rolling population. Dormant specialized dashboard sources were
migrated away from removed per-session scaling metrics.

No Kafka consumer lag, physical Kubernetes replicas, fabricated queue depth,
hold/cooldown distribution or end-to-end query latency is invented. Those need
additional authoritative producers before they can be shown.

## Loki and Grafana

Shared Python formatting and Go slog attributes produce timestamp, level, service,
component, event and message, with protocol/authority/success/latency_ms and
error_category where available. SQL-bearing Python messages and Go query/payload
attributes are omitted; known secrets, credential assignments and verifier
material are redacted. Python exception bodies/tracebacks and Go raw error objects
are suppressed while fixed event context remains. Existing third-party container
logs and historical records are not retroactively sanitized by these formatters.

Promtail is scoped to the capstone-main Compose project. Indexed labels are stable
service, compose_service, compose_project and normalized bounded level; container
IDs, sessions, usernames, query strings and technique IDs are not indexed. The
producer's configured log level controls debug emission. IDs belong only in
sanitized bodies/evidence where necessary. Promtail transports infrastructure
logs too, which retain their native formats.

Default dashboard: **Honeypot Operations & Research Overview**. Generated rows:

1. Runtime Mode & Platform Health: configured mode, scrapes, backends and dependencies.
2. Live Database Activity: active/new connections, query and authentication outcomes.
3. Deception Effectiveness: decision results/latency, fallbacks, authority and traps.
4. Session & Behavior: active/closed sessions, distributions, real queue and publishing.
5. Deceptive Persistence: created/reused/returns, ratio and first-reuse distribution.
6. Evidence Pipeline: ingest attempts/failures/latency, links and principal/profile evidence.
7. Scaling & Resources: pressure, desired targets/budget, decisions/modes and native process usage.
8. Log Investigation: Loki warnings/errors across the enabled deployment.

Rows/panels for disabled producers are omitted. Rates are used for counters,
seconds for latency, percentages for ratios and quantiles for distributions.
No data can mean no observations; it is not automatically a service failure.
The aggregate scaling timeline is also provisioned when scaling is selected.
Other specialized source dashboards are retained without default provisioning.

## Changed areas and verification handoff

Changes span config/*.yaml, scripts/{honeypot,configuration,dashboard}.py,
.env.example/.gitignore, docker-compose.yml, shared logging, both proxy logging
and fallback counters, session configuration/consumer/metrics/storage, Evidence
Store ingestion/poller/metrics/Docker requirements, Deception Engine metrics and
requirements, replay logging, scaling logging/metric type, metrics bridge and
its fixture, Promtail, alerts and Grafana dashboard sources. AGENTS.md records the
continuation boundary. Existing .env and historical evidence were preserved.

Runtime verification now supplements the original offline checks. See
VERIFICATION_RESULTS.md for the 339 Python tests, Go suites, native protocol/state
checks, resolved failures and precise coverage limits. RUN_LOCAL.md contains the
tested startup procedure, repeatable health/state checks and troubleshooting.

Remaining scope: full load/soak and protocol campaigns, a live feature-combination
matrix, physical replica collection, complete consumer lag, transactional research
accounting and finer diagnostic error categories. Future adaptive development is
still deferred. Staging, commit and push remain the user's responsibility.

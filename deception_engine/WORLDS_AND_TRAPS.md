# Extensible Worlds and Traps: Immediate Operator Guide

## Intent

Make a new synthetic base world or a new generated trap asset available without
editing proxy, MITRE, evidence-store, scaling, or Grafana name lists.

The immediate supported contract is:

```text
one schemas/<world>.yaml
  -> auto-discovered virtual database/world
  -> tables and generated set-returning functions
  -> successful trap result carries structured identity
  -> MITRE R001 + risk + evidence + scaling/Grafana trap count
```

This is deterministic live deception. It is not the planned P0-P4 attack-path
steering or I0-I3 intervention system.

## Select a base world

The real backend remains the harmless `testdb`; it is only protocol/state
support. Choose which YAML world the deception layer presents by adding this to
the repository `.env`:

```dotenv
DECEPTION_ACTIVE_WORLD=research
```

Leave it blank to retain database-name mapping and the historical HR default:

```dotenv
DECEPTION_ACTIVE_WORLD=
```

`research` is a working example in `schemas/research.yaml`.

## Add a world

Copy `schemas/research.yaml` to a new lowercase filename and change:

```yaml
schema: your_world
settings:
  database_name: your_world_production
  database_aliases: [your_world, your_world_prod]
```

Add ordinary synthetic tables under `tables`. Supported column generators are
documented at the top of `generator.py`; examples include `pk_int`, `uuid`,
`name`, `email`, `choice`, `past_datetime`, `password`, `api_key`, and
`aws_access_key`.

The loader validates every table and function before activation: identifiers,
column names, generator names, bounds, duplicate columns/trap IDs, exposure
depth, foreign keys, and trap metadata. An `fk` must point to a declared
`pk_int` column, for example `ref: customers.id`; generated values are then
bounded by that parent table's effective per-session row count.

Never put literal secrets, credentials, real people, production rows, or raw SQL
in a world file.

A table can be a fully declarative trap too; no downstream name list is needed:

```yaml
tables:
  archived_service_tokens:
    exposure_depth: 3
    row_count: 12
    is_trap: true
    trap_id: "YOUR-WORLD-TABLE-001"
    trap_kind: "credential_table"
    strategy_id: "D3"
    mitre_technique_id: "T1555"
    risk_score: 12
    columns:
      - {name: id, type: pk_int}
      - {name: token, type: api_key}
```

## Add a function trap

Add this under the world's top-level `functions` mapping:

```yaml
functions:
  legacy_token_export:
    exposure_depth: 2
    row_count: 3
    description: "Over-permissive legacy helper with synthetic credentials"
    is_trap: true
    trap_id: "YOUR-WORLD-FUNCTION-001"
    trap_kind: "credential_function"
    strategy_id: "D3"
    mitre_technique_id: "T1555"
    risk_score: 12
    columns:
      - {name: service_name, type: choice, choices: [registry, runner, gateway]}
      - {name: service_user, type: email, domain: "@fictional.example"}
      - {name: access_token, type: api_key}
```

Use a strategy currently marked `APPROVED` by `GET /strategies`. The common
content choices are:

- `D2`: backup/archive lure
- `D3`: credential/token/key lure
- `D4`: sensitive-data lure

An invalid/unapproved strategy, unsafe identifier, duplicate database alias,
duplicate trap ID, unknown generator, broken foreign key, or malformed asset
makes the configuration fail closed. The previous configuration remains active
when a reload candidate fails validation.

Exposure depths are 1-3. A depth-2 function becomes available after a successful
access to a currently visible depth-1 asset. A guessed hidden function returns a
native-looking missing-function error and does not increment trap telemetry.

The supported function call is:

```sql
SELECT * FROM legacy_token_export();
```

Projection, `LIMIT`, and `OFFSET` are also supported. Arbitrary function SQL is
not executed; rows are generated deterministically inside the deception engine.

## Validate and activate YAML-only changes

The Compose service mounts `deception_engine/schemas` read-only. After the
initial deployment, adding or editing a YAML world does not require an image
rebuild. First disconnect demo/attacker clients, then inspect and reload:

```powershell
Invoke-RestMethod http://127.0.0.1:8001/worlds
Invoke-RestMethod -Method Post http://127.0.0.1:8001/worlds/reload
Invoke-RestMethod http://127.0.0.1:8001/readyz
```

Reload is rejected with HTTP 409 while any session is active. This prevents a
schema or trap change from contradicting facts already observed in that
session. Invalid YAML is rejected with HTTP 400 and does not replace the last
known-good in-memory configuration.

Changing `DECEPTION_ACTIVE_WORLD` itself still requires recreating the
deception-engine because environment selection is read at process startup:

```powershell
docker compose -f docker-compose.yml up -d --no-deps --force-recreate deception-engine
```

## Apply source-code changes once

For the initial rollout of this feature (or later source-code changes), do not
start the full stack. Rebuild/recreate the deception engine and the protocol
proxies:

```powershell
docker compose -f docker-compose.yml up -d --no-deps --build deception-engine pgproxy mysqlproxy
```

Because the proxy event schema changed, rebuild `mitre-agent`, `session-module`,
and `evidence-store` once before expecting end-to-end structured telemetry:

```powershell
docker compose -f docker-compose.yml up -d --no-deps --build mitre-agent session-module evidence-store
```

Prometheus, Grafana, metrics-bridge, and scaling-agent do not need a code or
configuration change for each new trap. They consume the generic MITRE trap
signal already used by the existing dashboard.

## Exercise the research example

Connect through the proxy to the real backing database name `testdb`. With
`DECEPTION_ACTIVE_WORLD=research`, the response world is the research YAML.

PostgreSQL:

```powershell
$env:PGPASSWORD = (Select-String -Path .env -Pattern '^POSTGRES_PASSWORD=').Line.Split('=',2)[1]
psql -h 127.0.0.1 -p 5432 -U postgres -d testdb
```

Then:

```sql
SELECT * FROM projects LIMIT 3;
SELECT * FROM information_schema.routines WHERE routine_name = 'legacy_token_export';
SELECT * FROM legacy_token_export();
```

MySQL:

```powershell
$env:MYSQL_PWD = (Select-String -Path .env -Pattern '^MYSQL_PASSWORD=').Line.Split('=',2)[1]
mysql -h 127.0.0.1 -P 3306 -u proxyuser testdb
```

Then:

```sql
SELECT * FROM projects LIMIT 3;
SELECT * FROM information_schema.routines WHERE routine_name = 'legacy_token_export';
SELECT * FROM legacy_token_export();
```

The first successful depth-1 read advances the session to depth 2. The function
call returns only generated synthetic values and emits:

```text
world_id=research
asset_id=research.function.legacy_token_export
asset_kind=function
trap_triggered=true
trap_id=RESEARCH-FUNCTION-TOKEN-001
trap_kind=credential_function
strategy_id=D3
trap_mitre_technique_id=T1555
trap_risk_score=12
```

That event is mapped generically to MITRE rule `R001_trap_table_access`, the
YAML-declared technique `T1555`, critical trap risk, evidence-store trap history, and the existing
trap-trigger metric used by scaling and Grafana.

## Recommended base-world workflow

1. Model the ordinary fictional business world first at depth 1.
2. Add coherent sensitive/lure assets at depth 2 with valid foreign keys.
3. Add requirement-specific traps at depth 2 or 3, each with a unique `trap_id`.
4. Check `/worlds`, drain sessions, call `/worlds/reload`, and confirm `/readyz`.
5. Demo normal reads, catalog progression, trap access, MITRE evidence, and the
   trap metric in that order.

The YAML world—not the harmless backing `testdb`—is the attacker-facing data
contract. Keep it fictional and internally coherent. Do not import production
database rows or credentials into the world files.

## Immediate boundaries

- YAML hot reload is local-instance scoped and requires all sessions to drain;
  a multi-replica deployment should roll all deception-engine replicas together.
- Function traps are deterministic set-returning functions with no arguments.
- New strategy classes still require the existing registry/policy review;
  adding a trap never expands the approved action space.
- Existing content strategies are not attack paths. P0-P4 steering, commitment
  ledgers, and post-success interventions remain pending by design.
- PostgreSQL simple-query and MySQL text-query paths carry the new outcome
  metadata. PostgreSQL extended-protocol outcome correlation remains outside this
  immediate change, matching the repository's existing safety boundary.

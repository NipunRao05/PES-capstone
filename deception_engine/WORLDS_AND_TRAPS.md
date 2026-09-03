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

Use an already approved strategy:

- `D2`: backup/archive lure
- `D3`: credential/token/key lure
- `D4`: sensitive-data lure

An invalid/unapproved strategy, unsafe identifier, duplicate database alias, or
malformed function definition makes that world fail closed during loading.

Exposure depths are 1-3. A depth-2 function becomes available after a successful
access to a currently visible depth-1 asset. A guessed hidden function returns a
native-looking missing-function error and does not increment trap telemetry.

The supported function call is:

```sql
SELECT * FROM legacy_token_export();
```

Projection, `LIMIT`, and `OFFSET` are also supported. Arbitrary function SQL is
not executed; rows are generated deterministically inside the deception engine.

## Apply only the changed services

Do not start the full stack. If the required existing dependencies are already
running, rebuild/recreate the deception engine and only the protocol proxy you
will use:

```powershell
docker compose -f docker-compose.yml up -d --no-deps --build deception-engine pgproxy
```

or:

```powershell
docker compose -f docker-compose.yml up -d --no-deps --build deception-engine mysqlproxy
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

## Immediate boundaries

- World YAML is loaded when deception-engine starts; there is no hot reload yet.
- Function traps are deterministic set-returning functions with no arguments.
- New strategy classes still require registry/policy review; reuse D2/D3/D4 for
  immediate traps.
- Existing content strategies are not attack paths. P0-P4 steering, commitment
  ledgers, and post-success interventions remain pending by design.
- PostgreSQL simple-query and MySQL text-query paths carry the new outcome
  metadata. PostgreSQL extended-protocol outcome correlation remains outside this
  immediate change, matching the repository's existing safety boundary.

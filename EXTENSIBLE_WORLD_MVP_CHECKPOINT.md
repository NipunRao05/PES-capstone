# Extensible Base-World and Trap MVP — Verification Checkpoint

Date: 2026-09-03

Status: **VERIFIED LOCALLY AND LIVE — DECLARATIVE TABLE/FUNCTION SCOPE**

## Intent

Allow an operator to add or replace a synthetic database base world and add a
new trap (including a misconfigured set-returning function that exposes generated
honeytokens) with minimal manual work, while integrating the successful trap
outcome with query events, MITRE/risk processing, session state, evidence,
scaling, and the existing Grafana trap counter.

The intended operator workflow is:

```text
add one deception_engine/schemas/<world>.yaml
set DECEPTION_ACTIVE_WORLD=<world>
rebuild only the affected services
```

This work does **not** implement the planned P0-P4 attack-path steering,
commitment ledger, or I0-I3 intervention system.

## What has been changed

### 1. YAML world discovery

- `deception_engine/schema_loader.py` now discovers every `schemas/*.yaml` world.
- Database names and aliases can be declared under `settings` instead of being
  added to a Python mapping.
- Duplicate/unsafe world identifiers and aliases fail closed.
- Existing HR, finance, and CRM aliases were moved into their YAML files while
  preserving the old compatibility mapping.
- `DECEPTION_ACTIVE_WORLD` was wired through `docker-compose.yml` and
  `.env.example`. This permits a virtual world to run over the existing harmless
  `testdb`, avoiding a new real backend database for every synthetic world.

### 2. Working example world

- Added `deception_engine/schemas/research.yaml`.
- It contains synthetic project, service-inventory, and migration-note tables.
- It declares a depth-2 function trap named `legacy_token_export`.
- The function returns only deterministically generated synthetic service users
  and API tokens.

### 3. Declarative function-trap handling

- `deception_engine/api.py` recognizes the bounded form:

  ```sql
  SELECT * FROM legacy_token_export();
  ```

- Declared functions use the existing deterministic fake-data generator; no
  configured SQL is executed.
- Exposure depth and existing approved strategy IDs (`D2`, `D3`, or `D4`) are
  checked before a function is served.
- A hidden/unapproved function returns a native-looking missing-function error
  and does not advance exposure.
- `information_schema.routines` can expose functions at the appropriate depth.
- Direct table traps can also declare `trap_id`, `trap_kind`, and `strategy_id`
  in YAML; unknown normal tables still use the safe D0 fallback.

### 4. Structured successful-trap events

- Deception responses now distinguish a visible lure from a successful trap
  result.
- Catalogue/table listings no longer set `is_trap` merely because a trap is
  visible.
- Successful managed trap responses carry structured fields such as:

  ```text
  event_schema_version
  world_id
  asset_id
  asset_kind
  trap_triggered
  trap_id
  trap_kind
  strategy_id
  strategy_registry_version
  ```

- Both MySQL and PostgreSQL simple/text proxy event paths were updated to carry
  those fields into query events.

### 5. Generic MITRE/evidence/session integration

- MITRE rule R001 now consumes `event.trap_triggered` instead of a fixed trap
  table-name list for v2 events.
- V2 trap signals are accepted only when the outcome is verified, successful,
  and authoritative from deception.
- Legacy events retain the previous name-based compatibility path.
- Session authoritative state and behavior state accept a structured function or
  table trap without knowing its name.
- Evidence-store query, MITRE, and trap records retain world/asset/trap/strategy
  identity.
- Scaling and the existing Grafana aggregate trap counter need no per-trap name
  change because they already consume the generic MITRE trap boolean.

### 6. Operator documentation

- Added `deception_engine/WORLDS_AND_TRAPS.md` with the YAML contract, example
  table/function traps, selective rebuild commands, and example client queries.

## Verification

- Complete deception-engine suite: **94/94 PASS**. This includes strict world,
  table, function, generator, foreign-key, duplicate-trap, strategy, projection,
  exposure-depth, reload, and mutation validation.
- MySQL and PostgreSQL proxy suites: **PASS**, including structured world,
  asset, trap, strategy, declared MITRE technique, and risk propagation.
- MITRE agent: **34/34 PASS**; session module: **256/256 PASS**; evidence store:
  **16/16 PASS** against freshly built images.
- Frozen live baseline `baseline-1788427577-a2cec9`: **40/40 PASS** after the
  trap case followed the same progressive-exposure contract as real sessions.
- Authoritative live state validation: **PASS** with 19 PostgreSQL and 13 MySQL
  verified outcomes, including CRUD, rollback, permissions, discovery, and
  contradiction checks.
- Local predeployment security gate: **19/19 PASS**; no public exposure or
  deployment was performed.
- Live `research` world validation passed through both real proxies. Each client
  traversed its synthetic base tables, discovered `legacy_token_export`, and
  received deterministic synthetic rows. Evidence sessions
  `90c9d777-6805-42f8-9bc5-dab36be2c1d7` (PostgreSQL) and
  `ca3f06d8-2b57-4b9b-a77b-bcb531180253` (MySQL) retained the declared function
  trap identity, D3 strategy, `T1555`, risk 12, and logical interaction.
- A closed-session `POST /worlds/reload` completed successfully and advanced the
  generation. Active sessions reject reload; invalid candidates fail atomically
  while the last valid world set remains active.

## Verified operator contract

1. Define a coherent synthetic base world in one
   `deception_engine/schemas/<world>.yaml` file.
2. Add ordinary tables and then declarative table or no-argument set-returning
   function traps with unique structured metadata.
3. Inspect `GET /worlds`, drain active sessions, and call `POST /worlds/reload`.
4. Select a fixed world with `DECEPTION_ACTIVE_WORLD=<world>` when required, or
   retain database-name/alias mapping.

The loader fails closed on malformed identifiers, generators, columns, ranges,
foreign keys, trap metadata, duplicate trap IDs, unsupported strategy/protocol
combinations, or unsafe configuration keys. Declarative function bodies are
never executed as SQL; only bounded deterministic generators create synthetic
rows.

## Deliberate boundaries / later work

- Function traps are deliberately bounded to no-argument set-returning functions.
- PostgreSQL discovery supports `information_schema.routines`; fuller `pg_proc`
  compatibility can be added if a target client requires it.
- Existing dashboards receive the generic trap total; per-world/trap panels are
  still future observability work.
- A new strategy ID still requires the existing human review and strategy
  registry workflow. Adding a trap does not expand the agent's action space.
- Content assets (D strategies), attack paths (P plans), and defender
  interventions (I actions) remain separate. This work does not implement the
  planned steering, commitment ledger, or interventions.

## Current repository state

- Completion changes are uncommitted in the working tree.
- No GitHub push, public exposure, or production deployment was performed.
- The Compose stack is healthy and the deception engine was restored to the
  default database-mapped world after the bounded `research` demonstration.

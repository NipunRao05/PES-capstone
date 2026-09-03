# Extensible Base-World and Trap MVP — Work-in-Progress Checkpoint

Date: 2026-09-03

Status: **SOURCE-LEVEL WORK IN PROGRESS — DO NOT CLAIM LIVE VERIFICATION**

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

## Verification completed before stopping

No containers were started.

- Python syntax compilation passed for the edited Python modules before the last
  declarative MITRE/risk metadata additions.
- YAML parsing passed for all world files.
- MySQL proxy: `go test ./...` passed.
- PostgreSQL proxy: `go test ./...` passed.
- MITRE focused suite: 32/32 passed.
- Evidence-store focused suite: 16/16 passed.
- Authoritative/behavior state focused suites: 21/21 passed.
- Extensible-world loader tests: two passed and the generator test was skipped
  because the host Python environment lacks Faker.
- `git diff --check` reported no patch-format errors; only Windows line-ending
  warnings.

The complete deception-engine suite could not run on the host because the host
Python environment lacks FastAPI, Uvicorn, and Faker. The Docker daemon was not
available, so image builds and live integration were not attempted.

## Incomplete work / resume blockers

### Must finish before calling the MVP deployable

1. **Finish declarative MITRE/risk propagation through both Go proxies.**
   The YAML and Python layers now contain `trap_mitre_technique_id` and
   `trap_risk_score`, but these two newest fields have not yet been added to the
   Go deception-response, interceptor, and publisher structs. Until completed,
   the trap still reaches generic R001 but falls back to R001's default
   `T1213.006`/critical scoring instead of the YAML-declared `T1555` value.

2. **Re-run syntax and focused suites after the last Python edits.**
   Work was stopped immediately after those edits at the user's request.

3. **Run the full deception-engine tests in its container/runtime.**
   Add focused tests for authorized function response, hidden-function failure,
   projection, LIMIT/OFFSET, routine discovery, strategy rejection, and the rule
   that metadata visibility never counts as a trigger.

4. **Perform one bounded live end-to-end validation.**
   Rebuild/recreate only `deception-engine`, one selected proxy, `mitre-agent`,
   `session-module`, and `evidence-store`. Verify generated rows, one query event,
   one MITRE event, one evidence trap record, and one aggregate Grafana/scaling
   trap increment. Do not start the whole stack unless dependencies are absent.

5. **Review/update frozen baseline expectations.**
   Database enumeration now auto-discovers `research_production`; exact-list
   baseline fixtures may need an intentional update or database visibility may
   need to be restricted to the active world.

### Strengthening for the next pass

- Validate table definitions as strictly as function definitions, including
  column generator names and duplicate columns.
- Add PostgreSQL `pg_proc` discovery for clients using `\df`; immediate discovery
  currently uses `information_schema.routines` and in-world clues.
- Add hot reload or an operator reload endpoint if restart-free YAML changes are
  required.
- Support only deliberately approved function argument contracts; current MVP is
  no-argument set-returning functions.
- Add explicit Grafana dimensions/panels by `world_id`, `trap_id`, and
  `trap_kind`. The existing dashboard receives the aggregate trigger count only.
- Decide whether a newly proposed strategy beyond D2/D3/D4 needs the existing
  blue-team registry approval/validation workflow.
- Design realism/consistency fixtures for whichever final base world replaces
  the research example.
- Later, keep content assets (D strategies), attack paths (P plans), and defender
  interventions (I actions) as separate registries when implementing the approved
  two-stage dynamic plan.

## Current repository state

- Changes are uncommitted in the working tree.
- No GitHub push was performed.
- No Docker/container state was changed.
- The source tree should be treated as a resumable implementation checkpoint,
  not as a completed verification record.

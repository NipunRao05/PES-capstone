# Realism + Protocol Corrective Pass

Status: **VERIFIED**

Date: 2026-09-02

Starting repository state: `727b055` (`i did it`), clean worktree

Scope: bounded remediation of the completed realism/protocol audit. This is not
a numbered implementation phase and adds no steering, intervention, path-world,
prepared-statement, persistence, deployment, or cloud behavior.

## Corrected contracts

### Deceptive-object authority

- A managed object is accessible only when its YAML `exposure_depth` is no
  greater than the session's authoritative Redis exposure depth and its mapped
  strategy is approved.
- Authorization runs before SELECT, COUNT, INSERT, UPDATE, DELETE, or exposure
  advancement.
- A guessed hidden object returns PostgreSQL `42P01` or MySQL `1146/42S02` and
  cannot advance depth.
- Proxy-native trap success fallbacks were replaced with fail-closed relation
  errors. The deception engine is now the only live exposure authority.
- The existing depth progression remains: depth-1 access exposes depth 2;
  depth-2 access exposes depth 3; exposed traps remain available.

### Mutation outcome atomicity

- MySQL accepts a zero-column deceptive mutation decision and returns a proper
  OK packet with the engine's affected-row count instead of forwarding the
  already-recorded mutation to the physical backend.
- Invalid bounded UPDATE/DELETE/INSERT syntax is rejected before overlay state
  changes.
- Both proxies notify the existing `/session/start` and `/session/end`
  lifecycle endpoints. A clean disconnect removes exposure, mutation, and
  uncommitted transaction snapshot keys; retained research evidence is not
  deleted.

### Catalog and persona consistency

- `information_schema.tables`, `information_schema.columns`,
  `pg_catalog.pg_tables`, psql `\dt`, and psql `\d` for exposed YAML tables use
  the same schema and exposure authority.
- The bounded PostgreSQL catalog implementation covers the exact PostgreSQL 16
  psql relation lookup, relation detail, attribute, and empty optional-object
  queries needed by `\dt` and `\d`. It does not emulate all PostgreSQL catalogs.
- MySQL `SHOW TABLES`, `DESCRIBE`, `DESC`, `SHOW COLUMNS`, and qualified
  `testdb.table` access agree. Unknown physical objects still pass through.
- The canonical personas are PostgreSQL 16.13, MySQL 8.0.45, connected database
  `testdb`, and PostgreSQL schema `public`. Connected database visibility,
  `current_database()`, `table_catalog`, `pg_database`, `DATABASE()`, and
  `SHOW DATABASES` now agree.

### Bounded SQL and protocol semantics

- Supported managed-table SQL remains deliberately small: identifier
  projections, `WHERE id = positive integer`, valid bounded LIMIT/OFFSET, and
  the existing bounded mutations and metadata `=`, `LIKE`, and `ILIKE` filters.
- Unsupported WHERE, malformed WHERE/LIMIT/OFFSET, ORDER BY, metadata IN, and
  unknown projections return deterministic protocol-native errors. Clauses are
  never silently ignored.
- Result decisions carry schema-derived column types. PostgreSQL Simple Query
  RowDescription uses integer, bigint, numeric, boolean, date, timestamp, or
  text OIDs as appropriate. MySQL ColumnDefinition types use the equivalent
  obvious types.
- PostgreSQL NULL is encoded as NULL rather than an empty string. MySQL uses
  the protocol NULL marker. Boolean text encoding is protocol-native, and
  integer/fixed numeric values no longer render in scientific notation.

### Research-data integrity

- Evidence sanitization preserves typed derived count/score/rate/boolean
  features even when their key contains `credential`; secret/password/token
  values remain redacted.
- New evidence timestamps are normalized to UTC ISO-8601, including safe legacy
  epoch ingestion. Returned event/artifact collections are deterministically
  chronological with stable ID tie-breaking.
- MITRE detailed trap events and session summaries now carry explicit
  provenance. Only a detailed trap event creates a logical `trap_events`
  record; summaries cannot become a second logical interaction.
- Synthetic `sessions.logout_at >= sessions.login_at` and
  `api_keys.last_used >= api_keys.created_at` are enforced deterministically.

## Verification evidence

### Automated

- Deception engine: **80/80 PASS** in the rebuilt image.
- Evidence store: **16/16 PASS**.
- MySQL proxy: all packages PASS; 40 named tests; focused protocol corrections
  PASS; `go vet ./...` PASS.
- PostgreSQL proxy: all packages PASS; 57 named tests; focused protocol
  corrections PASS; `go vet ./...` PASS.
- Scaling agent: all packages PASS; 38 named tests; `go vet ./...` PASS. Its
  threshold, cooldown, and scale-down regression tests remain green.
- Authoritative-state live validator: PASS with 19 PostgreSQL and 13 MySQL
  verified outcomes, exact one expected failure each, transaction/role/schema/
  consistency checks PASS.

### Live re-audit

- PostgreSQL and MySQL fresh hidden-table SELECTs returned native not-found
  errors. A fixed-session engine/Redis check remained at exposure depth 1 after
  a denied hidden guess.
- Normal PostgreSQL and MySQL sessions progressed 1 -> 2 -> 3 and accessed the
  trap only after exposure.
- MySQL salary changed by exactly 100 after a successful deceptive UPDATE; an
  unsupported failed UPDATE left that value unchanged. Qualified INSERT and
  DELETE returned OK and did not fall through to the backend.
- PostgreSQL `\dt`, `\d public.employees`, and `\d public.departments` completed
  under psql 16 catalog behavior and matched YAML columns/types/nullability.
- PostgreSQL version surfaces both reported 16.13; MySQL SQL and handshake
  surfaces reported 8.0.45. Both protocols reported/contained `testdb`.
- All audited unsupported PostgreSQL SQL examples and the corresponding MySQL
  examples returned explicit errors.
- PostgreSQL displayed a generated NULL manager as `[NULL]`; executive salary
  rendered as a fixed integer.
- Live evidence retained numeric credential feature values `3` and `2`, kept a
  boolean signal, redacted synthetic secret/token values, and normalized legacy
  epoch time to `2026-08-29T10:40:00Z`.
- A live trap session had one `trap_events` record and one logical MITRE trap.
- Live generated samples had 0/100 session time violations and 0/23 API-key
  time violations.
- Exact Redis scans after closed MySQL and uncommitted PostgreSQL sessions found
  no exposure, mutation, or mutation-transaction keys.
- A two-event bounded live scaling smoke produced `1 -> 3`, held the immediate
  second event at 3 under the 30-second cooldown, then produced `3 -> 2` after
  134 seconds below the 120-second scale-down threshold.

## Preserved boundaries and remaining limitations

- Physical PostgreSQL/MySQL databases remain authoritative for passthrough
  objects; no physical deceptive tables were created.
- PostgreSQL extended/prepared result synthesis remains unsupported by design.
- ORDER BY and general predicates remain unsupported and now fail explicitly.
- Native catalog emulation is intentionally limited to the tested discovery
  surfaces and currently exposed YAML objects.
- Lifecycle cleanup is best effort when the engine is unavailable; TTL remains
  the fallback. On the verified healthy local path, disconnect cleanup passes.
- Historical evidence was not rewritten. Normalization applies to new records
  and legacy timestamps when read/ingested through the corrected path.
- Dynamic steering, world commitments, intervention, and the factorial research
  experiment remain pending exactly as before this corrective pass.

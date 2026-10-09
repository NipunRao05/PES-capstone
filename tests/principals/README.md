# Persistent deceptive principals

Status: VERIFIED for the bounded native paths below (2026-10-09).
MITRE integration temporarily disabled; source retained.

## Authentication and SQL boundary

- PostgreSQL: startup username branches before forwarding any startup packet;
  SCRAM-SHA-256 only, simple query protocol only for virtual sessions.
- MySQL: current native-password greeting salt is used to verify the client's
  challenge response; no synthetic handshake response is sent to the backend.
- Seeded users keep existing backend authentication. Reserved `fake_` accounts
  always fail closed if the registry, secret, protocol, or proof is unavailable.
- Synthetic sessions execute only existing managed deceptive queries. Passthrough,
  prepared/extended queries, physical objects, and unsupported commands are denied.
  Existing connection managers still require backend TCP availability (MySQL also
  uses its greeting); no backend service login or physical privilege is used.
- Only an authenticated seeded administrator (`postgres` / `root`) may manage
  synthetic accounts. This explicit bounded policy does not activate D5 or change
  the strategy registry. Account commands require autocommit.
- Names are normalized lowercase `fake_[a-z0-9_]{1,48}`. Passwords are 8-128
  printable ASCII characters excluding quotes/backslashes. Other syntax is denied.

Supported SQL forms (password placeholders are not usable credentials):

```sql
-- PostgreSQL
CREATE USER fake_example PASSWORD '<generated-password>';
CREATE ROLE fake_example LOGIN PASSWORD '<generated-password>';
ALTER ROLE fake_example PASSWORD '<new-generated-password>';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fake_example;
ALTER ROLE fake_example NOLOGIN;
DROP ROLE fake_example;
-- MySQL; unquoted names or paired single quotes, optionally @'%'
CREATE USER 'fake_example'@'%' IDENTIFIED BY '<generated-password>';
ALTER USER fake_example IDENTIFIED BY '<new-generated-password>';
GRANT SELECT, INSERT, UPDATE, DELETE ON testdb.* TO fake_example;
ALTER USER fake_example ACCOUNT LOCK;
DROP USER fake_example;
```

SELECT alone or SELECT followed by a subset of INSERT/UPDATE/DELETE is accepted
for GRANT. New principals initially have SELECT only. DROP retains a disabled
tombstone; it does not remove historical evidence or allow name reuse. New table
DDL and arbitrary persistent objects are unsupported because this branch has no
synthetic object/catalog authority for them. `persistent_objects` remains empty.

## Configuration and schema

`DECEPTIVE_PRINCIPAL_HMAC_SECRET` is base64 of at least 32 random bytes, shared
only by both proxies and the engine. The local generated value is in ignored
`.env`; `.env.example` contains no secret. Keep it stable. Rotation needs a registry
migration; changing it silently makes existing lookup keys inaccessible. A missing
or invalid secret disables synthetic creation/authentication; seeded auth remains.
Private `/principals/*` POST requests authenticate with this secret and carry a
short deadline. Principal Redis calls have bounded connect/read timeouts. Expired
requests cannot proceed to registry writes. `/decide` never receives credentials.
Redis AOF with `appendfsync always` uses the existing `redisdeception` volume.

Record fields:

```text
principal_id, principal_key                  full HMAC-SHA256 identity material
username, protocol, principal_origin         attacker_created_deceptive
created_by_session_id, created_by_principal_id
created_at, updated_at, last_login_at
enabled, visible_role, persistent_permissions
strategy_id, world_id, world_revision
exposure_depth, persistent_objects, persistent_mutations
login_count, linked_session_ids              latest 256 IDs; count is not truncated
credential_revision, verifier
first_reuse_at, time_to_first_reuse_seconds
```

The lookup key is HMAC(protocol/username). Principal identity uses protocol,
username, and initial random verifier context; password rotation retains identity.
PostgreSQL stores salt/iterations/StoredKey/ServerKey. MySQL stores double-SHA1
verification material plus random identity context. Neither stores plaintext.
World ID remains empty because main has no authoritative producer for it.

Durable state: permissions, disabled status, committed managed-table overlays,
exposure, stable generated-row seed, revision, and creator/login metadata.
Session-only state: transaction overlays/snapshots, temporary protocol state,
query counters, current binding, and deadlines. Bindings expire after four hours.
Disconnect never promotes uncommitted overlays. COMMIT checks the world revision;
conflicts fail with 40001 and require rollback. Exposure progression persists
independently of transaction rollback. Explicit object DDL is rejected.

## Evidence and metrics

Existing session topics carry `deceptive_principal_created`,
`deceptive_principal_authenticated`, and `session_link`. Links contain creator and
child session IDs, principal ID, relationship `credential_persistence`, confidence
1.0, and the authenticated-credential reason. Evidence is asynchronous and does
not participate in login decisions. Existing auth/session/query events optionally
carry `deceptive_principal_id`, `principal_origin`, `creator_session_id`, and
`is_return_session`. Query outcomes keep canonical `authority` and existing fields;
return queries also carry `post_return_exploration_depth` and existing `is_trap`.
Creation SQL is redacted before logs, interception, normalization, and publishing.

`GET /principals/metrics` and the existing Prometheus bridge expose label-free
created/reused/return-session counters and reused/created (zero-safe). Reused counts
are distinct principals; repeated logins only increase return sessions. Creation
and authentication timestamps plus detailed query evidence support first reuse,
return exploration, and trap measurements without inferring identity from IP.

## Validation commands and observed results

Run Go commands from each proxy directory:

```text
go test -json ./internal/principal ./internal/session ./internal/interceptor ./internal/protocol ./internal/publisher
go vet ./internal/principal ./internal/session ./internal/interceptor ./internal/protocol ./internal/publisher
```

Each proxy: 12 top-level tests passed (22 including subtests), 0 failed; vet passed.
From deception_engine (using the existing dependency image if needed):

```text
python -m unittest test_principal_registry test_stateful_crud test_realism_protocol_corrective test_deception_helpers
```

47 passed, 0 failed. Evidence Store `python -m unittest test_evidence_store`:
18 passed, 0 failed. Session Module `python -m unittest test_authoritative_state`:
11 passed, 0 failed. Total: 100 top-level tests, 0 final failures.
`docker compose config --quiet` and `git diff --check` passed.

Native live runner, from repository root, requires the existing local Docker stack
and replay dependency image. Supply a fresh reserved name for a new complete run:

```text
python tests/principals/run_native_smoke.py create --name fake_new_run
python tests/principals/run_native_smoke.py return --name fake_new_run
python tests/principals/run_native_smoke.py reconnect --name fake_new_run
python tests/principals/run_native_smoke.py disable --name fake_new_run
python tests/principals/audit_live.py
```

The audit checks the fixed demonstration identities `fake_compro1` and
`fake_unused`. Native clients are libpq (psycopg simple queries) and PyMySQL.
Credentials are derived in memory from the local secret for reproducible smoke
runs and sent to the disposable client only through stdin. They are never printed
or written to artifacts. Distinct unused Docker source addresses are verified
before use; the Docker stack's existing subnet is used.

Both protocols passed creation, duplicate rejection, native login, wrong password,
rollback, commit/reconnect, uncommitted disconnect, trap queries, changed-IP
reconnect, and disabled-login checks. Physical `pg_roles` / `mysql.user` counts
were zero for the synthetic names. State survived Redis and engine restart.
Registry outage rejected login/creation, preserved seeded auth, and left all
principal counters unchanged after recovery. Evidence outage did not block login.
The test found and corrected delayed pre-fix requests; only the confirmed orphan
validation login/account were reconciled, with all failed-auth/query evidence kept.
The psycopg disconnect fixture was also corrected to avoid its implicit commit.
The four demonstration principals are disabled after validation.

The read-only security audit found zero plaintext matches across both Redis
stores, captured end offsets of six Redpanda topics, returned evidence, and nine
service logs. Both native protocols had creation/link evidence and returning IPs
172.19.0.241 and 172.19.0.242. Source IP is observational only. This audit proves
the exercised credentials/paths, not arbitrary SQL submitted outside this subset.

## Files for this feature

- `.env.example`, `docker-compose.yml`, `VALIDATION_CHECKPOINT.md`
- `deception_engine/api.py`, `mutation_store.py`, `principal_registry.py`,
  `principal_runtime.py`, `test_principal_registry.py`
- In each of `pgproxy/internal/` and `mysqlproxy/internal/`:
  `protocol/handler.go`, `protocol/principal.go`, `protocol/principal_auth.go`,
  `principal/principal.go`, `principal/principal_test.go`,
  `session/session.go`, `interceptor/interceptor.go`, `publisher/publisher.go`
- `session_module/authoritative_state.py`, `session_module/test_authoritative_state.py`
- `evidence_store/main.py`, `evidence_store/test_evidence_store.py`
- `observability/metrics_bridge/metrics_bridge.py`
- `tests/principals/native_smoke.py`, `run_native_smoke.py`, `audit_live.py`, `README.md`

Earlier uncommitted MITRE-disconnection and query-outcome changes remain intact.
MITRE source files were not modified. No GitHub push was performed.

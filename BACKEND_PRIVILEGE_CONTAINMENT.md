# Backend privilege containment

2026-10-31. Implemented and locally verified for the contained baseline. No Azure
resources/public ports, actual .env changes, volume deletion or Git mutation.

## Invariant and previous risk

No attacker-selected identity or SQL may obtain native administrative execution.
Previously both proxies relayed native authentication, so postgres/root could be
administrative backend sessions, and engine failures could forward arbitrary SQL.
Now visible seed identities are decoys authenticated separately from fixed native
runtime identities. Admin accounts remain initialization/operator-only.

## Execution-path inventory

| Protocol/path | Visible identity | Native identity | SQL/results |
|---|---|---|---|
| PG seed startup | postgres, testdb | honeypot_pg_runtime | Independent SCRAM conversations; no client startup options/proof forwarded |
| MySQL seed startup | root/proxyuser, testdb | honeypot_mysql_runtime | Local native proof validation; fixed backend login/capabilities |
| fake_ startup/query | Virtual registry identity | No authenticated backend identity | Existing Redis principal path; initial backend TCP/greeting dependency remains |
| Simple/text synthetic | Seed/virtual session | No native query | D0/D1/D2/D3/D4/D6 producer result |
| Account statements | Visible seeded administrator | No native query | Reserved fake_ management only; all other account statements rejected |
| Native fallback/passthrough | Visible decoy session | Fixed restricted account | Positive whole-statement grammar only; safe native result |
| PG extended/portal/function messages | Decoy session | No SQL forwarding | Unsupported error and discard through Sync |
| PG unauthenticated CancelRequest | None | None | Closed locally, no backend dial |
| MySQL prepared/change-user/kill/admin/unknown commands | Decoy session | No command forwarding | Unsupported protocol-native error |
| MySQL COM_INIT_DB | Decoy session | Restricted account | Only fixed testdb allowed; failed switch cannot change session identity |
| MySQL PING/QUIT | Decoy session | Restricted account | Bounded non-SQL control |

## Accounts and exact intended grants

PostgreSQL `honeypot_pg_runtime`: LOGIN; NOSUPERUSER, NOCREATEDB, NOCREATEROLE,
NOREPLICATION, NOBYPASSRLS; no role memberships; no database/schema/relation ownership.
CONNECT on testdb and USAGE on public. No application-table write privilege is
granted. PUBLIC CREATE/TEMP on testdb and CREATE on public are revoked. Default
transaction_read_only=on and statement_timeout=2s. Public system metadata/function
privileges are not falsely described as absent: native SQL grammar prevents calls,
and server-side privileged primitives additionally enforce native role checks.

MySQL `honeypot_mysql_runtime`@`%`: USAGE globally and SELECT on testdb.* only.
No GRANT OPTION, role memberships/default roles, FILE, PROCESS, SHUTDOWN, CREATE USER,
RELOAD, SUPER or administrative dynamic privileges. The initializer refuses unexpected
remaining dynamic grants. No DML/DDL privileges are required for empty physical tables.

Both runtime identities are internal and are never offered as public login names.
Synthetic current_user/session_user reflects the decoy identity; raw backend auth
errors and query error text cannot disclose internal account names.

## Initialization and existing volumes

`backend-containment-init` reuses the existing replay image/DB drivers, runs only an
operator bootstrap script, exposes no port, and exits. Both proxies depend on its
successful completion. It creates missing runtime identities, reconciles restricted
grants/memberships, verifies attributes, and operates on existing volumes. It does
not drop databases, rows, administrators or volumes. Unexpected PG runtime ownership
fails closed for operator review. Re-running is idempotent; fresh databases need no
manual post-deployment SQL. Database startup is boundedly retried.

The launcher derives independent runtime passwords by domain-separated HMAC from
the existing stable principal secret, unless explicit runtime passwords are supplied.
Only the child process environment receives them. Runtime passwords must be printable
ASCII 24..128 characters and differ from public decoy passwords. No actual .env was
edited. Optional PG_DECOY_PASSWORD, MYSQL_DECOY_PASSWORD and MYSQL_DECOY_ROOT_PASSWORD
separate public logins from operator passwords; local compatibility defaults retain
existing seed login passwords. Public deployment must explicitly set separate values.
Changing runtime/HMAC keys requires rerunning initialization before proxy recreation.
The principal key's existing rotation/migration requirements remain unchanged.

## Native grammar and fallback policy

Native grammar accepts only bounded integer/NULL/boolean constant SELECT lists and
plain BEGIN/START TRANSACTION/COMMIT/ROLLBACK/END/ABORT forms. MySQL additionally
allows exact SET NAMES utf8mb4/utf8/latin1/ascii for client initialization. A single
trailing semicolon is allowed. No comments, compound statements, identifiers,
functions, parameters, CTEs, arbitrary SET, DML or DDL are native-allowlisted.

| Cause | Final policy |
|---|---|
| Intentional engine passthrough | Safe grammar -> restricted native account; otherwise synthetic rejection |
| Timeout, transport failure, 5xx, open breaker | Same final allowlist; no arbitrary fallback |
| Invalid/unknown engine response | Same final allowlist |
| Unsupported SQL or parse failure | Fail closed unless it exactly matches safe native grammar |
| Engine policy rejection | Preserve synthetic protocol-native error; no fallback |
| Redis rate-limit dependency failure | Existing engine fail-open setting remains, but cannot bypass proxy native gate |
| Replay/full/ambiguous/internal error | Engine behavior remains; any fallback still passes the final native gate |
| Account/principal service failure | Existing reserved namespace/account path fails closed |

PG rejected statements use SQLSTATE 42501; unsupported extended messages use 0A000.
MySQL uses bounded 1142/42000 or unsupported-command errors. Backend error SQLSTATE/
number is retained with generic text. Server-internal exceptions/credentials are not
returned. PostgreSQL transaction-error recovery retains its existing failed-state
and rollback contracts.

## Verification and known limits

Positive grammar tests cover privileged SQL families, comments, executable comments,
compound statements, file/process/plugin functions and unknown syntax. Mocked wire
tests prove unsafe fallback does not reach a backend, fixed login replacement,
SCRAM startup budget, malformed SCRAM rejection and cancellation rejection. Dangerous
COPY PROGRAM/OUTFILE/plugin payloads run only through classifiers/mocked boundaries;
no OS command, host file write or plugin install is executed.

`scripts/validate_backend_containment.py` uses a disposable local driver container
with credentials supplied privately on stdin. It verifies real runtime role grants,
native SELECT 1, HR catalogs/rows/traps, D6, negative administrative statements and
virtual principal commit/reconnect/exposure on both protocols. New virtual fixtures
are disabled afterward, retaining tombstones/evidence; no physical fake_ user is
created. Local ordinary sessions and all fake_hp1_* fixtures are engineering traffic.
No real attacker dataset is claimed.

Observed corrections during implementation: MySQL parameter formatting required
escaping literal percent host syntax; PostgreSQL needed a bounded 64-message startup
budget; PyMySQL requires bounded SET NAMES; PG identity probes needed synthetic routing.
None was resolved by granting additional administrative runtime privileges.

This is not a proof against server vulnerabilities or a complete host sandbox.
Egress restrictions, image/dependency review, resource/storage bounds, reboot policy,
backup/restore and cloud network verification remain deployment requirements. No
backend Redis/database was restarted or volume erased for this migration.

## Exact validation commands and results

Use the bundled Python executable with `-B`; Python test commands below ran with
PYTHONPATH pointing to the existing ignored `.runtime/pass2-tooling`. The launcher
resolves its own `.runtime/tooling` PyYAML. No dependencies or caches are committed.

From `deception_engine`:

```text
python -B -m pytest -q -p no:cacheprovider test_hr_world_freeze.py test_base_world_realism.py test_strategy_registry.py test_action_provenance.py test_world_commitments.py test_world_commitment_lifecycle.py test_principal_state.py test_principal_registry.py test_query_correlation.py test_query_idempotency.py test_postgres_error_state.py test_phase_b_invariants.py test_decision_trace.py test_live_trace.py test_trace_outbox.py
```

192 PASS, 51.54s. Initial checkpoint191 PASS/1 FAIL was a new fixture calling
StrategyRegistry() instead of StrategyRegistry.load(); corrected fixture, no
assertion weakening. Final metadata/default-source changes additionally verified:

```text
python -B -m pytest -q -p no:cacheprovider test_hr_world_freeze.py test_base_world_realism.py test_decision_trace.py test_live_trace.py
```

33 PASS,22.51s. From `evidence_store`:

```text
python -B -m pytest -q -p no:cacheprovider test_world_trace_metadata.py test_strategy_traces.py test_strategy_trace_endpoint.py test_query_application_correlation.py test_strategy_outcomes.py test_trace_index.py
```

44 PASS,1.41s. From `scripts`:

```text
python -B -m unittest -q test_configuration.py
```

13 PASS. From each of `pgproxy` and `mysqlproxy`:

```text
go test ./internal/connection ./internal/protocol ./internal/principal ./internal/interceptor ./internal/publisher -count=1 -timeout 60s
```

All tested packages PASS; MySQL connection package has no tests. New two-sided
SCRAM, malformed GS2, cancellation, fixed identity/capability, forbidden grammar
and unsafe engine503 fallback regressions are included. Older fixtures originally
expected now-forbidden arbitrary backend DML/prepared execution; they now use safe
constant native queries while retaining transaction/error/rollback assertions.

Canonical local operations from repository root:

```text
python -B scripts/honeypot.py config-check
python -B scripts/honeypot.py config-status
python -B scripts/honeypot.py compose config --quiet
python -B scripts/honeypot.py compose up -d --build backend-containment-init pgproxy mysqlproxy deception-engine evidence-store
python -B scripts/honeypot.py compose up -d backend-containment-init
python -B scripts/audit_base_world.py
python -B scripts/validate_backend_containment.py
python -B scripts/verify_runtime.py
```

Initializer rerun and live six-check harness PASS. Generic verifier exit0/13 checks
PASS, nine Prometheus targets and53 expressions. Final live checkpoint UTC
2026-10-31T09:59:10..09:59:17, fixtures fake_hp1_pg_82cdba5b and
fake_hp1_mysql_6703df3b, disabled afterward. Earlier fake_hp1_* fixtures likewise
remain disabled. Local outputs are `.runtime/hardening-pass1-runtime.json` and
`.runtime/runtime-verification.json`. All current local traffic is engineering data.
The JSON marker is a harness marker, not a newly implemented event-origin contract.

Observed retained sample: query world metadata in both protocols;106 world-v1
decisions and106 applications among the first121 retained records of each kind.
This confirms storage/linkage, not outcome completeness or a research denominator.
Actual physical fake_hp1_* user counts were zero in both native engines.

# Pass 2 — Principal Transaction Lifecycle Formalization

> Subsequent Pass 3 update — 2026-10-28: preserved as the Pass 2 record. See
> `POSTGRES_SYNTHETIC_ERROR_STATE.md` for the now-implemented ordinary PostgreSQL
> local-error abort gate, early principal error transitions and private proxy abort
> reconciliation. Their deferred labels below describe the Pass 2 checkpoint.

2026-10-28. **IMPLEMENTED; VERIFIED BY FOCUSED TESTS.** Runtime health and live
Redis/backend recovery are **NOT VERIFIED**. No service was rebuilt/restarted.

## 1. Purpose

Make the existing virtual principal lifecycle explicit without changing its SQL
subset, login behavior, Redis schema, identity, verifiers, TTLs or config defaults.
The one intentional behavior correction is the ordinary PostgreSQL mixed
transaction rollback bug reproduced below. Pass 1 is retained in
`STATE_WORLD_AUDIT.md`; this document supersedes its planning/status statements
only for the implemented Pass 2 boundary.

## 2. Authoritative owner

`deception_engine/principal_runtime.py::query` still owns the live principal query
path under the existing principal lock. `principal_state.py::PrincipalTransactionContext`
centralizes lifecycle transitions over the **same binding dictionary**, not a
second transaction store. `PrincipalRegistry.login` uses its initial binding
factory. `MutationStore` remains the working-overlay owner; the principal JSON
remains the committed mutation authority. Native engines still own physical SQL.

Changed production symbols:

- `principal_state.py::PrincipalTransactionState`, `PrincipalTransactionContext`,
  `PrincipalTransactionConflict` (new, standard library only).
- `principal_runtime.py::query`, `install` and `end_session` (new cleanup helper).
- `principal_registry.py::PrincipalRegistry.login` (binding construction only).
- `pgproxy/internal/protocol/handler.go::Handler.drainBackendResponses` (backend
  transaction command-tag correction only).

Inspected without production changes: both proxies' `Handler.Run`,
`notifyDeceptionSession`, `principalLoop`, `authenticatePrincipal` and
`servePrincipalQuery`; MySQL `transaction.go::finalizeDeceptionTransaction`;
`mutation_store.py::MutationStore.finalize_transaction`, `cleanup_session`;
registry `command`; exposure/generator cleanup. No owner discrepancy from Pass 1.

## 3. Lifecycle

The enum is a view of legacy `tx`/`failed` fields, not a new persisted field.
Failed takes precedence exactly as before; unsupported/missing legacy fields are
not silently normalized or migrated.

| State | Representation | Existing transitions |
| --- | --- | --- |
| IDLE | `tx=false`, `failed=false`; wire I | BEGIN/START TRANSACTION -> ACTIVE; successful DML autocommits; COMMIT/ROLLBACK remain IDLE |
| ACTIVE | `tx=true`, `failed=false`; wire T | DML stages overlay; COMMIT promotes then IDLE; ROLLBACK restores then IDLE; normal PostgreSQL operation failure -> FAILED |
| FAILED | `failed=true`; wire E | Non-finalizing queries rejected; ROLLBACK -> IDLE; COMMIT returns ROLLBACK and restores -> IDLE |
| Disconnected | Binding removed, no new CLOSED field | Working copies discarded; only fresh authentication creates another binding |

Helpers: `new`, `begin`, `commit`, `rollback`, `abort`, `record_query_failure`,
`refresh_revision`, `track_working_keys`, `state`, `expected_mutation_keys`.
Commit checks the existing baseline revision before promotion. A stale commit
sets failed and raises the local conflict signal; runtime preserves the existing
40001/1213 response and stores the failed binding. Pending keys remain until
rollback/disconnect. Promotion failure never calls finalization/restore.

Repeated BEGIN retains pending overlays and revision, as before. Idle/double
COMMIT/ROLLBACK do not promote. Empty ACTIVE COMMIT still increments principal
revision; empty rollback does not. This pass does not impose native nested-BEGIN
semantics on the bounded virtual SQL path.

## 4. Pending vs committed state

- Binding: unchanged `key`, `tx`, `failed`, `revision`; `mutation_keys` is still
  absent at login and populated after query handling. It inventories working keys,
  including restored committed overlays, rather than a complete SQL write-set.
- Working rows: `mutation:<sid>:<table>`; rollback snapshots:
  `mutation-tx:<sid>`. Created lazily by the unchanged mutation store.
- Committed rows: principal `persistent_mutations` and `world_revision`. Explicit
  commit/autocommit promotion retains the existing 1 MiB overlay limit and Redis
  write ordering. Only existing supported fake INSERT/UPDATE/DELETE are promoted.
- Both explicit end transitions discard the mutation-store snapshot, then restore
  from the committed principal record. Calling the lower-level snapshot finalizer
  with `commit` is intentional even on principal ROLLBACK: that drops the obsolete
  snapshot; restoration supplies the correct principal rollback, as before.
- Ordinary seeded-session fake overlays remain session-scoped even after COMMIT.
  No durable ordinary-session mutation model was added.
- Permissions/reader-writer role are immediate, persistent admin registry updates,
  outside the returning session's row transaction. Account commands marked
  transaction-active remain rejected. No transactional permission model was added.
- Exposure depth is immediate observational metadata, saved independently of row
  promotion. Rollback/return preserves it. It is not a fact-level observation ledger.

## 5. PostgreSQL semantics and mixed result

Virtual principal commit/rollback/disconnect/autocommit are tested through the
shared engine path and real registry proof helpers. Normal denied/unsupported
operations during ACTIVE mark FAILED; COMMIT in FAILED restores and returns a
ROLLBACK tag. Early SQL validation exceptions retain their existing behavior.
Ordinary synthetic errors still do not uniformly set native E; that is **DEFERRED**.

**Mixed regression reproduced and fixed:** seeded/ordinary session begins a native
transaction, stages a fake overlay, then incurs a native error. At finalization
the proxy has `TxStatus=E` and `deceptionTxDirty=true`. Backend PostgreSQL answers
COMMIT/END with `CommandComplete("ROLLBACK")` and ReadyForQuery I. Previously
`drainBackendResponses` selected `/transaction/commit` from submitted SQL, retaining
the pending fake overlay despite native rollback. The focused protocol test
models that exact pre-state and backend response. Both COMMIT and END cases failed
before the fix and pass after it; normal commit/rollback controls pass too.

The correction records the native completion action while draining and uses it
when finalizing already-recognized transaction-end SQL. Backend bytes/status and
ordinary passthrough remain unchanged. No new command spellings, savepoint support,
or generic transaction subsystem was introduced. Test uses a simulated backend and
overlay endpoint; a fresh physical database reproduction was not run.

## 6. MySQL semantics

Same committed/pending invariant through the shared principal lifecycle.
Virtual MySQL normal statement errors remain ACTIVE rather than causing a
PostgreSQL-style abort. Stale revision conflict still fails the binding. Virtual
status serialization and native-password auth are unchanged.

Ordinary backend MySQL still owns autocommit flags, implicit DDL commit, new BEGIN
committing a previous transaction, chain variants and server status. Existing
`transaction.go` boundary tests passed without production MySQL changes. Virtual
MySQL remains the existing smaller SQL subset; no general SET autocommit or DDL
support was added.

## 7. Disconnect behavior

Both proxies' actual `Run` defer calls `/principals/end` for the session after
QUIT/Terminate, EOF or auth failure with a known session. New Go tests exercise
that routing through native protocol handlers and a stub private registry service;
they assert no auto-COMMIT request and no synthetic traffic reaching the backend.

The actual registered engine end route now calls `end_session`: delete binding,
cleanup exposure, cleanup mutations/snapshot, cleanup generator cache. It never
promotes or writes the principal record. ASGI tests verify repeated end, real route
dispatch, key deletion, byte-identical retained principal JSON, and rejection of
later queries on the old binding. Redis is an in-memory fixture in these tests.
No claim of guaranteed cleanup if the notification cannot reach the engine or
the proxy is killed: existing TTL/failure limits remain.

## 8. Reconnect behavior

Fresh native/SCRAM proof helpers authenticate the same principal in a new session.
It starts IDLE; first query restores the shared committed overlays and saved depth.
Tests cover reconnect after commit, rollback and uncommitted disconnect for both
protocols. A pending overlay never becomes committed just because end ran.
Creator-session login remains rejected; identity/verifier derivation is unchanged.

## 9. Autocommit behavior

IDLE successful DML still calls existing promotion immediately; explicit BEGIN is
not required. A later rollback cannot undo a preceding autocommit mutation.
Explicit transaction DML changes working state only until commit. Normal reads
outside transactions refresh from the latest shared committed revision. No new
Redis schema, service, persistence backend, or dependency was introduced.

## 10. Unsupported/deferred semantics

- Synthetic savepoints: **DEFERRED**, not equivalent to whole-transaction rollback.
- General observed-fact/world commitment ledger and contradiction checking:
  **NOT IMPLEMENTED**; no adaptive/AI/learning behavior enabled.
- Atomic evidence delivery/outbox: **DEFERRED**; publication hooks unchanged.
- Broad crash/concurrency guarantees, Redis fencing, lease expiry and disk recovery:
  **PARTIAL / NOT VERIFIED**; existing lock, pipeline and TTL policy unchanged.
- PostgreSQL ordinary local-error abort parity, unrecognized native transaction
  spellings and early virtual validation-error state remain **DEFERRED**.
- Registry serialization vs event delivery and backend commit vs failed overlay
  finalization remain separate failure boundaries.

## 11. Tests and executed commands

| Test file/symbols | Transitions/invariants |
| --- | --- |
| `deception_engine/test_principal_state.py::TransactionContextTests` (5 tests) | Initial/legacy shape; I/T/E; repeated begin; commit/rollback/failed commit order; stale revision; promotion failure |
| Same file `PrincipalLifecycleTests` (6 tests, both protocols) | Pending vs committed; explicit commit/rollback/autocommit; empty/idle/double finalization; actual end route + reconnect; PG abort vs MySQL error; immediate permissions/depth; stale commit |
| `test_principal_registry.py::test_creator_session_cannot_be_reused_for_either_protocol` (new) | Reject creator-session proof without principal/counter/binding mutation |
| Existing `test_principal_registry.py`, `test_phase_b_invariants.py`, `test_stateful_crud.py` | Auth/identity/tombstone, pending expiry, missing overlays, depth, session-local CRUD regressions |
| `pgproxy/internal/protocol/transaction_test.go::TestMixedTransactionFinalizationFollowsBackendOutcome` | COMMIT/END receiving ROLLBACK; normal COMMIT/ROLLBACK; unchanged backend status and correct overlay action |
| Both proxy `internal/protocol/principal_lifecycle_test.go::TestPrincipalRunDisconnectCleanup` | Real Run -> auth/query -> explicit end/EOF; failed-auth cleanup; same binding ID; no backend synthetic traffic |

Final local Python command (PowerShell, from `deception_engine/`):

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_principal_state.py test_principal_registry.py test_phase_b_invariants.py test_stateful_crud.py
```

**PASS: 41 tests, 13.65 seconds.** Existing requirements were installed only into
ignored `.runtime/pass2-tooling` with the same interpreter:
`-m pip install --target .runtime/pass2-tooling -r deception_engine/requirements.txt --disable-pip-version-check --quiet`
(from repository root). No requirement file was changed.

From each of `pgproxy/` and `mysqlproxy/`:

```powershell
go test ./internal/protocol ./internal/principal -count=1 -timeout 45s
```

**PASS: all four relevant packages.** New test subsets also passed with
`-run '^TestPrincipalRunDisconnectCleanup$' -count=1 -timeout 25s` in both proxies,
and `-run '^TestMixedTransactionFinalizationFollowsBackendOutcome$' -count=1`
in PostgreSQL. The latter initially failed two subcases before the fix.

Earlier container runs used this prefix and listed targets below:

```powershell
docker run --rm --network none --read-only --tmpfs /tmp --mount 'type=bind,source=F:\b\Capstone-main\deception_engine,target=/work,readonly' --workdir /work --env PYTHONDONTWRITEBYTECODE=1 --entrypoint python capstone-main-deception-engine:latest -m pytest -q -p no:cacheprovider
```

- Pre-edit `test_principal_registry.py test_phase_b_invariants.py`: 24 PASS.
- Initial `test_principal_state.py` before two additional parity tests: 9 PASS.
- Post-edit `test_principal_registry.py test_phase_b_invariants.py test_stateful_crud.py`:
  30 PASS.
- Initial container attempt without tmpfs failed pytest setup because the read-only
  filesystem had no temporary directory; adding tmpfs fixed the harness.
- Docker later lost its engine pipe; final combined run used local dependencies.
  Initial Go cache access failures required rerunning with approved cache access.
  These environment failures are not hidden as test passes.

No full test campaign, live SQL/native smoke, service startup, image rebuild,
configuration changes, runtime health assertion, Git staging or commit occurred.

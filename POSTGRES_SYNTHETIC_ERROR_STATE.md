# Pass 3 — PostgreSQL Synthetic Error and Abort-State Consistency

2026-10-28. **IMPLEMENTED / VERIFIED BY FOCUSED TESTS** for the supported bounded
statement paths. Physical PostgreSQL/Redis integration and runtime health are
**NOT VERIFIED** in this pass. No stack startup, rebuild, restart or Git mutation.

## 1. Scope and implementation boundary

Branch `feature/config-observability`, HEAD `ea364d1`, unchanged. Starting tree
contained the twelve unstaged/untracked Pass 1/2 paths; all were preserved.

Pass 3 changes:

- `pgproxy/internal/protocol/handler.go`: `markSyntheticTransactionFailed` (new),
  `sendPostgresDeceptionError`, `proxyLoop`, `drainBackendResponses`; one transient
  `syntheticTxFailed` cause marker distinguishes local abort from native failure.
- `pgproxy/internal/protocol/principal.go::principalQuery`: sends existing named
  transaction-state values on the trusted private principal request boundary.
- `pgproxy/internal/protocol/principal_auth.go::rejectPrincipalExtended`: uses the
  centralized local error transition. Authentication functions are unchanged.
- `deception_engine/principal_runtime.py::query`: existing Pass 2 context handles
  early SQL validation failure, quota/decision HTTP failure and proxy abort hints.
- New `deception_engine/test_postgres_error_state.py`, new
  `pgproxy/internal/protocol/synthetic_error_state_test.go`; strengthened existing
  `pgproxy/internal/protocol/principal_lifecycle_test.go` with FAILED -> EOF.
- Documentation: this file, AGENTS.md, dated notes in the two previous reports.

Inspected existing Pass 2 `PrincipalTransactionContext.record_query_failure`,
`commit`, `rollback`; both principal query/loop/status boundaries; native
ReadyForQuery and CommandComplete processing; API `_syntax_error`, `_column_error`,
`_relation_error`, `_table_access_error`; `ShapeContext.BlockResponse`; existing
transaction/cleanup tests. No new owner or competing lifecycle was introduced.

## 2. Actual PostgreSQL transaction-state model

| Client-visible state | Ordinary/seeded mixed session | Virtual principal |
| --- | --- | --- |
| IDLE / I | Latest native ReadyForQuery I; local SQL error leaves I | Binding inactive; statement error does not activate FAILED |
| ACTIVE / T | Native BEGIN/ReadyForQuery T; successful fake statement remains T | Pass 2 context active; fake DML stages working overlays |
| FAILED / E | Native ReadyForQuery E, or local statement error while T | Pass 2 context failed; non-finalizing queries rejected with 25P02 |

PostgreSQL defines I/T/E and E's reject-until-end behavior in its
[ReadyForQuery message format](https://www.postgresql.org/docs/16/protocol-message-formats.html).
Extended error cycles discard commands until Sync, as described in
[protocol message flow](https://www.postgresql.org/docs/16/protocol-flow.html).
This pass implements those constraints for the existing virtualized subset;
it does not claim complete PostgreSQL emulation.

**Important distinction:** ordinary sessions have a native backend; virtual
principals have no backend SQL execution after authentication routing. A backend
error cannot mutate a virtual principal's Redis binding because those are separate
paths, not two copies of the same database transaction. Ordinary overlays remain
session-only; only the existing principal path promotes durable principal data.

## 3. Synthetic error inventory and corrections

Before this pass, ordinary local SQL errors emitted a valid ErrorResponse followed
by ReadyForQuery T during an active transaction. Virtual normal operation failures
already marked FAILED, but early SQL validation raised before that update. Proxy
extended rejection marked only its local status, leaving registry state healthy.

| Implemented error / source | Inside ACTIVE after Pass 3 | Outside transaction / evidence |
| --- | --- | --- |
| Bounded syntax or malformed managed SQL, `api._syntax_error` / 42601 | ABORTS TRANSACTION | Remains I; engine error matrix and proxy block test |
| Unknown managed column, `api._column_error` / 42703 | ABORTS TRANSACTION | Remains I; principal error matrix |
| Unexposed/unauthorized fake relation, `api._relation_error` / 42P01 | ABORTS TRANSACTION | Remains I; principal error matrix; ordinary mode-block/fallback use same error sender |
| Registry permission/unsupported verb, `query` / 42501; unknown virtual table passthrough rejected as 0A000 | ABORTS TRANSACTION | Remains I; principal error matrix |
| Proxy shaper rejection, `BlockResponse` / 42501 | ABORTS TRANSACTION | No active transaction is invented; active simple/extended tests |
| Reserved account/operation failure sent by `servePrincipalQuery`, including private-service error 58000 | ABORTS TRANSACTION at proxy | Active service-error propagation test; native/virtual auth is unchanged |
| Rejected extended virtual/account SQL, `rejectPrincipalExtended` / 0A000 | ABORTS TRANSACTION at proxy; reconciles registry before next query/finalizer | Existing protocol error sender, new Sync/COMMIT propagation test |
| Early principal SQL budget/empty/multi-statement/comment validation / 42601 | ABORTS TRANSACTION through Pass 2 context | Remains I; new multi-statement idle/active/reconnect tests |
| Principal overlay size quota / 54000 | ABORTS TRANSACTION through context before raising | New active size-limit/retry test; no mutation is promoted |
| Decision HTTPException during active principal query (e.g. admission rejection) | ABORTS TRANSACTION while Redis is writable | New HTTPException test; router retains bounded service-error handling |
| Unwritable Redis, deadline expiry, generic transport/process failure | NOT VERIFIED as an immediately durable FAILED write | Proxy visible E plus next-request reconciliation prevents a later healthy promotion on the tested service-recovery path; crash/partial-write windows remain separate |

SQL error classes are not assigned a new taxonomy: ordinary error senders share
one transition helper. Principal transitions use the existing
`PrincipalTransactionContext.record_query_failure`, which aborts only active
PostgreSQL transactions. The private request's `transaction_state` is protected by
the existing trusted proxy boundary. It does not alter login authentication or
permit an attacker to set another session's state.

Only statement-error state is corrected; error codes/messages and successful row
contents remain unchanged. Early PostgreSQL validation failures now also return
the correct `tx_status`; MySQL's prior validation exception behavior is preserved.

## 4. Backend error behavior

`drainBackendResponses` reads native ErrorResponse and records failed outcome/code;
ReadyForQuery supplies authoritative native I/T/E. `CommandComplete` supplies the
transaction completion action retained from Pass 2. Native failure followed by a
synthetic simple query uses the existing 25P02 rejection path. Native COMMIT after
native E follows the backend's ROLLBACK completion and restores the fake overlay.

No fake copy of native rows, backend snapshot or distributed transaction manager
was added. No backend SQL is injected just to manufacture a native error state.

## 5. Mixed transaction sequence results

| Sequence | Tested result |
| --- | --- |
| BEGIN -> fake success/mutation -> COMMIT | T -> T -> COMMIT/I; healthy overlay retained |
| BEGIN -> fake error -> ROLLBACK | E -> ROLLBACK/I; failure cleared |
| BEGIN -> native write + fake mutation -> fake error -> COMMIT | Native ROLLBACK is requested; actual ROLLBACK tag/I finalizes overlay as rollback; native and fake pending changes discarded in fixture |
| Same sequence -> explicit ROLLBACK | Both pending states discarded; fresh BEGIN works |
| Fake error -> another fake query | 25P02/E; no successful response or promotion |
| Fake error -> backend-routed SELECT | 25P02/E locally; no healthy SQL escapes to backend |
| Fake mutation -> native error -> fake query -> COMMIT | Native E blocks fake query; native ROLLBACK completion restores overlay |
| Fake error -> Parse/Bind/Execute -> Sync | Error then discard through Sync; ReadyForQuery E, not healthy backend T |

The local cause marker matters: the native backend did not execute the rejected
synthetic statement and can still be physically T while the client correctly sees
E. The proxy gates further SQL until a supported full transaction end. It does not
pretend the backend itself sent E. A client COMMIT/END is sent to the native backend
as ROLLBACK in this situation; the native rollback response is relayed unchanged.
After native ReadyForQuery I, local failure is cleared. For a native-origin E,
existing backend processing remains authoritative.

Recognized whole-transaction spellings remain the existing bare COMMIT/END and
ROLLBACK/ABORT classifier. No savepoint or new transaction grammar was added.

## 6. COMMIT after error

- Virtual: failed context's existing `commit` restores committed state and returns
  ROLLBACK/I; no persistent overlay/revision promotion.
- Ordinary local error: backend receives ROLLBACK rather than committing physical
  pending writes it has not itself marked aborted. Pass 2 completion-tag handling
  then selects `/transaction/rollback` for the dirty fake overlay.
- Ordinary native error: original COMMIT reaches native E, whose ROLLBACK tag drives
  the same finalization. The prior Pass 2 correction is retained and tested.
- Private proxy-local virtual error: the next principal request includes client
  failed state. Under the existing lock, engine marks FAILED before executing
  even a COMMIT. This reconciliation is lazy (next request), not an added RPC on
  each local error. No query can promote through the tested path before it.

## 7. ROLLBACK and clean recovery

Whole rollback discards transaction pending state, restores the committed principal
overlay, clears binding failed/active state and pending key inventory, and returns
I. Tests verify unchanged committed data/revision, deletion of snapshot keys, and
a new BEGIN/query/rollback cycle. Permissions and observed depth retain Pass 2
semantics; neither is rolled back as a row mutation.

## 8. Disconnect and reconnect

Principal FAILED -> EOF reaches actual `Handler.Run` deferred `/principals/end`
without a commit request. Python tests call the actual end route after failure,
verify pending/binding cleanup and authenticate a new session; committed rows are
unchanged and new binding is not FAILED. Ordinary sockets remain owned/closed by
the manager, so disconnect cannot issue an auto-commit; its transient cause marker
belongs to that handler only. Notification-loss/kill/Redis recovery are not proven
by these fixture tests.

## 9. MySQL non-equivalence

No MySQL production file changed. Normal MySQL statement errors still leave an
explicit virtual transaction active; bounded malformed SQL retains its prior
PrincipalError behavior. A PostgreSQL failure hint is ignored for MySQL. Existing
Pass 2 lifecycle parity tests and both relevant MySQL packages pass; no PostgreSQL
abort rule was applied to MySQL.

## 10. Unsupported and deferred behavior

- Synthetic savepoints: DEFERRED. Native-only savepoint handling was not rewritten;
  a local synthetic abort requires a supported full transaction end. Whole rollback
  is not claimed to implement rollback-to-savepoint.
- Broader PostgreSQL emulation, arbitrary multi-statement/extended SQL, alternative
  end spellings and extended backend outcome correlation remain outside this pass.
- General world commitment/observed-fact ledger, adaptive selection and learning:
  NOT IMPLEMENTED; no feature activation.
- Atomic evidence/outbox and broad concurrency/crash/fencing guarantees: DEFERRED.
- Evidence keeps existing outcome fields and original submitted SQL. A COMMIT that
  resolves as ROLLBACK is not a new evidence-schema event; downstream SQL-text-only
  projections can still miss that distinction. Publication/schema redesign deferred.
- Immediate registry state can lag a proxy-local error until the next private
  request. Failure to persist or deliver that reconciliation is not certified by
  fixture tests; the proxy retains E on failed private calls and does not fall back
  to physical SQL for virtual principals.
- Live physical SQL/Redis fault injection, crash and full runtime health NOT VERIFIED.

## 11. Focused verification evidence

New Python `test_postgres_error_state.py`:

- `test_postgres_statement_error_state`: six actual error paths, idle/active.
- `test_pending_failure_finalization_and_fresh_session`: existing and early errors
  crossed with commit, rollback, disconnect; pending/committed keys and fresh login.
- `test_proxy_observed_failure_prevents_principal_commit`: private failed hint.
- `test_mysql_malformed_statement_preserves_existing_active_state`: compatibility.
- `test_postgres_decision_http_failure_marks_existing_transaction_failed`.
- `test_postgres_overlay_limit_failure_cannot_be_retried_as_commit`.

New Go `synthetic_error_state_test.go` exercises actual loops with existing
net.Pipe/httptest techniques: idle error, healthy mixed commit, failed commit and
rollback, native-error -> synthetic rejection, synthetic-error -> backend rejection,
policy abort, policy/failed extended Sync recovery, and proxy-local principal abort
propagation (extended rejection/service error). Extended-cycle tests assert wire
message ordering; query tests assert emitted outcome transaction state as well as
wire status/code/tag. Engine/native stores are distinct deterministic test doubles.
`principal_lifecycle_test.go` additionally covers actual Run FAILED -> EOF routing.

Before correction: initial Python matrix **6 FAIL / 14 PASS**; ordinary proxy matrix
failed its two synthetic-error cases and policy-abort case (wire T instead of E).
A separate extended policy regression failed on a duplicate ErrorResponse before
Sync. Those failures are resolved; none were weakened or marked xfail.

Commands actually run (PowerShell; Python working directory `deception_engine`):

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_postgres_error_state.py
```

Final focused result: **22 PASS, 3.06s**. With existing principal/lifecycle/expiry
coverage, the same command using these targets:

```text
test_postgres_error_state.py test_principal_state.py test_principal_registry.py test_phase_b_invariants.py
```

**58 PASS, 12.90s.** Existing ignored local dependencies were reused; no installation
or new dependency/config artifact was needed in Pass 3.

From `pgproxy`:

```powershell
go test ./internal/protocol -run 'TestSynthetic|TestPolicy|TestBackendErrorBlocksSynthetic|TestPrincipalProxyLocalAbort|TestPrincipalRunDisconnectCleanup' -count=1 -timeout 30s
go test ./internal/protocol ./internal/principal -count=1 -timeout 45s
```

Both PASS. From `mysqlproxy`, the second command also PASS (both packages).
Earlier narrowed Go selections and pre-fix failure commands used the corresponding
test names; initial sandbox Go cache denial was resolved with approved cache access.
`git diff --check` and gofmt checks pass. No full-suite, live stack, deployment,
auth/credential/config mutation, Git staging/commit or Pass 4 implementation.

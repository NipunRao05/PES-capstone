# Deterministic database honeypot baseline contract

Phase A source audit: 2026-10-26. Repository: `NipunRao05/PES-capstone`, branch
`feature/config-observability`, inspected HEAD `0e0dd66`.

This describes the current implementation and the intended acceptance boundaries.
**Observed source behavior is not a new runtime pass.** Historical evidence and
its limitations are in [VERIFIED_TESTS.md](VERIFIED_TESTS.md); unresolved differences
from the intended contract are in [STATIC_BASELINE_PROGRESS.md](STATIC_BASELINE_PROGRESS.md).
Phase B update (2026-10-26): ordinary MySQL transaction coordination/status and
principal working-state expiry handling were corrected. Focused evidence is in
VERIFIED_TESTS.md. Phase B remains open for ordinary expiry and reset/timeout
invariants; this is not a release-candidate acceptance record.

## System identity and supported components

The baseline is a local, deterministic, stateful PostgreSQL/MySQL honeypot. It
combines controlled physical databases with bounded synthetic SQL responses and
persistent deceptive identities. It is not a complete database emulator.

`deterministic_rule_based` is the only supported configuration mode. Retained
components are `pgproxy`, `mysqlproxy`, `deception_engine`, its schema/generator/
policy/strategy modules, Redis-backed deceptive principals, `session_module`,
Evidence Store, Redpanda, and the existing observability stack. Canonical settings
are `config/features.yaml`, `config/deception.yaml`, and `config/observability.yaml`;
the launcher is `scripts/honeypot.py`. Secrets remain in private deployment inputs.

Scaling and sandbox replay remain enabled in the inspected canonical defaults.
Phase A does not activate, remove, redesign, or certify them. Retaining the
`redis-mitre` service name does not enable MITRE: Evidence Store also uses it.
Future feature activation is rejected by the canonical configuration loader.

## Authority and ownership

| State | Owner and storage | Boundary |
| --- | --- | --- |
| Physical database/backend state | PostgreSQL and MySQL; named `pgdata` and `mysqldata` volumes | Native SQL engines decide physical SQL outcomes, transactions, constraints and physical permissions. |
| Synthetic/deceptive state | Deception Engine, YAML schemas, deterministic generator, `MutationStore` and `ExposureTracker`; `redis-deception` | Synthetic rows, exposure and bounded overlays are not physical tables or backend writes. Ordinary sessions use session-scoped seeds/keys. |
| Connection/authentication state | Each proxy's connection/session and protocol handlers | Owns wire authentication, current connection, backend transaction status and protocol responses. |
| Behavior/session projection | `session_module/authoritative_state.py::AuthoritativeStateStore` | Bounded in-memory projection from events; verified successful backend outcomes change physical-object projections. It is not the SQL database authority or a durable world ledger. |
| Persistent principal state | `deception_engine/principal_registry.py` and `principal_runtime.py`; `redis-deception` | HMAC-derived identity scoped by protocol and reserved username; verifiers, enabled flag, permissions, persistent mutations, exposure depth and revision. |
| Evidence/history | Redpanda transport; `evidence_store/main.py::EvidenceRepository` in `redis-mitre` | Correlated, sanitized, bounded historical records. Evidence and aggregate metrics do not grant query authority. |

Principal identities use reserved `fake_` names. PostgreSQL authenticates them
with SCRAM-SHA-256; MySQL uses mysql_native_password. Their SQL stays on the
synthetic route. Supported account creation/grant/password/disable/drop statements
are restricted to the seeded administrator and bounded grammar; physical account
creation is not an allowed substitute. Drop/disable retains the registry identity
as a disabled record; a dropped name is not automatically reusable.

The registry uses per-principal locks, session bindings, revision checks and
atomic Redis writes. Principal state promotion precedes a successful response.
The stable HMAC, schema/generator inputs and retained volumes are prerequisites
for identity/content continuity. Never rotate or reset them as a recovery shortcut.

## Query behavior

These are documentation categories, not new response enum values. Existing
decision responses use `fake`, `passthrough` and `block`; events use bounded
authorities such as `backend`, `deception` and `policy`.

| Category | Current examples | Limits |
| --- | --- | --- |
| SYNTHETIC | Exposed configured tables; selected metadata/catalog discovery; simple projections; unfiltered COUNT; numeric LIMIT/OFFSET; bounded ID-predicate CRUD | Rows are generated and overlaid within the existing grammar. Unsupported expressions must not be treated as fully executed SQL. |
| BACKEND_PASSTHROUGH | Ordinary authenticated sessions querying unmanaged physical tables; allowed physical DDL/CRUD and native transactions | Controlled backend remains authoritative. This category never authorizes a virtual principal to fall through to a backend. |
| SIMULATED | Fixed server/system-variable replies, selected catalog replies, virtual account permissions and virtual transaction acknowledgments; generated INSERT row values | A successful simulated account statement creates no physical user. `_fake_insert_row` does not preserve literal INSERT VALUES; transaction tests cover the generated overlay's lifetime, not full INSERT semantics. |
| REJECTED_WITH_NATIVE_ERROR | Hidden traps, restricted account statements, unknown managed columns, unsupported managed predicates/ORDER BY, unsupported virtual commands | PostgreSQL SQLSTATE/ErrorResponse or MySQL ERR response. Exact support must be established operation by operation. |

Ordinary PostgreSQL **simple Query** and MySQL **COM_QUERY** consult `/decide`.
Ordinary PostgreSQL Parse/Bind/Execute and MySQL COM_STMT_PREPARE/EXECUTE follow
backend paths instead; they do not implement equivalent synthetic results.
Account statements on prepared paths are rejected. Virtual PostgreSQL sessions
reject extended queries and recover through Sync; virtual MySQL sessions support
text queries, ping and quit, rejecting other commands. This distinction is a
known consistency gap for ordinary sessions accessing synthetic assets.

Managed UPDATE/DELETE require a supported positive-integer `id` predicate;
INSERT uses a limited explicit-column VALUES form. Managed ORDER BY is rejected.
General JOINs, expressions, subqueries, bulk mutations and arbitrary metadata SQL
are not certified. In particular, `_handle_count` computes base count plus overlay
delta without applying an accepted ID filter: filtered COUNT is a known gap, not
supported semantics. Phase D must define/reject unsupported grammar consistently.

Exposure normally advances from depth 1 toward 3 after authorized table access;
unseen traps are hidden. Ordinary sessions have four-hour Redis key expiry and
cleanup on disconnect. Principal exposure is retained as a maximum in the durable
record. Expiry and Redis failures can reset ordinary observed state; continuity
across those cases is not yet guaranteed.

## Persistence boundaries

| Boundary | Physical backend | Ordinary synthetic state | Virtual-principal state | Session projection / evidence |
| --- | --- | --- | --- | --- |
| Next query | Native visibility rules | Same session's deterministic rows and overlays while keys exist | Same principal's committed state; transaction-local working overlay | Projection arrives asynchronously; evidence arrives asynchronously. |
| Transaction | Native commit/rollback rules | Both proxies invoke the existing snapshot/finalize API for bounded text transactions. MySQL now sends transaction context, finalizes after native success and before forwarding OK, and reports synthetic transaction/autocommit flags. See limits below. | BEGIN/COMMIT/ROLLBACK; promotion on successful commit/autocommit mutation; revision conflicts reject commit; missing expected working state invalidates the binding instead of promoting partial state | Projection tracks verified outcomes; evidence retains transaction history rather than rolling it back. |
| Same session | Backend connection rules | Session seed, exposure and overlays; bounded TTL | Active binding plus principal identity | Projection is bounded and may be evicted; evidence is retained within limits. |
| Disconnect/new session | Committed physical changes persist; native open transaction rolls back | Cleanup discards overlays/exposure; new session seed need not reproduce the old world | Committed overlays/permissions/exposure persist; uncommitted working overlays are not promoted | Connection state ends; stored history remains subject to TTL/caps. |
| Container restart | DB volume preserves committed data under engine durability rules | Engine-only restart can recover existing Redis keys, subject to TTL; proxy restart closes connections | Registry survives Deception Engine restart using Redis; reconnect creates a fresh binding | Session Module restart loses its in-memory projection. Evidence service restart uses Redis/Kafka, subject to delivery gaps. |
| Full stack restart with volumes retained | Expected durable native state; not newly tested here | No promise to retain an ordinary socket session or its transient world | Intended committed continuity with stable HMAC/schema/generator and `redisdeception` AOF volume; full-stack coverage not established | Projection is not durable. Evidence persistence depends on Redis durability, retention and Kafka offsets; full-stack/crash recovery not certified. |

`redis-deception` is configured with AOF and `appendfsync always`. Principal
records have no ordinary session TTL; bindings and working overlays expire.
Evidence defaults to a 30-day TTL with bounded per-session collections (including
500 query and 100 stage events). The evidence Redis has a named volume but no
explicit AOF configuration in the Compose template. A named volume alone does
not establish lossless crash recovery. These are configured properties, not
fresh restart-test results.

## Failure behavior: required boundary versus inspected implementation

| Failure | Required acceptance behavior | Current implementation / limitation |
| --- | --- | --- |
| Deception Engine unavailable | Unmanaged backend SQL may continue safely. Established synthetic objects must receive a bounded temporary/native failure, without changing authority or disappearing. | Ordinary decision transport/status/decode failures can fall through to backend; recognized traps receive missing-table errors even if previously observed. Virtual principal calls block with account-service errors and never use backend fallback. A-M3 remains open. |
| Redis deception unavailable or keys expired | Do not acknowledge lost writes or silently reset established synthetic facts. | Ordinary mutation helpers swallow several Redis failures; reads may return base rows/count delta zero. Exposure reads return depth 1 on errors. Principal mutation helpers rethrow, and registry failures block, but no outage matrix was run. |
| Redpanda unavailable | SQL authority stays deterministic; telemetry loss must be visible and must not be presented as complete research history. | Publishers buffer asynchronously, retry, then drop batches; buffers may overflow. No lossless delivery guarantee. |
| Evidence Store / evidence Redis unavailable | Query execution must not depend on history availability; ingestion failures must have an explicit recovery/loss policy. | Consumer retries connections, but per-event ingest failures are caught while Kafka auto-commit remains enabled. Failed records can be skipped durably. TTL/caps also limit history. |
| Backend DB unavailable | Native error/connection failure; never fabricate physical success or redirect unmanaged writes into fake state. | Ordinary backend dialing/forwarding fails. Initial virtual authentication also traverses backend connection/greeting setup, so backend-independent virtual availability is not promised. |

`config/deception.yaml: decision.fail_open` maps specifically to
`DECIDE_RATE_LIMIT_FAIL_OPEN`, the Redis **rate-limiter** failure behavior. It is
not a global switch for proxy transport fallback or synthetic-state durability.
Changing that flag alone would not fix A-M3. Neither Phase A nor the bounded
Phase B correction changes that global fallback policy.

## Explicit state transitions and invariants — Phase B

These names explain existing handler/store states; they are not a new service,
framework or wire protocol. Read the evidence limits beside each invariant.

| Area | Transitions / invariant | Owner and evidence |
| --- | --- | --- |
| Connection/auth/session | CONNECTED -> AUTHENTICATING -> AUTHENTICATED -> READY -> CLOSED. Rejection/disconnect during authentication never reaches READY or emits a successful session start. Quit, EOF and configured idle timeout run deferred cleanup. | Existing proxy `Run`/connection managers. MySQL socket fixture covers success, rejected/unknown login, auth disconnect, quit, abrupt EOF and idle expiry; original PG code remains unchanged and selected existing checks pass. PostgreSQL command idle timeout is still an open source finding. |
| Ordinary transaction | Native BEGIN/status enters transaction. Synthetic writes snapshot session overlays; COMMIT retains them and ROLLBACK restores prior rows. Failed native commit does not finalize. | PostgreSQL existing flow; MySQL new `transaction.go` uses backend OK/status as boundary evidence. Engine tests cover generated INSERT, UPDATE, DELETE, rollback, commit, subsequent transaction and cross-session cleanup. No new live physical SQL pass. |
| Virtual transaction | READY -> IN_TRANSACTION -> COMMIT/ROLLBACK -> READY. PostgreSQL statement failure -> FAILED_TRANSACTION until rollback/commit-as-rollback. MySQL statement rejection does not automatically adopt PostgreSQL abort semantics. | `principal_runtime.query`; scoped tests cover normal persistence, conflict rejection, PG abort/rollback and both protocols' missing-overlay guard. |
| Principal lifecycle | NON_EXISTENT -> CREATED/ENABLED -> REUSED_IN_LATER_SESSION -> DISABLED. Stable protocol/name identity; disabled identities reject authentication and existing-session queries; tombstones prohibit duplicate recreation. | Existing registry/HMAC/native verifier code unchanged. Focused registry tests plus expiry/disable tests; historical native-wire evidence remains historical. |
| Exposure | Authorized access increases depth toward 3. Hidden access cannot advance depth. SQL rollback does not erase observations; principal reconnect restores maximum observed depth. | Existing ExposureTracker and principal record. Focused tests pass within the live-key lifetime. Ordinary expired-key continuity is not guaranteed (B-OPEN1). |
| Disconnect/cleanup | Session cleanup removes working overlays/snapshots/exposure without deleting another session's state or durable committed principal record. Reauthentication uses committed state, never an abandoned transaction. | Existing cleanup endpoints; new isolation/idempotency fixture plus historical/selected principal tests. Abrupt process loss is not equivalent to graceful disconnect and was not tested. |
| Expired principal binding | Missing binding rejects queries. Missing expected overlay during an active transaction invalidates the binding before state promotion. Reconnect restores committed state. | New expected-key list stored in the existing binding; working-key/snapshot/exposure TTLs refresh with that binding. No verifier or principal identity change. |

### MySQL correction boundary

The ordinary command loop tracks dirty **synthetic** transaction state separately
from the backend's `InTransaction` and `AutoCommit` flags. With autocommit disabled,
a synthetic write requires a snapshot even if no physical-table access has yet
set MySQL's IN_TRANS bit. Synthetic responses and outcome events reflect the
open synthetic transaction; the proxy does not invent physical SQL success.

After successful text COMMIT/ROLLBACK (including WORK/CHAIN/RELEASE forms), the
proxy calls the existing engine transaction endpoint before forwarding backend
OK. Successful BEGIN/START TRANSACTION finalizes an earlier overlay as commit,
matching the native fresh-transaction boundary. Observed successful native
transaction exit/autocommit enablement also commits the pending overlay. Native
packets are otherwise forwarded unchanged. No dirty overlay means no finalization
call. The virtual-principal loop retains its own transaction path.

An engine finalization failure returns an error from the ordinary loop and the
connection manager closes the connection; backend OK is withheld. A physical
commit may already have happened. This is not a distributed atomic transaction
between SQL and Redis. Savepoints, arbitrary multi-statements, prepared transaction
commands, implicit commits reported through errors and all native implicit-commit
variants are not certified by these focused checks.

### Principal expiry compatibility and remaining limits

The binding's `mutation_keys` records working keys that must remain present while
its transaction is active. Missing state or a legacy active-transaction binding
without this manifest is invalidated with a native account/session error; the
client must reconnect. Durable committed overlays remain untouched. A normal
binding created by the updated handler gains the manifest on BEGIN. Normal
principal authentication, permissions, content generation and transaction results
are preserved by the focused tests.

This guard does not repair ordinary session TTL expiry. It is not a general Redis
outage/eviction recovery system or an exactly-once commit protocol. Ordinary
MySQL COM_INIT_DB error handling, reset/change-user synthetic cleanup and
PostgreSQL command idle expiry remain the open Phase B items in the progress file.
Passing initial login/quit tests must not be presented as coverage of those paths.

## Explicit unsupported guarantees and deferred work

- Full PostgreSQL/MySQL SQL or wire-protocol compatibility; synthetic prepared
  statements, arbitrary transaction/isolation/savepoint semantics or general DDL.
- Persistent ordinary-session synthetic worlds across reconnects, or durable
  Session Module projections across process restarts.
- Exactly-once, complete or indefinitely retained evidence; crash-proof research
  recovery; load/soak performance; public deployment or Linux/Azure rehearsal.
- AI/LLM generation, MITRE runtime, steering, interventions, live learning,
  bandits, adaptive experiments, self-evolution, Kubernetes/KEDA, cloud resources,
  fictional-company sites and final realistic dataset generation.

Existing tests establish only their covered cases. This contract does not certify
a local release candidate. Update it when an intentionally approved behavior
change resolves a listed gap; preserve the evidence trail.

# Pass 1 — State / World Consistency Audit

> Subsequent Pass 4 progress — 2026-10-28: bounded principal observation facts
> now persist in optional principal JSON `world_commitments`, acknowledged after
> successful proxy writes for simple known-table reads. First values/provenance
> survive reconnect and rollback; internal conflicts retain the original fact.
> See `WORLD_COMMITMENT_MODEL.md`: 82 focused Python cases and four Go packages
> PASS. Coverage is partial; socket/storage atomicity, broader crash/concurrency
> and runtime health remain NOT VERIFIED. Original audit is retained below.

> Subsequent Pass 3 update — 2026-10-28: the bounded PostgreSQL synthetic-error
> gaps below now have focused corrections and tests in
> `POSTGRES_SYNTHETIC_ERROR_STATE.md`. The general fact/commitment, savepoint,
> evidence-atomicity and crash/concurrency gaps remain deferred. Original Pass 1
> findings and scope are retained as history.

Date: 2026-10-28. Scope: repository inspection only; no runtime implementation,
test execution, service changes, Git mutations, or Pass 2 implementation.

> Subsequent Pass 2 update — 2026-10-28: this audit is preserved as the Pass 1
> record. `PRINCIPAL_TRANSACTION_LIFECYCLE.md` now records the implemented binding
> lifecycle, focused test results and narrow PostgreSQL correction. The COMMIT/END
> receiving backend ROLLBACK finding below was reproduced by a failing protocol
> test and corrected; no general savepoint/observation/evidence/crash guarantees
> were added. Pass 1's proposed scope and next action below are historical.

**Conclusion:** the deterministic platform has useful principal-scoped commitment
and transaction mechanisms, but no general committed-world/observation ledger.
It is not ready to authorize adaptive changes to previously observable facts.
“ENFORCED” below means enforced on the inspected code path, not a fresh live-test
pass. Tests listed below were read, not run. Runtime outcomes are **NOT VERIFIED**.

## 1. Git / branch / working-tree status

- Branch: `feature/config-observability`.
- HEAD: `ea364d1` (`Monday-28/10`). Initial `git status --short`: empty; clean,
  with no pre-existing uncommitted changes to classify or preserve.
- Last five commits: `ea364d1`, `0e0dd66`, `2ab1e04`, `2c95ba9`, `ed6bd56`.
- Only this report and the mandatory `AGENTS.md` handoff are changed by this pass.
- Historical documents describe uncommitted work at `2ab1e04`; that is historical,
  superseded by the observed HEAD and clean initial status.

The requested historical direct Compose status observation failed at interpolation:
`HONEYPOT_CONFIGURED` is required. Docker also reported denied access to its client
configuration. This establishes neither healthy nor unhealthy containers. The
guard is intentional (`docker-compose.yml`, `name`; `scripts/honeypot.py`, launcher).
No startup/restart or attempt to bypass that guard was made.

## 2. Current configuration baseline

`config/features.yaml` selects `deterministic_rule_based`. Both proxies, Deception
Engine, session/behavior, evidence, deceptive principals, scaling, replay and all
four observability switches are enabled. MITRE, live learning, dynamic steering,
intervention, generative AI and local LLM are disabled.

`scripts/configuration.py::FEATURES`, `DEPENDENCIES`, `render` supply the executable
feature model and deployment gating: adaptation and experiments are forced off,
the adaptation endpoint is emptied, operator mode is `SAFE_MODE`, and unsupported
future activation is rejected by validation. `config/deception.yaml` configures a
10-second analysis inactivity timeout, 1,000 active analysis sessions, a 10,000-event
queue and best-effort decision rate limiting. These are not TCP connection lifetimes.
Private `.env` inspection was limited to relevant compatibility flags; no secret
values were output. Its explicit MITRE flag is false and Compose profiles empty.

Configured baseline is confirmed by source; actual running-container configuration
is **NOT VERIFIED**. An ignored generated Compose artifact is dated October 16;
its presence is not evidence that current containers match current source.

Existing strategy registry/guard/selector and learned/experiment source already
exist (`deception_engine/strategy_registry.py::StrategyRegistry`,
`policy_guard.py::PolicyGuard`, `strategy_agent.py::StrategyAgent`,
`session_module/authoritative_state.py::AuthoritativeStateStore`). Their presence
does not mean live adaptive execution is enabled. Do not create a second registry.

## 3. Authoritative state ownership map

| State | Owner and exact implementation | Storage / durable? | Creation, update and removal | Restart behavior / projections |
| --- | --- | --- | --- | --- |
| PostgreSQL TCP/authentication | `pgproxy/internal/connection/manager.go::Manager.handleConnection`; `pgproxy/internal/protocol/handler.go::Handler.handleStartup`, `relayAuthRaw`, `Run` | Go handler and `pgproxy/internal/session/session.go::Session`; transient | Manager accepts with capacity limit, dials backend; startup creates random session ID; physical auth relayed until ReadyForQuery or ErrorResponse; reserved identity goes to `principal_auth.go::authenticatePrincipal`; deferred cleanup/end on exit | Connections, prepared statements, portals, parameters and counters disappear; backend socket closes; domain events are historical copies |
| MySQL TCP/authentication | `mysqlproxy/internal/connection/manager.go::Manager.handleConnection`; `mysqlproxy/internal/protocol/handler.go::Handler.Run`, `relayServerGreeting`, `relayClientHandshake`, `relayAuthResult` | Go handler and `mysqlproxy/internal/session/session.go::Session`; transient | Backend greeting precedes client identity; session created after parsed handshake; physical auth relays plugin exchanges, virtual auth uses intercepted token; quit/EOF/error/idle exit triggers deferred end | Reconnect is new random session; prepared statements, selected DB, capability and transaction flags are lost |
| Physical SQL state and transactions | PostgreSQL/MySQL engines; proxy `handler.go::drainBackendResponses` / `drainResponse`, session status setters | Native database storage (`pgdata`, `mysqldata` volumes); durable committed data | Native SQL and native transactions own actual rows/objects/permissions; account statements are intercepted/rejected by proxy policy | DB recovery owns committed data; open socket transactions do not become committed merely because proxy state says so; session service is a projection |
| Active behavioral sessions | `session_module/session_engine.py::ActiveSession`, `SessionEngine.process_event`, `_timeout_sweeper`, `_emit_closed_session`; `storage.py::RedpandaSessionStore.save_session` | In-memory map; closed summaries in Redpanda | First mapped query/auth-failure creates entry; protocol+session ID key, legacy identity fallback; fingerprints, timing, suspicion, read/write and failed-auth counts accumulate; inactivity, capacity eviction, flush/shutdown close | No active-map reload. Summaries do not restore protocol/world state. Explicit proxy disconnect does not directly close this engine (see FSM 2) |
| Event-derived session/object state | `session_module/authoritative_state.py::AuthoritativeSessionState`, `AuthoritativeStateStore.apply_proxy_event`, `_apply_query` | Bounded memory map and transaction snapshots; not durable | Events create state; only verified successful outcomes mutate projected objects; session_end marks closed; oldest-updated eviction discards state and snapshots | No baseline replay/bootstrap reconstruction; auto-committed consumer offsets can outlive memory. Despite class name, this is not the database/principal truth owner |
| Deceptive principals | `deception_engine/principal_registry.py::PrincipalRegistry.command`, `save`, `login`, `key` | Non-expiring JSON in `redis-deception`; configured AOF volume | Seeded admin creates reserved identity with reader permission; bounded grant/password/disable/drop updates under principal lock; drop retains disabled record | Survives engine restart with stable HMAC and Redis data; evidence and proxy context are derived copies, not authorities |
| Committed principal world | `deception_engine/principal_runtime.py::query`, nested `restore`, `promote` | `persistent_mutations`, `exposure_depth`, `world_revision` inside principal JSON; durable as above | Autocommit DML or successful transaction commit promotes overlays; row rollback restores committed record; observed depth remains advanced | Returning sessions use stable principal seed and shared committed overlays. No stored complete row snapshot, general world ledger or persisted base-schema version |
| Session working mutations | `deception_engine/mutation_store.py::MutationStore.record_insert`, `record_update`, `record_delete`, `_capture_transaction_table`, `finalize_transaction`, `cleanup_session` | Redis JSON overlays and pre-transaction snapshots; four-hour TTL | Ordinary writes modify overlay immediately; first transactional table write snapshots prior overlay; commit drops snapshot, rollback restores it; end deletes all ordinary overlays | Ordinary COMMIT survives only within that session/TTL, not reconnect. Principal working copies are restored/promoted through separate runtime path |
| Synthetic base objects/rows/assets | `deception_engine/schema_loader.py::SchemaLoader._load_all`, `schema_for_database`; `generator.py::session_seed`, `DataGenerator.generate_rows`, `generate_organization_rows` | `deception_engine/schemas/hr.yaml`, `finance.yaml`, `crm.yaml`; bounded reconstructable memory cache | Startup reads schema definitions; rows generated from session or principal seed, fixed time anchor and schema; cache cleaned/evicted | Reproducible only with same generation code/dependencies/schema/seed/locale/anchor. No historical schema binding per principal; `persistent_objects`/`world_id` are initialized placeholders, not implemented object persistence |
| Exposure / discovery | `deception_engine/exposure.py::ExposureTracker`; principal runtime depth promotion; session projection `discovered_objects` | Redis depth, last table, timestamps; principal depth durable, ordinary depth TTL | Start sets depth 1; authorized SELECT can advance toward 3; cleanup deletes session depth; rollback does not erase actual exploration depth | Not a record of returned rows, existence/absence, counts, grants, foreign servers or arbitrary facts. Projection relation sets are bounded SQL-derived hints |
| Evidence | `evidence_store/main.py::EvidenceRepository.ingest_kafka`, `_append_once`, `ingest_artifact`, `_touch`; `EvidenceConsumer.run` | `redis-mitre` session hashes, bounded lists, dedup sets, indexes; 30-day refreshed TTL by default | Query outcomes, auth/lifecycle, principal creation/auth/link events and research artifacts ingested; expiry removes records | Redis volume survives process/container replacement, but default Redis persistence is weaker than deception AOF. Not used to authorize live query/auth responses |
| Scaling | `scaling_agent/internal/scaler/scaler.go::Scaler.process`, `claimEvent`, `ExportState`, `RestoreState`, `SaveNow`; `internal/state/store.go::RedisStore` | Memory + non-expiring versioned `redis-mitre` document | Scoring, cooldowns, desired target, safe/manual/autoscaling controls, bounded events and processed IDs; state saved after processing/control | Control-plane target only; no query/world rewrite. `CurrentReplicas` explicitly returns desired count, not actual infrastructure count; lost connections on physical rescheduling remain an indirect risk |
| Replay/hardening | `sandbox_replay/main.py::ReplayEngine.replay`, `_execute_postgres`, `_execute_mysql`, `verify_hardening_report`; `ReplayStore` | Replay/report Redis keys, seven-day TTL; separate sandbox DB data on tmpfs | Reads captured sanitized evidence, executes allowed reads in fresh read-only transactions then rolls back; hardening can commit sandbox-only privilege revocations | No principal/world snapshot copied, no live DB/principal mutation by replay path. Sandbox DBs reset on container restart; Redis artifacts may remain |

### Principal identity, credentials and roles

`PrincipalRegistry.key` HMACs protocol+normalized reserved username for lookup.
Creation HMACs protocol+name+initial verifier to assign stable `principal_key` and
`DP-…` identity. Password changes replace verifier and increment credential
revision without changing identity or data seed. Neither secrets nor verifier
contents belong in this report.

PostgreSQL stores SCRAM verifier components; challenge is one-use, 30 seconds,
and final proof rechecks enabled state and credential revision under lock.
MySQL stores the native-password verifier and validates a 20-byte challenge/token
pair. Both are restricted to synthetic `testdb` authentication by the proxy.
Physical seeded users authenticate with the native backend, not registry verifiers.

Creation records creator session, timestamps, default SELECT permission and reader
role. Bounded GRANT replaces the permission list and derives reader/writer role;
it is not general SQL role membership/inheritance. Login updates count, first reuse,
time-to-first-reuse, last login and last 256 linked session IDs. Aggregate created
and reused sets count distinct identities; returns counts successful logins.
Login from the creation session is explicitly rejected, not counted as reuse.
Disable/drop sets `enabled=false`; the non-expiring record blocks recreation.
There is no supported re-enable statement. Password/grant changes do not re-enable.
An existing binding is rechecked for enabled state on each query; this does not
actively close the TCP socket, and MySQL PING is handled locally.

### Redis deception inventory

| Key/model | Role and lifetime | Recovery / requirement |
| --- | --- | --- |
| `deceptive-principal:<HMAC>` | Authoritative principal, credentials, permissions and committed overlays; no TTL | Essential for auth and committed-world continuity; cannot reconstruct verifier/mutations from evidence |
| Same key + `:lock` | Redis lock, 15-second lease, two-second blocking wait (`PrincipalRegistry.lock`) | Ephemeral concurrency control; not a durable world record or fenced write |
| `deceptive-principal:challenge:<token>` | SCRAM challenge, 30 seconds, consumed with GETDEL | Transient; lost challenge requires new authentication |
| `deceptive-principal:session:<sid>` | Binding with principal key, tx/failed flags, baseline revision, expected mutation keys; four hours refreshed | Live virtual-session authority; lost binding rejects queries and requires reconnect |
| `deceptive-principal:created`, `:reused`, `:returns` | Non-expiring aggregate sets/counter | Metrics, not authentication/world authority; updated with principal/login pipeline |
| `mutation:<sid>:<table>` | Working overlay, four hours | Ordinary session truth; principal copy reconstructable from committed record outside transaction |
| `mutation-tx:<sid>` | Original overlays for rollback, four hours | Needed for ordinary rollback; not a native DB transaction or savepoint stack |
| `exposure:<sid>` | Depth/last table/timestamps, four hours refreshed on accesses | Live progressive-disclosure state; principal depth can restore it; no fact ledger |
| `rate:decide:<scope>:<identity>:<bucket>` | Expiring rate-limit counters (`api.py::_rate_limit_counter`) | Ephemeral admission policy; not committed truth |

`docker-compose.yml::redis-deception` explicitly enables AOF with
`appendfsync always` and mounts `redisdeception:/data`. Durable here means configured
Redis persistence, not proof of backup, disk failure survival, or current mount
health. Other volume-backed Redis data can physically retain ephemeral keys until
TTL; this does not make them logically permanent.

## 4. Existing implicit state machines

### FSM 1 — Connection/authentication

PostgreSQL: accept/capacity check -> backend dial -> startup parsing/session New ->
physical raw auth relay OR reserved SCRAM -> authenticated/session_start -> query
loop -> Terminate/EOF/error -> deferred engine cleanup/session_end/socket close.
Auth rejection produces auth failure where an identity/session is known. Earlier
dial/malformed-startup failures need not have a session or auth event. See ownership
paths above and `pgproxy/internal/protocol/principal_auth.go::authenticatePrincipal`,
`principalLoop`, `rejectPrincipalExtended` (discard extended messages until Sync).

MySQL: accept -> backend dial/greeting -> parsed client handshake -> session New ->
physical auth/plugin relay OR reserved native proof -> auth+session_start -> loop ->
QUIT/EOF/idle/error -> deferred cleanup/end. Virtual branch closes backend without
forwarding its username/token. `mysqlproxy/internal/protocol/principal_auth.go`
owns native virtual authentication and permits only QUERY/PING/QUIT in that loop.

Neither implementation has an explicit shared lifecycle enum. Both currently
require a successful initial backend dial even for virtual users; MySQL additionally
needs its greeting. Backend outage therefore affects virtual login availability.
MySQL command loops set a configured client idle read deadline. PostgreSQL's
inspected query loops have no equivalent idle deadline (SCRAM has an auth deadline);
TCP keepalive is not the analysis inactivity timeout.
Protocol state is transient and is not reconstructed after process restart.

### FSM 2 — Session lifecycle

There are **three different lifecycles**, not one shared FSM:

1. Proxy Session: created during authentication; active only after successful auth;
   deferred end runs on normal exits/errors after creation, including auth failure.
   Process kill can skip end notification and event emission.
2. `SessionEngine`: first mapped query/auth-failure -> active -> timeout/capacity/
   explicit helper/shutdown removal -> emitted closed summary. Production
   `redpanda_consumer.py::map_proxy_event_to_event` drops a query-less session_end;
   `event_worker` only calls `process_event`, so disconnect closure is delayed until
   inactivity (10 seconds configured), not immediately routed to `close_session`.
   Late events can recreate a previously summarized session. Capacity is analysis
   eviction, not a client disconnect. Graceful shutdown flushes; crash loses memory.
3. `AuthoritativeStateStore`: any identified event -> projection; session_end sets
   closed+expected query count; late query events can complete projected rollback
   through `_finalize_closed_if_complete`. Bounded eviction drops state. There is
   no persistent reload and no explicit CLOSING enum.

### FSM 3 — Transactions (physical, ordinary synthetic, virtual)

- Physical PostgreSQL: backend ReadyForQuery supplies `I/T/E`; backend owns BEGIN,
  commit, rollback, errors, savepoints and disconnect rollback. Proxy retains status
  in `Session.SetTxStatus`. Ordinary fake DML snapshots Redis overlay when status T.
  `drainBackendResponses` finalizes dirty overlays on recognized successful native
  transaction-ending SQL. COMMIT retains ordinary overlay; ROLLBACK restores it;
  end deletes it. `deceptionTransactionAction` recognizes only bare COMMIT/END/
  ROLLBACK/ABORT after normalization. No synthetic savepoint snapshots exist.
- Physical MySQL: `InTransaction` and `AutoCommit` follow OK/EOF status flags.
  `transaction.go::deceptionTransactionState` also treats autocommit-off or dirty
  overlay as transactional. `finalizeDeceptionTransaction` recognizes full ends,
  chain variants, new BEGIN committing old work and native implicit commits;
  requires successful final backend OK before the client receives it. ROLLBACK TO
  does not finalize the entire overlay, but no partial overlay restoration exists.
- Virtual principals: `principal_runtime.py::query` uses Redis binding `tx` and
  `failed`, maps to I/T/E, snapshots working overlays, and compares principal
  `world_revision` on COMMIT. Conflict -> `40001` / MySQL 1213 plus failed binding;
  rollback required. Successful commit promotes overlays and increments revision;
  rollback/failed commit restores committed overlays. PostgreSQL application-level
  query errors set aborted state; MySQL normal statement errors do not. Early
  validation exceptions bypass that common aborted-state update. Only exact BEGIN,
  START TRANSACTION, COMMIT, ROLLBACK are recognized. Savepoints, general autocommit
  controls and native nested-BEGIN behavior are not implemented in this path.
- Virtual disconnect removes binding/working state, without promotion. Lost/expired
  binding requires reconnect; missing expected transactional overlay invalidates
  binding before promotion. Engine restart can retain bindings/overlays through
  Redis, but proxy restart loses connections; no recovery transaction coordinator.

These are not distributed atomic transactions spanning SQL engine, Redis and
Kafka. A backend commit followed by failed overlay finalization cannot undo the
physical commit. Client failure after a durable registry write also leaves an
ambiguous acknowledgement, not an automatic undo.

### FSM 4 — Principal lifecycle

Absent -> CREATE atomically stores enabled principal+created set -> successful
later login stores binding, increments login/returns and marks reused -> repeated
logins -> NOLOGIN/ACCOUNT LOCK/DROP stores disabled tombstone. ENABLED and REUSED
are predicates/counters, not mutually exclusive enum states. Same-creator-session
login is rejected. Multiple distinct session bindings are supported; shared
principal lock serializes requests, revision comparison rejects stale tx commits.
No re-enable transition or deletion/recreation path is exposed.

### FSM 5 — Persistent world commitment

**General UNRESOLVED -> GENERATED -> EXPOSED -> COMMITTED fact FSM: NOT IMPLEMENTED.**
The closest current mechanism is principal committed overlays + working transaction
copies + monotonic saved depth + revision number. `world_id` is empty at creation;
`persistent_objects` has no observed update path. The session experiment revision
belongs to a separate disabled experiment subsystem, not the principal world.
`policy_guard.py::PolicyGuard._asset_observed` inspects projected object hints; it
does not prove that an exact returned fact is immutable or prevent all contradictions.

## 5. Invariants already enforced (with limits)

| Invariant | Status | Repository/test evidence and actual boundary |
| --- | --- | --- |
| Principal never becomes physical backend user | ENFORCED on inspected supported paths | Both proxies `internal/principal/principal.go::Reserved`, `AccountSQL`, `Call`; virtual auth closes backend before forwarding credentials; commands run only in Redis registry. `TestReservedAndSensitiveStatements`, `TestRegistryTransportFailsClosed`; `tests/principals/native_smoke.py` create/outage stages assert zero backend users. Arbitrary protocol/SQL bypass resistance is not exhaustively proven |
| Committed principal survives reconnect/restart | PARTIALLY ENFORCED | Non-expiring record, stable seed, restore/promote, AOF volume; `test_committed_state_survives_reconnect_and_rollback`. Historical service restart result in `VERIFICATION_RESULTS.md`; no fresh Redis crash/recovery proof |
| Disabled principals cannot authenticate/use queries | ENFORCED on registry paths | Enabled recheck in `finish_scram`, `native_auth`, runtime `query`; `test_scram_wrong_password_and_disable_in_flight`, `test_mysql_proof_wrong_password_and_disabled`, `test_disabled_identity_rejects_existing_session_and_retains_tombstone`. No immediate socket revocation; PING is local |
| Reuse means later session | ENFORCED | `PrincipalRegistry.login` rejects creator session or existing same binding; distinct reused set; `test_metrics_distinct_two_created_one_reused`, proof/link tests. Explicit creator-session rejection test missing |
| Commit/rollback/disconnect isolation | PARTIALLY ENFORCED | Physical DB authority, ordinary overlay snapshots, virtual promote/restore; CRUD and phase-B tests below. Ordinary committed fake data is deliberately session-only; savepoints, mixed-authority failure and crash windows remain |
| Exposed facts never silently contradict | NOT ENFORCED generally | Fixed generation/time anchor and schema-coherent metadata provide local repeatability; no fact ledger/schema binding; TTL/outage/schema changes can invalidate prior observations |
| Concurrent persistent updates cannot silently corrupt | PARTIALLY ENFORCED | Principal Redis lock + stale revision check + final MULTI pipeline; sequential interleaving conflict test. Finite lock lease has no fencing; ordinary overlay read-modify-write/depth updates lack distributed lock; no real parallel Redis test |
| Event redelivery cannot duplicate durable logical state | PARTIALLY ENFORCED | Evidence upstream event ID or source-coordinate ID plus SADD; scaling bounded processed IDs persisted. Evidence SADD and append are separate operations; session projections do not deduplicate; no atomic event outbox joins registry write and Kafka publication |
| Restart cannot contradict world/principal state | PARTIALLY ENFORCED | Principal commitment persists with stable dependencies/config; transient sessions/projected observations do not reconstruct; base schema not bound to principal version |
| Protocols share equivalent persistent abstraction | PARTIALLY ENFORCED | Shared registry/runtime and principal-seeded generation; native proof/status/error semantics differ intentionally; MySQL implicit boundaries exceed PostgreSQL ordinary-overlay handling; virtual MySQL is a bounded subset |

## 6. Missing or weak invariants, ranked

Rank indicates importance **before adaptation or Internet deployment**, not proof
of a current exploit or a failing live service. No CRITICAL exploit was established
by this static pass; broad deployment security certification is outside scope.

| Rank | Finding | Evidence / implication |
| --- | --- | --- |
| HIGH | No observed-fact commitment or contradiction gate | `ExposureTracker` tracks depth only; `query` persists aggregate depth; generated schema/base rows have no historical version binding. No safe input contract for changing facts adaptively |
| HIGH | PostgreSQL ordinary synthetic rollback can diverge from backend outcome | `Handler.drainBackendResponses` derives finalizer action from submitted SQL, not `CommandComplete` tag. If fake write -> native transaction error -> COMMIT yields backend ROLLBACK, overlay receives commit. Compound native commit spellings are also not recognized. Static path finding; reproduction NOT VERIFIED |
| HIGH | Synthetic savepoints are absent | `MutationStore` has one snapshot per transaction, no savepoint stack. Native ROLLBACK TO can succeed while fake overlay remains changed. Virtual path rejects savepoints. MySQL test explicitly asserts rollback-to is not full rollback; that is not a test of correct partial restoration |
| HIGH | Failure semantics differ by authority | Ordinary `MutationStore.record_*` logs Redis errors and can still let API claim affected rows; principal path raises. PostgreSQL ordinary `sendPostgresDeceptionError` does not set T -> E while virtual runtime does for ordinary operation failures. Early virtual SQL-validation exceptions also escape failed-binding update |
| HIGH | Durable state/evidence publication is not atomic | Registry writes precede proxy-published events; process loss can retain principal but lose evidence. Proxy `internal/publisher/publisher.go` emit methods use bounded best-effort buffers and publish loop can drop exhausted batches. Evidence `_append_once` claims ID before nontransactional append; crash between operations can permanently suppress missing event on retry |
| HIGH | No general concurrent/crash proof | Principal lease can expire before stalled writer returns; no fencing/CAS on final record write; unit MemoryRedis lock is `nullcontext`, pipeline is immediate writes. Sequential conflict test is valuable but not actual concurrency proof |
| MEDIUM | Session projection loss/duplication | `AuthoritativeStateStore._apply_query` increments on every event; consumer auto-commits offsets; bounded memory evicts and no boot replay restores it. Separate topics can deliver transaction events out of order |
| MEDIUM | Ordinary exposure/overlay TTL can change an ongoing world | Four-hour expiries; ordinary reads do not refresh all overlay snapshots; depth read errors return 1. Principal expected-key guard prevents partial transactional promotion but is not a complete observation guarantee |
| MEDIUM | Session end is not behavior-engine closure | Mapper drops query-less end; timeout or capacity closes summaries instead. Old session can reopen after late records; summaries can be dropped after bounded publish retries |
| MEDIUM | SQL abstraction is deliberately bounded | `_fake_insert_row` generates a row rather than faithfully storing literal VALUES (phase-B test explicitly notes this); no arbitrary DDL objects, role graph or all SQL expressions. Future fact model must not assume full SQL equivalence |
| MEDIUM | Replay cannot reproduce the original world | `ReplayEngine.replay` consumes sanitized capped queries on static sandbox fixtures; no copied principal, row, transaction or exposure snapshot |
| LOW | Historical “authoritative” naming and stale checkpoints overstate scope | Session state is derived, principal revision is not experiment revision, desired replica count is not physical count; older AGENTS/verification HEADs are historical |

## 7. Test-to-transition coverage map

All entries are **discovered coverage, not newly passing tests**. Tests were read
for their setup/assertions; mocks do not certify live durability or parallelism.

| Transition/invariant | Exact test file and symbols | Coverage limits / missing relevant cases |
| --- | --- | --- |
| Physical MySQL new -> auth -> close/fail | `mysqlproxy/internal/protocol/lifecycle_test.go::TestOrdinarySessionLifecycle`: quit, abrupt_disconnect, idle_timeout, wrong_password, unknown_user, disconnect_during_auth | Simulated wire/backend; no full PostgreSQL matching lifecycle matrix found |
| PostgreSQL session/prepared state / cleanup / local concurrency | `pgproxy/tests/proxy_test.go::TestSessionCreation`, `TestSessionPreparedStatements`, `TestSessionConcurrentAccess`; `pgproxy/tests/fixes_v2_test.go::TestInterceptorCleanupSession`, `TestInterceptorCleanupIdempotent`, `TestInterceptorCleanupDoesNotAffectOtherSessions` | Struct/map/counter and interceptor coverage, not principal Redis concurrency or wire authentication lifecycle |
| PostgreSQL backend health / shutdown | `pgproxy/tests/fixes_v2_test.go::TestBackendHealthCheckDetectsDown`, `TestBackendHealthCheckRecovery`, `TestGracefulShutdownDrainsConnections` | “Recovery” checks initial reachability then loss, not a restored listener; shutdown test has no active connections, so does not prove active transaction draining |
| Reserved route / outage -> reject | Both `internal/principal/principal_test.go::TestReservedAndSensitiveStatements`, `TestRegistryTransportFailsClosed` | Transport/predicate checks; malformed sequences do not exhaust parser bypass surface |
| SCRAM start -> finish -> no replay | `deception_engine/test_principal_registry.py::test_scram_proof_signature_and_replay`, `test_scram_wrong_password_and_disable_in_flight` | Proof, signature, challenge reuse and disable-in-flight; no real timed challenge expiry/racing rotation test |
| MySQL native success/failure | Same file `test_mysql_proof_wrong_password_and_disabled`, `test_native_malformed_lengths`, `test_rotation_preserves_identity_and_rejects_old_password` | In-memory Redis; backend availability dependence not simulated |
| First event -> active -> summary/capacity close | `session_module/test_session_module.py::test_new_session_created_on_first_event`, `test_close_session_calls_storage_save`, `test_oldest_session_closed_at_capacity`, `test_flush_all_closes_all_sessions` | Explicit helper/capacity assertions; production disconnect-to-summary integration and crash recovery missing |
| Out-of-order session/projection closure | Same file `test_session_duration_does_not_go_negative_for_replay_order`, `test_legacy_session_update_keeps_last_seen_monotonic`; `test_authoritative_state.py::test_out_of_order_session_end_rolls_back_open_transaction` | End-before-query case covered, not arbitrary ordering of BEGIN/DML/COMMIT or duplicate queries |
| Ordinary DML -> read-your-writes -> rollback/commit | `deception_engine/test_stateful_crud.py::test_rollback_restores_and_commit_preserves_same_session`, `test_transaction_mutation_is_isolated_between_sessions`; `test_phase_b_invariants.py::test_crud_rollback_commit_and_next_transaction_for_both_protocols` | Engine API snapshots, not PostgreSQL backend COMMIT-as-ROLLBACK; literal INSERT semantics explicitly excluded |
| MySQL ordinary transaction boundaries/failure | `mysqlproxy/internal/protocol/transaction_test.go::TestSyntheticTransactionRollback`, `TestSyntheticTransactionBoundaries`, `TestSyntheticStatusPreservesTransactionFlags`, `TestSyntheticFinalizationFailureDoesNotSendBackendOK` | Tests rollback/chain/autocommit/implicit commit, engine finalization failure and backend failure. No partial fake savepoint rollback or crash after backend commit |
| PostgreSQL transaction helpers | `pgproxy/internal/protocol/deception_crud_test.go::TestTransactionActionClassification`, `TestFailedTransactionRejectsOnlyDeceptiveQueries`, `TestPostgresMutationCommandTagsUseAffectedRows` | Classifier/status tests, not mixed physical/synthetic failed-commit integration |
| Absent -> enabled / duplicate rejected / permissions | `test_principal_registry.py::test_duplicate_and_invalid_are_not_created`, `test_bounded_role_and_quoted_mysql_syntax`, `test_permission_and_transaction_rejection` | No explicit same-creator-session login assertion or durable physical Redis round trip |
| Enabled -> later reuse -> correlated history | Same file `test_metrics_distinct_two_created_one_reused`, `test_scram_proof_signature_and_replay`; `evidence_store/test_evidence_store.py::test_principal_links_and_return_measurements` | Distinct identity/counter and creator-child link checks; does not prove every durable registry action reaches Kafka |
| Committed principal -> reconnect / rollback / disconnect | `test_principal_registry.py::test_committed_state_survives_reconnect_and_rollback`, `test_disconnect_discards_uncommitted_state`; `tests/principals/native_smoke.py` return/reconnect stages | “disconnect” unit test opens a second session while first is uncommitted, not actual socket teardown; native script has actual close checks |
| Tombstone rejects existing/later session | `test_phase_b_invariants.py::test_disabled_identity_rejects_existing_session_and_retains_tombstone`; verifier disable tests above | MySQL engine query fixture, no active proxy socket revocation test for both protocols |
| Expired binding/working state -> fail closed | Same file `test_expired_binding_rejects_queries_and_keeps_committed_identity`, `test_expired_working_overlay_cannot_erase_committed_state`, `test_active_transaction_refreshes_working_state_with_binding`, `test_postgres_abort_rollback_and_expiry_guard` | Explicit key deletion / expiry metadata assertions, not real Redis clock, AOF or crash behavior |
| Two returning sessions -> stale commit rejected | `test_principal_registry.py::test_concurrent_commit_conflict_and_unsupported_operation` | Sequential interleaving, MySQL fixture; no simultaneous processes/lock lease expiry/parallel grant-disable-DML stress |
| Observations/depth remain after rollback | `test_phase_b_invariants.py::test_observed_exposure_does_not_rollback_with_rows`, `test_principal_exposure_survives_rollback_and_return`; `test_realism_protocol_corrective.py::test_hidden_access_is_denied_without_progression_for_both_protocols`, `test_normal_progression_exposes_trap` | Depth monotonicity, not fact-level exposure persistence or contradiction rejection |
| Base world deterministic/coherent | `test_base_world_realism.py::test_same_seed_produces_identical_world`, `test_manager_hierarchy_is_valid_and_acyclic`, `test_department_heads_counts_and_budgets_are_derived`; `test_realism_protocol_corrective.py::test_postgres_catalogs_and_catalog_identity_are_coherent`, `test_mysql_metadata_and_qualified_table_are_coherent` | Repeatability under same inputs; no schema/generator upgrade compatibility for existing principals |
| Historical restart persistence | `tests/principals/run_native_smoke.py`, `native_smoke.py` reconnect stage; `VERIFICATION_RESULTS.md` restart observation | Historical Deception Engine restart only; fresh Redis crash, proxy crash with active tx, partial pipeline failure NOT VERIFIED |
| Evidence identity/idempotency/order/correlation | `evidence_store/test_evidence_store.py::test_kafka_event_id_preserves_upstream_identity_across_offsets`, `test_kafka_event_id_falls_back_to_source_coordinates`, `test_timestamps_are_normalized_sorted_and_traps_are_not_double_counted`, `test_artifact_updates_are_versioned_and_exact_replays_are_idempotent`, `test_first_and_last_seen_are_monotonic_for_out_of_order_artifacts`, `test_phase20_end_to_end_trace_contract` | In-memory repository tests, no crash between claim/append, broker auto-commit loss or duplicate logical event with fresh event ID |
| Scaling restore / replay rejection | `scaling_agent/tests/state_test.go::TestScalerPersistentStateRoundTrip`, `TestScalerIgnoresDuplicateEventIDs`, `TestRestoredProcessedEventIDRejectsReplay`, `TestControlStateAndAuditSurviveRestore` | Bounded dedup history, not world state or physical replica recovery |
| Replay allow/deny/isolation policy | `sandbox_replay/test_policy.py::test_replay_request_rejects_supplied_query_text`, `test_drop_is_blocked`, `test_multi_statement_is_blocked`; `test_hardening.py::test_fix_identifier_is_restricted_to_sandbox_schema` | Policy tests; no reconstructed original-world replay acceptance test |

Dormant experiment tests include concurrent assignment and revision/idempotency
checks (`session_module/test_experiment_assignment.py`). Those do not cover the
enabled principal runtime or make its session projection durable.

## 8. Adaptive-readiness gaps

| Question | Classification | Evidence-based answer |
| --- | --- | --- |
| 1. What has this attacker observed? | PARTIAL | Depth, SQL-derived discoveries, bounded sanitized query/outcome evidence. No actual returned fact/result ledger; no reliable attacker identity for ordinary sessions across reconnects |
| 2. Which facts are permanently committed? | PARTIAL | Principal permissions/verifier/overlays/revision persist; native DB commits persist. No generalized commitment set or base-world/schema-version pinning |
| 3. What is session-only? | SUPPORTED within inspected model | Proxy structs/prepared state; ordinary overlays/depth; virtual binding/transaction copies; transient analysis/projection maps. Lifetimes and owners above are explicit, although not exposed as one authoritative snapshot API |
| 4. Which persistent mutations did attacker cause? | PARTIAL | Principal overlays+creator/linked sessions and native modified-object projections; no complete durable native before/after causal ledger or unbounded linked-session history |
| 5. Which deception decisions were applied? | PARTIAL | Published outcome strategy/profile/trap fields in evidence; session strategy telemetry exists, but adaptive worker/poller disabled and no delivery guarantee joining writes to evidence |
| 6. Which future responses contradict observations? | NOT SUPPORTED | No fact-level contradiction evaluator/immutable observation history; projected-object guard is narrower |
| 7. Can authority be reconstructed after restart? | PARTIAL | Native DB and Redis principal records plus deterministic generation can recover under stable inputs; in-flight protocol state and session projections cannot be completely reconstructed |
| 8. Can two return sessions share consistent world? | PARTIAL | Stable principal seed/shared committed overlays, request lock, optimistic commit conflict detection; no full cross-session snapshot/exposure ledger, lease fencing or real concurrency/crash proof |

## 9. Recommended Pass 2 scope

**PLANNED ONLY: formalize the existing principal transaction lifecycle and pin its
current behavior with focused transition tests.** This is the smallest useful,
reviewable pass without changing SQL responses, persistence format or deployment.

Introduce a small local typed representation/helper for the existing binding
`tx`, `failed`, `revision`, `mutation_keys` fields and I/T/E mapping. Retain the
current JSON wire/storage fields and all current transition outcomes, lock scope,
revision comparison, TTLs, error codes, promotion ordering and rollback behavior.
Document principal commitment as the sole live durable authority; exposure depth
is knowledge that survives rollback, not transactional row state.

Characterize enabled/read-only, transaction begin, PostgreSQL abort, commit,
rollback, stale commit, expired binding, missing overlay, disable during a bound
session and rejected same-creator login. Assert exact serialized before/after
bindings and unchanged committed principal state on rejection, for both protocols.
Do not introduce stricter validation that silently changes accepted legacy states.
If extraction reveals a required behavior change, record it separately for review.

Acceptance: focused unit transition tests plus existing principal/phase-B suites
remain passing; representative response/status/Redis serialization is unchanged;
Git diff limited to the files below and handoff. No external services or FSM
library. No learner design. General exposure ledger and listed transaction fixes
remain separate follow-up passes because they require semantics decisions.

## 10. Exact files Pass 2 should modify

1. New `deception_engine/principal_state.py`: dependency-free binding type and pure
   transition/status helpers for existing semantics; no new storage authority.
2. New `deception_engine/test_principal_state.py`: table-driven transition and
   serialization compatibility tests.
3. `deception_engine/principal_runtime.py`: use helpers in `query` without changing
   Redis commands/ordering, persistence shape, SQL handling or response behavior.
4. `deception_engine/principal_registry.py`: use binding construction helper only
   in `PrincipalRegistry.login`; preserve auth/identity/verifier/locking behavior.
5. `deception_engine/test_principal_registry.py`: characterize creator-session
   rejection and existing cross-session transitions with explicit assertions.
6. `deception_engine/test_phase_b_invariants.py`: preserve and strengthen both-
   protocol abort/expiry/disable transition checks.
7. `AGENTS.md` and `STATE_WORLD_AUDIT.md`: record actual results and limits.

## 11. Files/components Pass 2 must NOT modify

- `.env`, `.env.example`, `config/features.yaml`, `config/deception.yaml`,
  `config/observability.yaml`, `docker-compose.yml`, `scripts/configuration.py`.
- `pgproxy/internal/protocol/handler.go`,
  `mysqlproxy/internal/protocol/handler.go`,
  `mysqlproxy/internal/protocol/transaction.go`, both proxy principal/auth modules.
- `deception_engine/api.py`, `generator.py`, `exposure.py`, `mutation_store.py`,
  `schemas/hr.yaml`, `schemas/finance.yaml`, `schemas/crm.yaml`.
- `deception_engine/strategy_registry.py`, `policy_guard.py`, `strategy_agent.py`,
  `strategies/registry.yaml`; no additional strategy/experiment registry.
- `session_module/authoritative_state.py`, `redpanda_consumer.py`, `session_engine.py`,
  learned/shadow/experiment/adaptation modules; no activation or new state API.
- `evidence_store/main.py`, `scaling_agent/internal/scaler/scaler.go`,
  `scaling_agent/internal/state/store.go`, `sandbox_replay/main.py`, observability,
  Kubernetes/cloud deployment and existing database/Redis volumes.
- Preserve user `cmds.txt` and unrelated work. No branch changes, worktrees,
  staging, commit, push, resets, volume resets or HMAC rotation.

## 12. Risks / unresolved questions

- Running service/config/volume health is NOT VERIFIED; October 16 verification
  is historical evidence, not a current pass. No tests were executed in Pass 1.
- Is ordinary-session fake COMMIT intentionally only session-lived? Code and
  cleanup tests say yes; durable principal semantics must not be generalized to it.
- Future fact scope needs a decision: session, principal, attacker cohort or global
  world. Current principal namespaces are protocol-specific; an IP is not identity.
- Safe base-schema/generator upgrades for existing principals need an explicit
  policy before adaptive or evolving assets exist. An overlay alone is not a
  frozen copy of the world that produced it.
- Mixed physical/synthetic transactions, savepoints, failed commits, temporary
  Redis loss, process death before/after promotion, event publish failure and lock
  lease expiry need separate fault-injection acceptance checks before strong claims.
- Evidence retention/redaction and replay limits prevent exact reconstruction of
  original results/literal queries. Sandbox hardening resets with its tmpfs DBs;
  retained reports can outlive the sandbox configuration they describe.
- Regex account interception and malformed-sequence tests provide bounded evidence,
  not a complete SQL/protocol security audit. Internet exposure is not authorized
  or certified by this pass.

PASS 1 STATUS: AUDIT COMPLETE (source/test-coverage audit; runtime NOT VERIFIED).

AGENTS.md updated: YES.

Recommended next action: implement only the behavior-preserving principal binding
type/transition helpers and focused tests described in Pass 2 above.

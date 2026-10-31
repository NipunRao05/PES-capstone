# Pass 8B — Authoritative Query/Application Correlation and Request Timing

> Pre-deployment hardening 1 — 2026-10-31: native seed authentication now maps to
> fixed least-privilege backend identities. Native fallback has a positive grammar;
> extended/prepared/binary native execution is rejected. Simple/text correlation
> remains; query evidence adds optional HR base-world identity/version. Historical
> records remain valid. See BACKEND_PRIVILEGE_CONTAINMENT.md and BASE_WORLD_HR_V1.md.


> Pass 8F — 2026-10-31: Redis now owns correlated query replay across processes
> and engine restart. COMPLETE reuses the original body/IDs without producer or
> outbox work. Claims older than five seconds can become AMBIGUOUS; no takeover.
> The original request is rejected after its 600-second start-time horizon, even
> after record cleanup. No independent local cache remains. See
> DISTRIBUTED_QUERY_IDEMPOTENCY.md for capacity, clock-skew and failure semantics.

> Pass 8E — 2026-10-30: one real PostgreSQL simple SELECT version() now verifies
> proxy execution/start -> engine decision/application -> daemon outbox -> indexed
> Evidence Store, with matching query-event IDs and no private metadata in SQL
> output. A reproduced Docker script-entry-point reimport defect was minimally
> fixed and rerun. MySQL/extended live linkage was not exercised; replay scope is
> unchanged. See TRACE_RUNTIME_VALIDATION.md for exact evidence and limitations.

2026-10-30. IMPLEMENTED / VERIFIED BY FOCUSED TESTS for newly instrumented ordinary
PostgreSQL simple and MySQL text queries, including supported virtual-principal
query loops. Historical and uncovered paths remain NOT OBSERVED. Runtime health,
cross-process replay recovery and real Redis recovery NOT VERIFIED.

## Problem and authority

Existing query fingerprints identify SQL shapes, not executions. Evidence event_id
is transport/retention identity (topic/partition/offset/session), not request identity.
Existing event timestamp is captured after response outcome is known. None safely
identified the query producing an application. The proxy now owns that identity
and start time; engine decision/application, world and storage authorities remain
unchanged. No raw SQL hashing or temporal guessing creates an execution ID.

## Proxy execution identity and timing

Each Handler.beginQuery creates a cryptographically random UUID4 and captures UTC
request_started_at in RFC3339Nano. It runs on accepted PostgreSQL simple Query or
MySQL COM_QUERY before policy handling/private engine RPC. Virtual principal loops
use the same helper. Per-handler state is reset for each execution; identical SQL
gets different UUIDs. Existing completion/outcome timestamp is not renamed.
Entropy failure leaves correlation absent rather than changing SQL behavior.

QueryCorrelation is shared through handler, QueryOutcome, QueryEvent and publisher
RawEvent within each Go module. Optional JSON fields use omitempty. Prepared and
extended event paths retain absent correlation; no protocol functionality expanded.

## Engine request and decision propagation

Ordinary /decide requests carry query_execution_id/request_started_at; private
/principals/query carries them through principal_runtime to /decide. Python validates
canonical UUID and bounded timezone-aware timestamp. Missing fields remain valid
legacy requests; invalid partial metadata is rejected. Optional typed request-model
fields are additive. They never participate in strategy definition digests.

Finalized decision records retain producing query_execution_id and request_started_at.
Applications link through their existing decision_id, without a second redundant
execution field. Existing state-before/producer ordering and actual provenance remain
unchanged. Optional trace schema fields preserve old decision records and their
original bytes/idempotency. Outbox and receiver accept the new records without
regenerating IDs or using payload-level identity.

## Private response envelope

After actual application creation, live_trace adds `_correlation` to the private
engine HTTP body, containing query_execution_id/request_started_at/decision_id/
application_id. This is not a database result field. Content-Length is updated;
the principal query response preserves the envelope after JSON decoding.

Both proxies accept strategy correlation only when execution UUID matches their
current request and both strategy IDs are canonical UUIDs. They retain their own
request timestamp, never replace it from a reply. Decode/transport failure leaves
decision/application IDs absent. D0 passthrough metadata is captured before the
existing fallback branch; policy/error applications retain their returned linkage.
Rows, columns, SQLSTATE/error packets, notices and headers are unchanged. Wire tests
compare responses with and without the private envelope in both protocols.

## Query-event propagation

The final per-execution event carries execution/start plus returned decision and
application IDs where present. The publisher does not infer them from fingerprint,
SQL or policy hints. Existing session partitioning, fingerprints, aggregate buckets
and event timestamps are preserved. Evidence Store retains bounded metadata on
the query record, accepting old events without it. Malformed metadata is marked
INVALID rather than fabricating fields. No high-cardinality metric labels added.

## Replay protection and its limits

Current Pass 8F behavior: the existing redis-deception authority coordinates one
global execution UUID across ordinary /decide and the full principal-query lifecycle.
Atomic claim/CAS completion, exact bounded replay, 250-ms duplicate wait, conflict,
ambiguity and fail-closed Redis behavior replace the process-local authority.
Principal binding/enabled/deadline checks still apply. A matching completed replay
does not advance exposure/mutations or enqueue traces. Capacity remains 1,024 and
the response horizon is 600 seconds from proxy request start; original expired
requests are rejected, never admitted as new. Oversized replies are explicitly
COMPLETE_UNREPLAYABLE. No exactly-once guarantee across side-effect crashes or Redis
data loss. Real two-process, engine-restart and both wire paths were verified.
Full contract and test limits: DISTRIBUTED_QUERY_IDEMPOTENCY.md.

### Historical Pass 8B process-local limitation (superseded by Pass 8F)

Existing proxy POST helpers have no application-level retry loop. Their normal
request lifecycle makes one strategy RPC per covered execution. Engine query_replay
also protects concurrent/repeated delivery in-process: scope/session/execution key,
request digest excluding changing private deadline, shared Future for in-flight
duplicates, original response/UUID replay, and 409 for conflicting reuse. It wraps
both /decide and private principal query so mutations are not replayed within that
cache window. Principal replay rechecks binding, enabled account and deadline under
the existing lock; it cannot bypass active-disable checks.

Cache is process-local, at most 1,024 entries, 600-second expiry of completed attempts;
oldest completed entries may be evicted earlier at capacity. Failed attempts are
retained to avoid blindly reapplying mutations. If all slots are in-flight, a new
request proceeds without correlation and logs that linkage is unavailable; SQL is
not blocked by research-cache capacity. This is not durable distributed idempotency.
Cross-replica replay, post-restart retransmission and retries after eviction are
not certified. Do not introduce cross-process transport retries on this foundation
and claim at-most-one global application. A repeated retained execution claiming
two different decision/application pairs is rejected during outcome evaluation.

## Asynchronous Evidence Store correlation

Query ingestion never requires an application lookup, so event-first and trace-first
delivery both work. Evaluation later verifies session, decision/application relation
and execution identity when linked records are present. Conflicts fail evaluation;
unresolved referenced applications make coverage incomplete, not a guessed match.
Events are also deduplicated by execution UUID, with inconsistent duplicate execution
content rejected rather than counted twice under different broker event IDs.

## Outcome evaluator

For a correlated decision, the producing query UUID is excluded first, irrespective
of a misleading completion timestamp. Other queries must have a distinct execution
UUID, matching session, authoritative request start strictly after application,
and completion before the normal episode end. Next-decision/horizon/close/event caps
remain intact. Matching SQL/fingerprint never excludes a different execution.
Clock ordering is only a boundary safeguard; UUIDs establish producing identity.
Unsynchronized host clocks can still reduce observed follow-up coverage.

The completed-session adapter can certify a bounded session snapshot only when the
formal proxy close query_count equals retained distinct executions, all events carry
identity/start, every query's indicated application is present in the manifest, and
every producing execution is retained. Otherwise it stays PARTIAL. Unannotated
bypass/prepared/transport-failure events prevent this conservative certification.
This is local snapshot verification, not a global retained-store coverage index.

Controlled complete snapshots with zero follow-up now produce observed zero;
missing IDs/start/trace context remain null. Tests prove Q1 -> A with Q2/Q3 follow-up
counts two, repeated SQL still counts, and consecutive episodes do not overlap.
Newly observable dimensions are follow-up/verified/successful query counts, errors
and successful trap interactions where all source guards are satisfied. Exposure,
commitment deltas, novelty inventories and cross-session outcomes remain deferred.

## Profile and historical compatibility

deterministic_components v1 already defined these nullable activity counts and their
formulas. This pass supplies previously absent evidence without changing caps or
normalization. Historical v1 outcomes remain immutable; re-evaluation changing an
existing outcome raises conflict, never silently overwrites it. Old events without
correlation are not repaired by timestamps, fingerprints or SQL. Legacy fixture
contracts that explicitly supply request-start/coverage remain valid; current
historical retained completion-only events still do not meet that contract.

## Protocol scope

Covered: ordinary PostgreSQL simple queries, MySQL text queries, supported virtual
principal SELECT/SHOW/DML paths, D0 evaluated passthrough and covered error results.
No strategy IDs are fabricated for authentication or transaction-only responses.
NOT COVERED: PG extended/prepared/portal execution, MySQL binary prepared execution,
framework exceptions and paths never returning an engine strategy decision.
No backend mirroring, protocol rewrite or new request retries were added.

## Tests and status

New Go query_correlation_test.go in each proxy verifies execution uniqueness, start,
event linkage/reset and rejection of foreign execution IDs. Existing world commitment
wire tests now echo private correlation and prove no UUID/envelope leakage. All six
affected protocol/interceptor/publisher packages pass. gofmt applied.

New test_query_correlation.py verifies real ASGI /decide, repeated/concurrent requests,
distinct executions of identical SQL, invalid metadata, private envelope length,
outbox acceptance, and principal disable protection. New
test_query_application_correlation.py verifies ingestion without trace dependency,
both delivery orders, producing-query exclusion, observed zero, boundaries, conflicts,
historical missingness and aggregation compatibility.

The long engine regression initially had one deadline failure because in-memory
principal tests attempted unavailable background Redis delivery. Their common
test_principal_registry.py fixture now stubs only optional trace transport; deadlines
and principal assertions remain intact. Also corrected a script encoding failure
and duplicate edits before passing Go tests; no checks weakened.

Commands: existing bundled Python, pass2-tooling PYTHONPATH and
PYTHONDONTWRITEBYTECODE=1. From deception_engine:

```text
python -m pytest -q -p no:cacheprovider test_query_correlation.py test_live_trace.py test_decision_trace.py test_trace_outbox.py test_action_provenance.py test_world_commitments.py test_world_commitment_lifecycle.py test_strategy_registry.py test_strategy_version_integrity.py test_strategy_commitment_preconditions.py test_principal_registry.py test_principal_state.py test_postgres_error_state.py test_phase_b_invariants.py
```

157 PASS, 71.98s. Final ASGI and explicit passthrough/rejection/error linkage tests
were then added; query_correlation + strategy_registry selection: 24 PASS, 5.63s:

```text
python -m pytest -q -p no:cacheprovider test_query_correlation.py test_strategy_registry.py
```

From evidence_store:

```text
python -m pytest -q -p no:cacheprovider test_query_application_correlation.py test_outcome_aggregation.py test_strategy_outcomes.py test_strategy_trace_endpoint.py test_strategy_traces.py test_evidence_store.py
```

53 PASS, 1.28s. From each proxy:

```text
go test ./internal/protocol ./internal/interceptor ./internal/publisher -count=1 -timeout 60s
```

All six packages PASS after approved Go cache access. git diff --check passes.
No service restart, live stack, real Redis recovery or Internet attacker-data claim.
Recommended next pass: authoritative retained-trace enumeration/coverage denominator,
not a learner. No next-pass work started.

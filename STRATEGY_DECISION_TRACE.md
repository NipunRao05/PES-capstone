# Pass 6 — Strategy Decision/Application Trace and Experiment Registry

> Pass 8D — 2026-10-30: TraceStore now uses one Lua operation per record for
> canonical content plus versioned membership/expiry/context/sequence storage,
> replacing SET NX EX alone. Same-ID replay retains original position and TTL;
> conflicts remain immutable. Decision/application pairs remain separate writes.
> See TRACE_INDEX_AND_COVERAGE.md for epoch, bounds, snapshots and legacy gaps.
> Contract tests pass; real Redis Lua execution remains NOT VERIFIED.

> Pass 8B — 2026-10-30: optional proxy query_execution_id/request_started_at are
> retained on decisions; application -> decision preserves that producing request.
> The private `_correlation` reply connects proxy query events to those exact IDs.
> Old records remain valid; see QUERY_APPLICATION_CORRELATION.md for scope/limits.

> Pass 7 — 2026-10-30: explicit retained decision/application pairs can now link to
> immutable same-session outcome episodes in Evidence Store. Current query timing
> and manifest completeness limits remain visible as null/PARTIAL rather than
> invented activity scores. See STRATEGY_OUTCOME_MODEL.md; no causal claim.

## Durable delivery and recovery — Pass 6C, 2026-10-30

The volatile queue described in the historical Pass 6B section below is superseded
by a producer-owned Redis outbox with durable-before-send, bounded automatic retry,
terminal diagnostics and startup recovery. Causal production boundaries and
TraceStore IDs/validation are unchanged. See STRATEGY_TRACE_DELIVERY.md for bounds,
shutdown, loss/retention windows, tests and the unverified real Redis recovery limit.

## Pass 6B implementation — 2026-10-30

**IMPLEMENTED / VERIFIED BY FOCUSED TESTS** for covered engine producers. This
section supersedes the disconnected-runtime status in the historical Pass 6 record
below. Runtime health and real Redis restart durability remain **NOT VERIFIED**.

### Final decision and application boundaries

`live_trace.producer` wraps the covered semantic producer functions. At entry,
`live_trace.finalize` reuses `select_registered_rule` and registry eligibility,
resolves fallback when needed, then calls the existing `decision_trace.begin`.
A frozen Finalized context retains the selected immutable Strategy and its exact
ID/version/digest/expected binding. A ContextVar carries it through production;
the decision record is created before producer invocation, not inferred afterward.

Candidate rules remain existing ones: D0 baseline/system-variable/default decide;
D1 database enumeration, catalog/information_schema/SHOW producers; D2–D4 existing
asset-family selection at SELECT/COUNT entry; D6 known managed mutation, otherwise
D0. Inline database enumeration was extracted unchanged into
`_handle_database_enumeration` to establish its D1 boundary. The outer decide and
system-variable probes may prepare an unused D0 context; no trace is emitted for
None results or when an inner producer already completed the response. Only the
innermost completed producer pair is emitted. Direct transaction/auth and framework
exception paths remain outside strategy tracing.

State-before captures protocol, tx state, exposure depth and bounded relevant
commitment evaluations/digest before producer effects. `principal_runtime.query`
supplies its already-authenticated record through a scoped ContextVar and resets
it in finally. The current response's exposure acknowledgement still happens later;
it cannot enter the earlier snapshot. No raw SQL, rows, verifier or full principal
record enters persistence. Baseline experiment remains deterministic_baseline v1.

Actual action still comes independently from Pass 5C. `_json_response` compares it
against the pre-production strategy, then the wrapper constructs an application
using the same prior decision UUID. Exposure denial after a selected lure retains
that decision with policy_rejection/BLOCKED. Existing wire strategy annotations on
errors/direct callers retain the old guard normalization/allowlist; they do not
replace the finalized trace decision. No new selector or behavior policy was added.
Commitment eligibility was previously not a live gate; current production conditions
are empty. Nonempty fixture conditions can select fallback in the trace context;
they do not silently rewrite existing SQL producer behavior.

### Live observational emission and storage

After a completed producer, its Python response carries the decision/application
pair privately and a bounded emission status. `Emitter.submit` uses a 128-entry
nonblocking process queue; a daemon worker posts the pair to Evidence Store
`/evidence/strategy-trace`, using EVIDENCE_STORE_URL or the existing internal service
address. Timeout is 0.5 seconds; no required readiness or configuration default was
added. The in-process decision precedes production; **durable storage need not**.
Pair submission is after production so unused probes produce no orphan records.

The Evidence Store endpoint validates bounded schema/linkage before calling the
existing repository TraceStore, decision first, application second. It returns
inserted/unchanged, HTTP 409 on conflicting IDs and 422 on invalid records. It uses
the existing Evidence API trust/network boundary, not a new authenticated control
plane. The endpoint cannot prove a caller's research claim or execute strategies.
It accepts no arbitrary state fields/SQL/results and uses the existing record cap.
Generic ingest_artifact remains unchanged and unused for these traces.

TraceStore remains ID-based SET NX EX. Decision failure stops application storage;
application failure can leave a decision without application. Same original pair
can be retried manually with original UUIDs/content. No automatic retry/backoff or
durable outbox exists. Queue full, transport failure, finalization/build failure
and conflicts have bounded warnings without payload/error text. Response-local
status is QUEUED or FAILED; QUEUED is **not** a durable receipt. Worker 409 is logged
as integrity conflict; other write/HTTP failures as persistence failure.

### Availability and limits

SQL never waits for HTTP evidence writes. Context read/record construction uses
bounded existing local state; failures skip tracing with a warning and preserve
SQL. Decision/application/SQL are not pair-atomic. Process death can lose queued
pairs; failed deliveries are dropped with a warning; daemon shutdown does not drain
the queue. Successful storage durability is still governed by existing Redis
configuration and TTL, with no restart/disk recovery claim. No high-cardinality
metrics or provenance fields were added to wire JSON, headers or rows.

The pre-existing SELECT/COUNT and mutation algorithms, timing policy, principal
state transitions and commitment acknowledgement remain unchanged. D5 is still
review-only and D7 unmapped. No outcome linkage/scoring, reward, learner, adaptive
selector, shadow policy, graph, gap detector, candidates or promotion.

### Verification

New `test_live_trace.py` covers all six families plus inline database enumeration;
explicit decision-before-generator ordering and old exposure depth; pair linkage
through real TraceStore code with a Redis double; decision/application failures,
TraceConflict with unchanged response; keyword-call compatibility and ingestion
validation. `test_strategy_trace_endpoint.py` verifies decision-first storage,
replay, 409 conflicts and rejection without writes. Initial endpoint test collection
lacked local requests; it now reuses the existing service dependency stubs.

Final exact PowerShell commands use the existing bundled Python and tooling shown
in the historical verification section. From deception_engine:

```text
python -m pytest -q -p no:cacheprovider test_live_trace.py test_decision_trace.py test_action_provenance.py test_strategy_version_integrity.py test_strategy_commitment_preconditions.py test_strategy_registry.py test_policy_guard.py test_world_commitments.py test_world_commitment_lifecycle.py test_postgres_error_state.py test_principal_state.py test_principal_registry.py test_phase_b_invariants.py
```

From evidence_store:

```text
python -m pytest -q -p no:cacheprovider test_strategy_trace_endpoint.py test_strategy_traces.py test_evidence_store.py
```

Evidence: **24 PASS, 1.23s**. Final engine result recorded in newest AGENTS handoff.
Earlier engine checkpoints: 145 PASS, then 146 PASS after keyword handling. A bounded
real Redis check was attempted using temporary UUID test keys and existing container,
but Docker reported Evidence Store restarting, so the script never executed. No
services restarted/config changed, no full-stack or Go campaign. Live deployment
and real Redis durability remain NOT VERIFIED. Recommended Pass 7: scoped outcome
linkage and deterministic scoring, only after reviewing this pass; not started.

---

2026-10-30. **PARTIAL**. Record builders and trace-specific Redis storage are
IMPLEMENTED / VERIFIED BY UNIT TESTS. Live trace emission is NOT IMPLEMENTED.
Real Redis/process restart durability and runtime health are NOT VERIFIED.

## Decision timing

The interrupted builders were preserved, reviewed and extended. Actual flow is
api.decide -> deterministic request branch -> response producer (e.g.
_handle_select/_handle_mutation) -> DecisionResponse construction -> _json_response
-> RuleOnlyStrategyAgent.select_registered_rule -> PolicyGuard.enforce_registered_choice
-> strategy annotation -> ActionProvenance comparison. Shared reads choose their
asset family before generation, but this is not the final universal approval point.
Commitment eligibility is a read-only API, not a live gate on every current producer.

No live pre-application decision boundary was fabricated. begin must be called
only with an explicitly finalized approved selection and pre-production context;
there is currently no runtime caller. Moving approval earlier across catalogs,
read/count, errors and mutation paths requires explicitly passing the final
selection through those branches and preserving existing fallback behavior. This
pass does not certify that refactor or emit post-hoc records as causal decisions.

## Decision model

decision_trace.begin returns schema_version=1; UUID decision_id; UTC timestamp;
experiment_id/version/mode/active; session_id; optional principal_id; protocol;
strategy_id/version/strategy_definition_digest; expected_action_binding;
approval_status; eligibility boolean/reason; reason_code; state_before.
It rejects unapproved or ineligible selections. D5 cannot be recorded as approved;
D7 is unknown. UUIDs/timestamps are generated once: delivery retries must reuse the
original record, not call begin again.

## Application model

applied returns schema_version=1; UUID application_id; decision_id; UTC timestamp;
expected_action_binding; actual_action_binding; provenance_status;
application_status; result_class. Pass 5C ActionProvenance is consumed without
reimplementing its comparison. Expected-binding disagreement is rejected.
Policy rejection -> BLOCKED; statement error -> ERROR; known fake production ->
APPLIED; missing provenance or unconfirmed passthrough -> NOT_VERIFIED.
MISMATCH is preserved independently of application status. APPLIED describes
engine production, not client delivery, physical execution or effectiveness.

## Experiment registry

The small code-owned experiment() definition is deterministic_baseline v1,
deterministic_rule_based, active. Unknown ID/version fails. Historical
session_module/experiment_assignment.py is DORMANT and UNSUITABLE for this baseline:
it represents sticky HMAC factorial arms and operator intervention control, not
read-only baseline membership. It was not changed or activated.

## State-before and strategy references

Only transaction state, exposure depth, commitment scope/digest and evaluated
precondition identities/values/results are captured. No principal mutation JSON,
verifiers, raw SQL, IPs, credentials or response rows. Missing principal context
is unavailable, not an empty authoritative principal world. The principal reference
must already be explicit; no inference from IP/username. Digest references alone
do not reconstruct old facts after later observations; no full snapshot claim.
Strategy exact lookup resolves ID/version/digest while that definition is retained.

## Evidence Store findings

Existing EvidenceRepository.ingest_artifact hashes kind/identity/payload into its
event ID. _append_once performs SADD then a nontransactional append pipeline.
A failure after SADD can suppress retry before the payload is stored. Generic
artifacts remain unchanged; their behavior is not reused for trace identity.

## Trace-specific persistence

EvidenceRepository.strategy_traces exposes TraceStore on the existing Evidence
Store Redis client, using EVIDENCE_TTL_SECONDS retention (currently 30-day default).
No new database/service. Each evidence:strategy_trace:<kind>:<UUID> key contains
the entire canonical JSON record. Atomic SET NX EX stores ID and content together;
there is no separate claim or append. get retrieves directly by kind/UUID.
The interface is repository-internal, not a public ingestion HTTP endpoint. It
checks schema field sets, canonical UUID keys and a 16-KiB limit; it expects trusted
model-builder output, not arbitrary external nested data. External ingestion would
require full schema validation/authentication before exposing this interface.

## Idempotency, failure and ordering

Same kind/ID + identical canonical record -> unchanged. Different content under the
same ID -> TraceConflict, never overwrite. Different IDs retain distinct records
even with otherwise identical content. Failed writes before storage leave no claim;
unknown client outcome after storage is recovered by retrying the original record.
Duplicate delivery does not refresh TTL. Deduplication is bounded by retention;
after expiry the ID may be inserted again. Decision/application TTLs are independent.

Application before decision is rejected for caller retry; no pending queue exists.
Its expected binding must match the stored decision. No cross-key atomic ordering
or retention guarantee: a decision may expire after linkage validation. There is
no pair transaction, index, global event count or session evidence projection yet.

## Availability and limits

No runtime trace emission or persistence dependency was wired into SQL. Therefore
these persistence failures currently cannot alter SQL or state. A future emitter
must catch/report bounded failures and retry asynchronously with original IDs;
that behavior is NOT IMPLEMENTED or verified here. This is a storage foundation,
not yet durable research evidence from real decisions. Source Redis configuration
and TTL are the durability boundary; unit doubles do not prove disk persistence.

No outcome linkage/scoring, reward, learner/shadow mode, adaptive selection, gap
detection, candidate generation, graph or promotion. Before Pass 7, complete the
explicit pre-production selection contract and observational runtime emission.

## Verification

PowerShell environment for both working directories:

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
```

Bundled interpreter: C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe

From evidence_store:

```text
python -m pytest -q -p no:cacheprovider test_strategy_traces.py test_evidence_store.py
```

22 PASS, 3.55s. RedisDouble tests cover identity/different IDs/conflicts/retrieval,
failure before and after write, duplicate application and out-of-order retry. This
is simulated Redis behavior, not a real server restart or Lua/transaction test.

From deception_engine:

```text
python -m pytest -q -p no:cacheprovider test_decision_trace.py test_action_provenance.py test_strategy_version_integrity.py test_strategy_commitment_preconditions.py test_strategy_registry.py test_policy_guard.py test_world_commitments.py test_world_commitment_lifecycle.py
```

Existing interrupted command was rerun with these targets including registry/policy:
78 PASS, 12.39s. No proxy edits or Go campaign.

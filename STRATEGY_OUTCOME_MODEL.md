# Pass 7 — Strategy Outcome Linkage and Deterministic Component Scoring

> Pass 8D — 2026-10-30: outcome availability can now be measured against indexed
> retained applications under an exact experiment/profile scope. Missing outcomes
> are coverage gaps, never zero behavior. Pass 7 identities/formulas are unchanged;
> see TRACE_INDEX_AND_COVERAGE.md. Pre-index history and real Redis NOT VERIFIED.

> Pass 8B — 2026-10-30: newly instrumented simple/text query paths now carry proxy
> execution/start metadata and exact private application linkage. Producing-query
> exclusion uses identity; certified bounded snapshots can observe v1 activity
> counts/zero. Historical unlinked evidence remains unobserved. See
> QUERY_APPLICATION_CORRELATION.md for protocol/coverage/replay limits.

> Pass 8A — 2026-10-30: persisted outcomes now support bounded, read-only manifest
> aggregation with exact strategy/experiment/profile grouping and null-aware
> observability diagnostics. Global retained coverage denominator is not verified.
> See OUTCOME_AGGREGATION_BASELINE.md. Pass 7 semantics below remain unchanged.

2026-10-30. IMPLEMENTED / VERIFIED BY FOCUSED TESTS for bounded completed-evidence
evaluation. Current retained-evidence scoring coverage is PARTIAL. Runtime health
and real Redis recovery remain NOT VERIFIED. CALIBRATION REQUIRED.

## Purpose and interpretation

Outcomes link subsequent evidence temporally within one session. They do not show
that a strategy caused behavior or estimate causal effectiveness. APPLIED describes
engine application, not attacker receipt or strategy effectiveness. No composite
reward, strategy utility, weighted sum, learner or adaptive consumer was added.

## Ownership and inspected prior code

Evidence Store owns offline/on-demand evaluation and historical persistence.
Existing TraceStore and retained session evidence are REUSED. The pure evaluator
in strategy_outcomes.py consumes explicit decision/application pairs and a bounded
evidence snapshot; it is independent of SQL, proxies and live selection.
SessionEngine/consumer retain their existing behavior and derived/session outputs.

Historical session_module/reward_model.py expects a different linked telemetry
schema, learned_selection validation, MITRE progression and resource fields.
It is DORMANT / INCOMPATIBLE with this v1 dataset; no helpers or formulas reused.
Shadow/bandit/learning code and factorial assignment remain DORMANT and unchanged.
No MITRE dependency is required by the new evaluator.

## Episode start/end and non-overlap

An episode starts at the retained application's timezone-aware timestamp. Follow-up
request start and completion must both be strictly before the end; request start
must be strictly after application. Events at either boundary are excluded.

Applications sort by event time plus application ID. Each episode ends at the
earliest next retained decision, formal session_end, 300-second horizon or event
cap. Next-decision boundaries are clamped to start in overlapping timestamp cases;
no negative windows or event overlap is created. Equal application timestamps
therefore yield an empty earlier window, not duplicate attribution.

V1 prefers formally closed session evidence. Without closure it emits nothing
until the application's full horizon has elapsed, then marks outcomes PARTIAL.
An active session is not finalized solely because later events arrived. Session
closure never comes from inferred inactivity in this evaluator. Snapshot input is
bounded to 128 pairs and 1,000 events; scoring caps follow-up requests at 100. All
these are UNVALIDATED_RESEARCH_BOUND values, not calibrated scientific thresholds.

## Explicit retained-evidence interface

POST /evidence/session/{session_id}/strategy-outcomes accepts only a bounded
application_ids manifest (1–128). It loads existing TraceStore applications and
decisions, verifies session linkage and retrieves repository session evidence.
Formal closure comes from retained connection_events with event_type=session_end.
No trace is fabricated from query strategy labels. The explicit manifest is needed
because current TraceStore has no session trace index. Missing IDs fail; it does
not silently infer them. Returned records include outcome IDs and insert/replay
status; TraceStore.get('outcome', id) retrieves persisted data internally.

The API cannot certify that this manifest or retained event collections are
complete. Therefore current service evaluations always use PARTIAL completeness
and leave unprovable query dimensions null. The pure evaluator accepts explicit
coverage contracts for controlled snapshots/fixtures, not an HTTP claim of completeness.

## Critical producing-query limitation

Proxy InterceptSimpleOutcome/InterceptTextQueryOutcome emit query events after
responses; their timestamps are completion/emission time. Retained evidence lacks
a per-query application link or authoritative request-start timestamp. Thus the
current application's own query can appear after the application timestamp.
Timestamp-after alone is insufficient to call it subsequent engagement.

The evaluator requires request_started_at to attribute query activity. Current
repository records do not provide it, and the adapter does not invent it. Any
completion-only query in a window makes the activity dimensions NOT OBSERVED even
if a caller supplied a stronger coverage contract. Adding that source contract is
deferred; no proxy/protocol change was quietly included in this pass.

## Outcome schema and stable identity

schema_version=1; UUID5 outcome_id; decision_id/application_id; session/principal
reference; strategy ID/version/digest; experiment ID/version; window_start/end;
termination_reason; application_status/provenance_status; effectiveness_eligible;
raw_features; component_scores; scoring profile ID/version; completeness and
calibration_status. No raw SQL, IP, response dump or secrets are persisted.

Identity is UUID5 over application UUID + deterministic_components + profile
version. Same application/profile yields the same identity across repeated builds;
a future profile version has a different ID. Only v1 formulas are implemented.
There is no speculative production v2 or automatic formula migration.

## Eligibility

Only APPLIED + MATCH sets effectiveness_eligible=true. BLOCKED, ERROR,
NOT_VERIFIED, INVALID_ACTION and MISMATCH remain observable records but are not
eligible for later comparisons. This flag alone does not certify complete evidence;
analysis must also filter completeness and component availability.

## Raw features and missing versus zero

Implemented fields: followup_queries, verified_followup_queries,
successful_followup_queries, verified_errors, verified_trap_interactions,
window_duration_seconds and disconnect_observed. Query dimensions require verified
coverage and request-start provenance; otherwise null. With genuine complete empty
coverage they are zero. Verified success/error uses response.outcome_verified and
literal boolean success, never SQL text.

Trap counts additionally require successful verified deception authority, is_trap
and a managed read/mutation profile (fake_table_data/high_value_target). Catalog
visibility (fake_schema) is not a trap interaction. Window duration describes the
attribution interval, not attacker activity. Disconnect signal means formal
session-close evidence terminated that window; it is not a failure judgment.

new_relations, new_query_families, new_commitments and exposure_depth_delta remain
null / NOT OBSERVED. Pre-decision trace digests do not reconstruct old commitment
sets or relation inventories; end-depth observations can include producing-query
effects. No novelty or depth improvement is guessed from insufficient baselines.

## Deterministic component profile

Code-owned deterministic_components v1, schema version separate. Constants and
formulas (all CALIBRATION REQUIRED):

- engagement = min(verified_followup_queries / 20, 1)
- error_component = min(verified_errors / 10, 1)
- trap_interaction = min(verified_trap_interactions / 5, 1)
- disconnect_signal = 1 if formal closure ended window, otherwise 0 when closure
  evidence is available; null if unavailable.

Unavailable components remain null. Error is a separate observed component, not
negative reward or a claim of strategy failure. No weighted composite exists.

## Persistence, duplicates and late evidence

TraceStore's outcome kind uses the existing atomic whole-record SET NX EX with
Evidence Store retention (default 30 days). It requires retained decision/application
linkage and matching session/strategy/version/digest/experiment references.
Generic artifact deduplication and trace delivery/outbox are unchanged.

Same outcome ID/content is unchanged; different content under the same ID conflicts.
New profile versions use different IDs and can retain historical scores. Events
deduplicate by stable event_id; contradictory duplicate IDs are rejected. Ordering
is deterministic by event time then ID, not assumed across Kafka topics.

Formal closure reduces late-event uncertainty but does not eliminate it. A late
event/trace changing an already persisted result triggers HTTP 409; old scores are
never silently updated. There is no automatic correction/revision mechanism.
Closed/horizon results from incomplete manifests/events remain PARTIAL. There is
no claim that late evidence is automatically discovered or re-evaluated.

## Limits and next boundary

Same-session only; delayed principal return attribution is DEFERRED, DPR unchanged.
Missing trace/event delivery creates dataset bias. Pass 6C transport has bounded
retry/loss/expiry; real Redis/process recovery is still NOT VERIFIED. This pass
scores only records actually retained; it does not reconstruct missing applications.
No service restart or claim of real Internet attacker data.

DEFERRED: composite reward calibration, cross-session delayed outcomes, aggregation,
causal effectiveness claims, learner/shadow/adaptive policy, graph, gaps, candidates
and automatic promotion. Recommended next pass: outcome aggregation and baseline
completeness statistics, explicitly reporting null/unattributable dimensions.

## Tests and evidence

New test_strategy_outcomes.py covers non-overlap, before/start/end exclusions,
cross-session exclusion, duplicate/out-of-order events, application eligibility,
zero vs missing, own-query ambiguity, verified traps vs catalog visibility, separate
component formulas, event/horizon caps, profile identity, persistence replay/late
conflict and completed-evidence endpoint replay/session scope.

Using existing bundled Python, pass2-tooling PYTHONPATH and
PYTHONDONTWRITEBYTECODE=1, from evidence_store:

```text
python -m pytest -q -p no:cacheprovider test_strategy_outcomes.py test_strategy_trace_endpoint.py test_strategy_traces.py test_evidence_store.py
```

36 PASS, 1.16s. From deception_engine:

```text
python -m pytest -q -p no:cacheprovider test_decision_trace.py test_live_trace.py test_trace_outbox.py test_world_commitments.py test_strategy_version_integrity.py
```

45 PASS, 4.43s. No live runtime, Docker restart, Go/protocol or full repository tests.

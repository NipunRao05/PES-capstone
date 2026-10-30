# Pass 8A — Outcome Aggregation, Coverage Diagnostics, and Baseline Research Statistics

> Pass 8D — 2026-10-30: explicit population_mode=INDEXED_RETAINED adds bounded
> atomic retained-index snapshots and application-to-outcome denominators with
> exact experiment/profile scope. Valid reports use AUTHORITATIVE_INDEXED_SCOPE;
> pre-index history remains NOT VERIFIED. Manifest mode remains the explicit selected
> population with DENOMINATOR_NOT_VERIFIED. See TRACE_INDEX_AND_COVERAGE.md for
> activation, capacity, expiry, eligibility and orphan semantics. Real Redis NOT VERIFIED.

> Pass 8B — 2026-10-30: future retained outcomes can gain observed activity fields
> through authoritative execution/application correlation. Null/zero aggregation
> semantics are unchanged; no historical repair or global denominator was added.
> See QUERY_APPLICATION_CORRELATION.md.

2026-10-30. IMPLEMENTED / VERIFIED BY FOCUSED TESTS. Coverage denominator PARTIAL /
NOT VERIFIED. Runtime and actual retained attacker population NOT VERIFIED.
CALIBRATION REQUIRED. This is descriptive research tooling, not strategy selection.

## Purpose and prior code

Evidence Store owns on-demand aggregation of persisted Pass 7 outcomes. It never
reconstructs episodes or calls evaluate to manufacture outcomes. Standard-library
Counter/statistics.mean/statistics.median are PURE STATISTICAL HELPERS. Existing
TraceStore is REUSED read-only. Historical reward/shadow bandit/learning code is
DORMANT / INCOMPATIBLE with this reporting purpose and is not connected or reused.

## Population and API

POST /evidence/strategy-outcomes/aggregate takes outcome_ids (0–1,000 UUIDs) and an
optional filters object. It retrieves retained outcomes by exact ID. A missing or
expired requested ID returns 404, not an implicit zero-outcome. Invalid/inconsistent
records return 422. No Redis scanning, session enumeration, writes, refresh of TTL,
aggregate persistence, training export or new service is added.

Population is EXPLICIT_RETAINED_OUTCOME_MANIFEST, after bounded exact filters. It
is neither a full store census nor lifetime totals. The API accepts only strategy
ID/version/digest, experiment ID/version and scoring-profile ID/version filters;
there is no query language. No session/principal statistics or raw attacker data
are returned. Empty manifests return zero selected counts with unavailable rates
and no invented strategies. Group ordering is deterministic; generated_at is UTC.

## Grouping identity

Every numerical distribution is grouped by all seven fields:

```text
strategy_id, strategy_version, strategy_definition_digest,
experiment_id, experiment_version, scoring_profile_id, scoring_profile_version
```

Versions/digests/experiments/profiles are never silently merged. Multiple digests
claiming one strategy ID/version produce separate groups and an explicit
MULTIPLE_DEFINITION_DIGESTS diagnostic. This diagnoses record disagreement; it does
not independently authenticate the old registry lock or unknown future formulas.

## Coverage denominator

TraceStore currently has per-UUID GET and TTL-bounded records, without an
authoritative retained application/decision/outcome index. No global denominator
can be certified by this endpoint. coverage_denominator_status is therefore
DENOMINATOR_NOT_VERIFIED. retained_decisions, retained_applications,
retained_outcomes_total, applications_without_outcomes and retained-store coverage
percentage are null. applications_with_selected_outcomes counts only distinct
application IDs in the selected manifest, across any profile versions.

manifest_records, unique_manifest_records and overall.outcome_count identify the
input, deduplicated input and post-filter populations separately. Observed rates
and completeness proportions use this explicit selected population as their valid
denominator; they are not ingestion completeness or lifetime coverage percentages.
Reports warn about bounded retention/delivery and unresolved producing-query timing.
No fabricated report of a live evidence population was generated in this pass.

## Operational, eligibility and completeness populations

Overall and each exact group retain outcomes, eligible/ineligible, APPLIED/MATCH,
application status, provenance status, completeness and termination counts.
Application and provenance counts are separate dimensions and can overlap; blocked
and mismatch are not mutually exclusive reasons. COMPLETE, PARTIAL and
INSUFFICIENT_EVIDENCE proportions divide by the selected outcome count, or null
when empty. Empty filtered populations do not create placeholder outcome records.

Per-group all_outcomes describes the entire operational population. Separately,
eligible_outcomes contains only effectiveness_eligible records. Eligibility must
agree with APPLIED + MATCH or validation fails. Its component summaries therefore
exclude blocked/error/mismatch/unverified applications. Eligibility still does
not certify complete sources, calibration or causal interpretation.

## Missingness, numeric and boolean summaries

Every actual v1 raw feature and component remains visible. Null/missing keys mean
NOT OBSERVED, never zero. Numeric summaries include observed_count, missing_count,
observed_rate, coverage label, n, min, max, mean and median. Only observed finite,
nonnegative numeric values contribute. Components are bounded to [0,1]. Boolean
values are not accepted as numeric counts. Standard-library median averages the
middle pair for even n; no quantiles or scientific significance tests were added.

All-null dimensions have n=0 and null min/max/mean/median. Observed [0,0] has n=2,
mean/median=0 and missing_count=0. disconnect_observed reports true/false/missing
counts rather than a numerical mean. The numeric disconnect_signal component
retains its existing v1 meaning and is summarized separately.

Global feature_observability/component_observability are machine-readable
observed/missing counts and rates; they contain no cross-profile numerical means.
Numerical distributions live only in exact groups. NO_DATA means zero observed
values; OBSERVED means all selected records supplied a value; PARTIAL_COVERAGE means
some supplied one. These are availability labels without a readiness threshold.
They do not indicate performance or scientific usability.

## Deferred features and producing-query ambiguity

Current raw dimensions include follow-up queries, verified/successful queries,
verified errors, verified trap interactions, window duration, close observation,
new relations/query families/commitments and exposure delta. Components remain
engagement, error_component, trap_interaction and disconnect_signal. Each is
summarized individually; nothing is aggregated into a reward.

capability_limits keeps deferred dimensions visible with missing source needs:
pre-decision relation/query inventories; reconstructible commitment sets;
attributable end depth excluding the producing query; delayed cross-session linkage.
Their actual values remain null as produced by Pass 7. Aggregation does not infer
new facts, reinterpret missingness or change the scoring profile.

Pass 7's producing-query ambiguity remains: completion-time query events cannot
identify subsequent requests reliably. Current endpoint-built outcomes therefore
have null activity scores/PARTIAL status. The report quantifies those missing
dimensions in the supplied population. It does not repair timestamps or claim a
measured live missingness percentage without loading real outcomes.

## Time range, integrity and immutability

The report returns earliest selected window_start and latest selected window_end
as normalized UTC timestamps, not experiment start/end or ingestion times. Unknown
retention age is not inferred from those timestamps. Bounded-retention warnings
always remain present.

Same canonical outcome ID/content is counted once. Conflicting reuse of an ID fails
the report rather than choosing a copy. Invalid schema/status/eligibility/window,
group identity or numeric values are rejected. No source record, principal state,
registry, score or trace is mutated. Store-before/after tests verify read-only API
behavior. Aggregate reports themselves are not persisted or used by selectors.

## Interpretation limits

CALIBRATION REQUIRED. No composite reward, rankings, recommended strategy, causal
uplift, D0 comparison, p-values, significance claims or learner-readiness threshold.
Small groups retain their exact observed n; no minimum n is invented. Means may
differ across groups without supporting superiority or effectiveness claims.

The next recommended pass is authoritative request-start and query/application
linkage instrumentation, because source semantics currently prevent defensible
observation of key activity dimensions. No instrumentation was implemented here.

## Verification

New test_outcome_aggregation.py tests empty/all-null/all-zero/mixed populations;
all seven grouping fields; digest diagnostics; operational vs eligible populations;
completeness/termination/boolean counts; duplicate/conflicting IDs; deterministic
order; invalid values/filters; selected time range; forbidden ranking/reward fields;
and endpoint reads from persisted outcomes without modifying Redis contents.

PowerShell, working directory evidence_store:

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_outcome_aggregation.py test_strategy_outcomes.py test_strategy_trace_endpoint.py test_strategy_traces.py test_evidence_store.py
```

47 PASS, 1.29s. Initial new-file run had a test-fixture string-division error;
the fixture now sets the invalid raw value directly, and validation rejects it.
No cross-component code changed, so no engine/Go/full-suite or live/Docker campaign.
Runtime health, actual population statistics and real Redis recovery NOT VERIFIED.

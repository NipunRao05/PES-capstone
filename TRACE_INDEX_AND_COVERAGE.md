# Pass 8D — Authoritative Retained-Trace Indexing and Coverage Denominators

> Pass 8E — 2026-10-30: real Redis Lua admission/metadata, replay/conflict,
> snapshot, 132-record pagination, one-second expiry cleanup, bounded concurrency
> and the HTTP 3/2/1 denominator are now VERIFIED. Isolated capacity 3 rejected the
> next admission safely; 100/500 records per kind were timed. Full configured sizing
> and Redis restart/disk durability remain NOT VERIFIED. See TRACE_RUNTIME_VALIDATION.md.

2026-10-30. IMPLEMENTED / VERIFIED BY CONTRACT TESTS. REAL REDIS INDEX/LUA
VERIFICATION: NOT VERIFIED. Runtime health NOT VERIFIED. This document supersedes
older no-index statements only for the newly indexed retained population.

## 1. Problem

Explicit outcome-ID manifests summarize supplied subsets. They cannot prove that
all retained applications have been enumerated and cannot establish an application
denominator. Manifest reports remain supported with DENOMINATOR_NOT_VERIFIED.

## 2. Population terminology

INDEXED_RETAINED_POPULATION means live records admitted through the versioned
indexed TraceStore path, at or below a captured sequence boundary. It is not all
historical applications, all delivered traces, or everything ever observed.
Pre-index records, expired records, traces lost before receiver storage and
capacity-rejected deliveries are outside this denominator. Coverage describes
retained data availability, never strategy performance.

## 3. Index authority

The existing Evidence Store Redis client remains authority. No new database,
container, worker, feature flag, Prometheus counter or generic artifact index is
introduced. Trace IDs and canonical contents remain unchanged. Engine/proxy/world/
strategy selection code is unchanged in Pass 8D.

## 4. Indexed record kinds

decision, application and outcome have separate members/expiry/context keys under
evidence:strategy_trace:index:v1:<kind>. Trace keys remain
evidence:strategy_trace:<kind>:<UUID>. Each member's score is its global index
sequence. An expiry sorted set records server-time expiry; a context hash retains
strategy ID/version/digest and experiment ID/version. Application context is copied
from its validated decision at indexed admission, permitting denominator filtering
after decision expiry. This is index metadata, not a new logical trace identity.

## 5. Index version

Index version 1 is independent of trace schema version, strategy version,
experiment version and scoring profile version. The three kinds share one sequence
counter and activation metadata hash, evidence:strategy_trace:index:v1:meta.

## 6. Activation epoch

The metadata hash persists index_version, enabled_at (UTC), random epoch UUID,
sequence and per-kind membership counts without a TTL. The first indexed write
activates it atomically. TraceStore.activate_index() can explicitly activate an
empty index; this is not automatic historical backfill. Before activation, indexed
reporting returns INDEX_NOT_ACTIVE (HTTP 409), never a fabricated epoch or denominator.
Process restart reuses Redis metadata. An epoch must accompany a reused snapshot.
Missing/corrupt metadata with residual index keys is an integrity error.

## 7. Atomic record/index storage

One Lua EVAL compares canonical content, writes a new TTL record, allocates sequence,
and updates membership/expiry/context/counts. All index key types and cardinalities
are checked before normal write mutations. Same-ID/content returns unchanged without
refreshing TTL or allocating a position. Same-ID/different-content conflicts before
index mutations. Different IDs remain distinct. Unknown acknowledgement is retried
with the original content/ID. Existing indexed application/outcome replay can remain
unchanged after dependencies expire; a new record still requires retained linkage.

Lua is serialized on the existing standalone Redis authority, so concurrent first
writes have one insertion and one position. This is a designed contract, modeled
in tests, not a real-server proof. Lua runtime errors do not roll back previous
commands; type/cardinality preflight addresses ordinary wrong-type failures, not
arbitrary Redis corruption, eviction, resource exhaustion or disk loss. Redis Cluster
cross-slot operation is not supported by these existing non-hash-tagged keys.
Decision/application pairs remain two separate record transactions.

## 8. Sequence semantics

Sequence is a monotonic ordering token, not a population count. Each first admission
consumes one position. Replayed legacy records enter at their current admission
position. After record expiry, re-admission gets a newer position. Cleanup never
resets/reuses sequence. Counter values are restricted below the sorted-set exact
integer limit, 2^53. Individual trace expiration does not expire epoch/counter state.

## 9. Snapshot semantics

An atomic read captures snapshot_max_sequence and epoch. Later insertions do not
enter that snapshot. Indexed aggregation reads all three bounded kind indices and
live records in one EVAL, with no interleaved writes during that report's capture.
The report exposes version, enabled_at, epoch, maximum sequence and live counts.
Same boundary yields the same report apart from generated_at while retention and
integrity state remain unchanged. A boundary is not an archived/frozen copy:
records can expire or be lost before a later report/page. Subsequent reads honestly
count only records still retained; this can shrink an old boundary's population.

## 10. Pagination and bounds

TraceStore.list_records(kind, after_sequence=0, limit=128, ...) and POST
/evidence/strategy-traces/list expose kind-specific pages. Allowed kinds are exactly
decision/application/outcome. Limit is 1–128; continuation requires original epoch
and snapshot_max_sequence. after_sequence is the last inspected position, including
stale rows, so empty pages still advance. done marks exhaustion of that boundary.
No wall-clock/UUID ordering, Redis SCAN, KEYS or arbitrary predicates are used.

Each kind is capped at 1,000 index entries, including stale entries until cleaned.
At capacity, new admission fails without storing a record or evicting live evidence.
Ingestion returns HTTP 503 so the existing outbox may retry within its own limits.
A complete report reads at most 3,000 records; existing record cap is 16 KiB, so the
raw theoretical bound is about 48 MiB plus protocol/metadata overhead. This bounded
atomic operation blocks concurrent Redis operations while executing; no latency or
production-throughput claim follows from the model tests. Capacity and operation
size require runtime validation before research-scale collection.

## 11. Retention and expiry handling

Record retention remains EVIDENCE_TTL_SECONDS (default 30 days), independent per
record. Duplicate delivery does not renew TTL. Expiry is recorded using Redis TIME
and the actual remaining PTTL on legacy admission. Enumeration checks the live key;
missing/expired records never count. An expiry between page requests shrinks the
later page rather than failing the entire population. Active metadata survives.

## 12. Legacy unindexed records

LEGACY GAP: existing trace keys are neither scanned nor automatically backfilled.
Matching replay can admit a legacy record from that point onward while preserving
its bytes, timestamp and remaining TTL; dependencies must support a safe context.
Other legacy keys remain outside the index. Referenced retained records without
membership are diagnosed LEGACY_UNINDEXED where detectable. No claim is made to
discover all unreferenced legacy records. historical_pre_index_coverage=NOT_VERIFIED
is always retained in indexed reports.

## 13. Stale-index cleanup

Each indexed admission inspects at most 128 due expiry entries for its kind.
Pages inspect at most 128 positions; full aggregation inspects at most 1,000 per
kind. Missing records have only their membership/expiry/context removed and the
persistent membership count decremented. Valid trace records are never deleted by
index cleanup, even when expiry metadata says they are overdue. No separate worker.
Idle indices remain bounded by capacity even before the next cleanup call.

## 14. Application-to-outcome coverage

POST /evidence/strategy-outcomes/aggregate adds explicit
population_mode=INDEXED_RETAINED. Existing outcome_ids requests keep manifest mode.
The indexed request requires filters.experiment_id, experiment_version,
scoring_profile_id and scoring_profile_version; optional exact strategy ID/version/
digest filters use the existing bounded contract.

Within that scope, N = live indexed applications and M = applications with one
matching live indexed outcome for the selected profile. Coverage = M/N, or null
when N=0. N-M is APPLICATION_WITHOUT_OUTCOME, not a zero behavior score. An expired
outcome means no matching outcome is currently retained, not proof none was ever
generated. Outcome statistics summarize matched records only; missing applications
do not manufacture zero scores. Groups with no outcomes still expose denominator
and empty distributions. Numeric formulas, profile versions and calibration remain
unchanged; no outcome evaluation/writes occur during reporting.

Example request:

```json
{"population_mode":"INDEXED_RETAINED","filters":{"experiment_id":"deterministic_baseline","experiment_version":1,"scoring_profile_id":"deterministic_components","scoring_profile_version":1}}
```

## 15. Scoring-profile scope

Coverage requires the exact profile ID/version. An application's v1 outcome cannot
cover v2. Original Pass 7 outcome IDs are retained. Multiple competing outcome
records for one application/profile are diagnosed and excluded from coverage;
they never inflate M. No new profile or second outcome identity convention.

## 16. Experiment and strategy scope

Experiment ID/version are exact filters, including in application denominators.
Group identity retains strategy ID/version/digest, experiment ID/version and profile
ID/version. Different strategy digests remain separate, including denominator-only
groups. MULTIPLE_DEFINITION_DIGESTS remains an explicit diagnostic. No rankings,
causal comparisons, weighted reward or recommendation of a winning strategy.

## 17. Eligibility denominators

All retained applications, including blocked/error/unverified, contribute to N.
APPLIED + MATCH separately defines eligible_retained_applications, with its own
covered/uncovered counts and rate (null if no eligible applications). Operational
data coverage and effectiveness-analysis eligibility are distinct. Eligibility
does not certify complete query evidence, calibration or causal effectiveness.

## 18. Orphan diagnostics

Reports count stale index members removed, outcomes without indexed retained
applications, outcomes without retained applications, applications without indexed
retained decisions, applications without retained decisions and detectable legacy
references. Orphan outcomes never create denominator applications. Applications
with missing decisions remain in the denominator using admission-time index context.
Global indexed counts and filtered scope counts are reported separately.

## 19. Integrity errors

Malformed metadata/key types/cardinalities, missing context/expiry, mismatched epoch
or invalid context fail closed as INDEX_INTEGRITY_ERROR (HTTP 409); no SCAN fallback.
Persistent per-kind counts detect missing index structures/members where possible.
Linked outcome disagreements/duplicate profile outcomes are bounded diagnostics and
set INDEX_INTEGRITY_WARNING. Normal valid indexed reports use
AUTHORITATIVE_INDEXED_SCOPE. Local cleanup is the only report-side mutation.
Administrative deletion of all index/metadata or coordinated corruption cannot be
distinguished from a new empty store without an external durability authority.

## 20. Historical completeness limitation

AUTHORITATIVE_INDEXED_SCOPE describes the designed current indexed retained scope.
PRE-INDEX HISTORY: NOT VERIFIED. Expired data, producer outbox losses and records
never admitted remain outside the denominator. No all-history total, real attacker
dataset, delivery-loss percentage or learner-readiness claim is made.

## 21. Real Redis verification status

NOT VERIFIED. Read-only docker ps found Evidence Store restarting and no running
Redis container. No healthy test-safe endpoint was available. No service/container
was started, restarted or repaired, no instance installed and no test keys written.
Lua atomicity/expiry/concurrency are modeled, not runtime-proven. Overall health,
disk recovery, failover and load behavior remain NOT VERIFIED.

## 22. Tests and next boundary

New test_trace_index.py covers all kinds, idempotency/conflict, before/after-write
failure and unknown acknowledgements, concurrent replay, distinct IDs, epoch,
legacy admission/remaining TTL, snapshot later-write exclusion, pagination, expiry,
stale cleanup preserving valid records, sequence survival, bounds/capacity, metadata
corruption/missing index, 3 applications/2 outcomes, empty denominators, profile/
experiment/strategy/digest scope, eligibility, orphans, read-only deterministic
reports, explicit manifest compatibility, API bounds and retryable capacity errors.
RedisDouble in test_strategy_traces.py models Lua contracts under a lock; it does
not execute the Lua text. Existing regression suites are retained.

PowerShell, working directory F:\b\Capstone-main\evidence_store:

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_trace_index.py test_strategy_traces.py test_strategy_trace_endpoint.py test_strategy_outcomes.py test_outcome_aggregation.py test_evidence_store.py test_query_application_correlation.py
```

Final selection: 71 PASS, 1.22s; git diff --check passes. No engine/Go/full-repository campaign because
those production files were unchanged. Recommended next pass: bounded deployment/
runtime validation of Evidence Store Redis Lua/index/outbox integration. This
recommendation does not authorize service changes; no next-pass work started.

DEFERRED: Pass 8B distributed/restart-safe replay, uncovered prepared/extended
protocols, commitment/exposure deltas, cross-session delayed outcomes, calibration,
learner, adaptive selector, attack graph and automatic promotion.

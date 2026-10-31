# Research dataset contract — Hardening Pass 2, 2026-10-31

This is a bounded seven-day **engineering collection contract**, not an effectiveness
claim or an internet deployment. Deterministic selection and scoring remain unchanged;
learning, adaptive selection, graph work and promotion remain disabled. Old records
are immutable and remain compatible. Missing evidence is never an observed zero.

## Population and workload

The target is 10 queries/minute for 604800 seconds, with ten queries/session and
one principal event/session in the representative sizing fixture. Each query can
produce one decision/application pair. Outcomes are evaluated on demand, with zero
to one outcome/application/scoring-profile version; the model budgets one. Actual
attacker behavior, session mix, response sizes and follow-up activity are unknown.

| Queries/min | Queries, decisions, applications each | Outcomes (0..upper bound) | Sessions at 10 queries/session | Principal events at 1/session | Outbox arrivals | Modeled Redis memory |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 10,080 | 0..10,080 | 1,008 | 1,008 | 10,080 | 0.098 GiB |
| 10 | 100,800 | 0..100,800 | 10,080 | 10,080 | 100,800 | 0.984 GiB |
| 60 | 604,800 | 0..604,800 | 60,480 | 60,480 | 604,800 | 5.905 GiB |
| 600 | 6,048,000 | 0..6,048,000 | 604,800 | 604,800 | 6,048,000 | 59.05 GiB |

The last two rows are overload scenarios, not supported rates under the current
policy. Sessions can reach the query count (or exceed it through auth-only traffic);
principal events are scenario assumptions, not a measured attacker rate. At one
session/query, the modeled four session/principal/profile events plus one query
event reach 504,000 journal admissions at 10 queries/minute; memory must be reviewed
for that larger session mix. Unbounded authentication floods are not covered.

Outbox arrivals are not concurrent backlog. Delivered entries are removed. With a
continuous outage at 10/min, 48 hours produces 28,800 pending arrivals before other
limits, below 32,768 slots. Retry exhaustion can occur sooner (500 attempts, about
41 hours at the maximum retry spacing). Terminal entries remain visible and consume
capacity until retention expiry. This is bounded delivery, never lossless delivery.

## Measurements, using retained local engineering fixtures

Bytes below are actual stored JSON encodings, not guessed object sizes. Session
evidence is the complete sanitized session projection serialized by the existing
repository, including its retained child lists; the old session-hash-only estimate
is not used as a complete session size. No source record contents were printed.

| Encoding | n | Median bytes | Largest measured bytes |
|---|---:|---:|---:|
| Decision, isolated current-metadata fixture | 132 | 1,079 | 1,079 |
| Application, isolated current-metadata fixture | 132 | 520 | 520 |
| Outcome, isolated current-metadata fixture | 1 | 1,397 | 1,397 |
| Sanitized query event, mixed retained fixture generations | 547 | 858 | 2,018 |
| Full retained session projection | 128 | 8,849 | 44,635 |
| Principal/session-link event | 102 | 562 | 705 |

Earlier pre-metadata decision/application measurements were median 921/389 and
maximum 1055/395 bytes; retained outcome median/max was 1240 bytes. The current
decision fixture changes its session/reason marker, so this is not an isolated
benchmark of metadata overhead. These samples do not establish a worst-case bound.

`scripts/measure_research_evidence.py` admitted 1,000 private queries, 100 sessions,
1,000 outcomes, 100 principal events and 1,400 journal events using the actual Redis
Lua/index/repository paths. Redis used_memory grew 10,483,464 bytes, or 10,483.464
bytes/query, including trace indices, journal, session projections and deduplication.
Elapsed admission time was 8.075206s. Exact private keys were removed afterward.
This small-fixture measurement extrapolates to about 1.06 GB at the baseline rate;
20% headroom is about 1.27 GB. It is not a capacity/load/latency certification.

Docker reported 16,712,589,312 bytes memory and the Redis volume filesystem reported
983,837,576 KiB available during validation. These are local observations, not Azure
resource reservations. Redis maxmemory excludes RSS, fork/COW, AOF buffers and other
services; the next runtime-hardening pass must reserve those resources explicitly.

## Canonical bounded policy

Only `config/deception.yaml` owns deployment policy. The launcher renders environment
values; standalone module defaults match it. Offline validation rejects insufficient
trace headroom, a journal below the modeled admission count, or a retry schedule
longer than retention.

| Setting | Current value | Meaning |
|---|---:|---|
| trace_index_capacity | 131,072 per kind | Decision/application/outcome, including stale memberships pending bounded cleanup |
| event_journal_capacity | 524,288 | Immutable sanitized event envelopes, including logical expiry until cleanup |
| retention_seconds | 2,592,000 | 30-day maximum retained record lifetime |
| outbox_capacity | 32,768 | Pending plus terminal retained envelopes |
| outbox_retention_seconds | 172,800 | 48-hour envelope retention |
| outbox_max_attempts | 500 | Bounded retries with existing exponential/300s backoff |
| evidence_redis_maxmemory_mb | 2,048 | Redis allocator limit, noeviction |
| redpanda_retention_seconds | 1,209,600 | 14 days, seven-day run plus seven-day temporal headroom |

The baseline consumes 100,800/131,072 trace slots per kind (76.9%), before existing
retained records. The representative journal scenario consumes 141,120 slots (26.9%).
At 60 and 600 queries/min, an initially empty trace index fills in approximately
36.4 and 3.64 hours. Capacity does not reset at a new run or export. Thirty-day TTL
does not promise thirty days of continuous collection at the seven-day sizing rate.
Review current retained counts before every run. Existing Redis data is not evicted
or deleted to make a capacity model fit.

Full trace admission returns 503 and preserves existing records; the outbox retries.
Journal capacity failure prevents Kafka offset commit and backpressures consumption.
Kafka offsets are committed per partition/message only after successful processing.
Malformed non-object messages are counted explicitly before commit. Redis OOM,
arbitrary corruption, disk failure and broker expiry remain possible collection gaps.

Legacy per-session query/stage lists remain capped projections (500 queries, 100
stage records). New evidence is admitted to the immutable journal before projection
trimming; a rollover counter exposes the projection limit. Journal cleanup removes
at most 128 expired envelopes/admission, never a live entry. Logical expiration
does not immediately erase physical hash members while the service is stopped.
The shared Redis allocator bound also applies to legacy projection/dedup keys.

Online indexed aggregation remains an atomic maximum-1,000-record-per-kind report.
A larger population fails explicitly with 413 and
`REPORT_LIMIT_EXCEEDED_USE_PAGINATED_EXPORT`; it never silently reports a prefix as
the population. Export uses 128-record trace/journal pages instead. Lifetime totals
and scientific experiment completeness remain NOT_VERIFIED even if retained-scope
application/outcome availability happens to be 100%. Collection integrity diagnostics
are separate from those retained-scope denominator ratios.

## Deployment provenance

Every canonical `compose up` creates a content-addressed launch manifest. Generated
files live under ignored `.runtime/`, with an operator-owned read-only manifest bind
into Evidence Store. The Redis manifest registry is bounded at 256 manifests; an
operator must archive/review it before reaching that bound. It is not silently pruned.

Fields include manifest schema/version/ID, UTC creation time, launch UUID, deployment
ID, run ID, experiment ID/version, Git commit, source-file SHA256 map/source digest,
resolved nonsecret configuration/digest, world ID/version, strategy registry version/
digest, scoring profile/version, and observed service image IDs/inventory digest.
Git commit plus source digest identifies uncommitted runtime inputs. Source hashes
are not a reproducible source archive or signed release. Dependency/image pinning is
deferred to release hardening.

Deployment/run UUIDs persist in `.runtime/research-identity.json`; a launch UUID is
new each up. Optional process environment `HONEYPOT_DEPLOYMENT_ID` and
`HONEYPOT_RUN_ID` can name a new research run without editing .env. A restart is not
automatically a new experiment. The manifest excludes itself/config-hash labels from
configuration digest computation to avoid circular identity.

Configuration digest covers resolved nonsecret features, policy, observability and
generated Compose content. Secret values are represented by a constant placeholder;
secret rotation alone does not change that digest. Source/deployment changes still
change provenance. After startup, observed image IDs supplement the immutable launch
base, with a separate inventory digest. Manifest validation checks both digests;
this is integrity checking, not cryptographic operator authentication.

New query/session/principal events, decisions, applications and evaluated outcomes
carry `deployment_manifest_id`; the manifest resolves deployment/run/world/strategy
and scoring identities. Legacy records without it remain unattributable, never
retroactively assigned to the latest manifest. Missing manifest references remain
export diagnostics. Existing persisted outcomes are not rewritten.

## Trusted traffic origin

`research_external` means a connection accepted by the ordinary proxy listener.
It is an operational source classification, not proof of maliciousness, a unique
attacker, or internet origin. `operator_validation` means the private validation
listener. `unknown` covers historical or unmarked producer traffic. Loopback alone,
client IP, SQL, login name and application_name never select operator origin.

PostgreSQL validation listener is 15432; MySQL is 13306. Compose publishes both on
127.0.0.1 only. The listener owner assigns origin and overwrites inherited session
origin; it cannot be selected by an ordinary SQL connection's request fields.
Manifest ID comes from producer configuration. Direct private HTTP/Kafka producers
remain trusted infrastructure, not public attacker interfaces. Docker peer services
can reach these ports: do not publish/forward them publicly. Access isolation and
public deployment firewall review remain deployment work.

Origin propagates through query/auth/principal/session events, session profiles,
decisions, applications, outcomes, filters and exports. Public metadata never enters
SQL response rows/columns. New controlled runtime queries use the private listeners;
private sizing/restart fixtures are separately namespaced and removed. Earlier
fixtures retain unknown origin. No existing fixture was relabeled external.

Research export defaults to exact `research_external` selection. Explicit
`operator_validation`, `unknown` and `all` modes support validation/legacy review.
Aggregate APIs accept exact origin and deployment-manifest filters; absent origin
matches unknown. Filters do not reinterpret missing outcomes as zero or certify a
historical denominator. Do not pool unknown/operator fixtures into research results.

## Integrity, metrics and interpretation

Bounded metric labels are the three trace kinds and fixed diagnostic reasons only.
Evidence metrics expose index count/capacity/remaining/utilization, journal count/
capacity/rejections/expiry, Redis used memory/AOF status, export success time/age and
projection/malformed/capacity diagnostics. Engine metrics expose pending/terminal/
capacity/oldest outbox age, Redis memory, full/terminal/expiry diagnostics. Legacy
pending entries without the new age index report unknown age (-1) until worked.

Warnings cover 80% trace/journal capacity, unhealthy AOF, overdue daily export and
delayed/terminal delivery. These are engineering operational thresholds, not research
effectiveness thresholds. Metrics/logs are not the authoritative dataset. Seven-day
Prometheus retention is operational only; Loki remains 72h, explicitly insufficient
as a seven-day forensic archive. The durable journal/export is the research path.

Exported SQL is sanitized but still potentially sensitive. Session/principal linkage,
usernames, metadata, artifact text and pseudonymous identities can identify behavior.
Use restricted storage, encryption/backups/access review and a deliberate deletion
policy. Exports contain no raw Kafka dump, .env, database secrets, password verifiers,
HMAC key, source-IP salt, or Redis principal/world credential records. Treat export
checksums as corruption detection; they do not make the dataset public-safe or signed.

Remaining limits: bounded retention/capacity, pre-journal/pre-index history gaps,
mutable legacy projections, broker retention/disk/backpressure, arbitrary corruption/
power loss/failover, unknown public traffic mix, unsupported prepared/extended query
trace paths and uncalibrated components. No real attacker dataset or causal result
was collected in this pass.

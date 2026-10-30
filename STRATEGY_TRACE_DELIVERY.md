# Pass 6C — Durable Strategy Trace Delivery, Retry, and Recovery

> Pass 8E — 2026-10-30: actual redis-deception enqueue/retry/update/ack and real
> HTTP delivery to indexed Evidence Store are VERIFIED. Test-only sender failure
> and discarded acknowledgement recovered with the original IDs in new Python
> worker processes. The actual engine daemon delivered a live PG query trace after
> a reproduced entry-point import fix. Redis process-restart/disk durability remain
> NOT VERIFIED; see TRACE_RUNTIME_VALIDATION.md. Earlier status below is historical.

> Pass 7 — 2026-10-30: outcome evaluation is an on-demand completed-evidence path
> in Evidence Store, not an outbox message from the live engine. Missing traces
> remain a dataset completeness limitation; delivery semantics below are unchanged.

2026-10-30. IMPLEMENTED / VERIFIED BY CONTRACT TESTS. Real Redis execution,
Redis/process restart recovery and whole-runtime health are NOT VERIFIED.

## Previous path and ownership

Pass 6B's Emitter used queue.Queue(128), a daemon HTTP worker, 0.5-second timeout,
no retries and no shutdown drain. Failures discarded pairs. Existing session-module
dead-letter publishing concerns malformed Kafka events, not producer-local recovery;
it is retained dormant/unmodified for this work. No broker topic or service added.

The deception engine now owns pending delivery in its existing Redis dependency
(REDIS_HOST/PORT, normally redis-deception). Evidence Store still owns received
historical records in its own Redis. These authorities remain separate.

## Durable enqueue boundary

live_trace.Emitter.submit calls trace_outbox.Outbox.enqueue after the original
decision/application records exist. A single Lua operation checks capacity and
stores the entire canonical envelope plus due/expiry indexes before returning
DURABLE_PENDING. No HTTP is sent before that acknowledgement. Delivery identity
is the original application UUID; original decision/application records never change.
The pair is capped at 32 KiB including envelope metadata. An existing delivery ID
with different pair content is CONFLICT, never overwritten.

The dedicated client uses the same engine Redis target with socket connect/read
timeouts of 0.4 seconds and retry_on_timeout=False. This is a configured bound,
not a measured latency promise or absolute DNS/OS wall-clock bound. A failed local
write returns FAILED and logs a bounded warning; no durable-acceptance claim is
made. A lost Redis enqueue acknowledgement may mean storage succeeded; recovery
still finds that entry. SQL never waits for Evidence Store or HTTP retries.

## Representation and bounds

Three namespaced keys: trace-outbox:v1:entries (hash), :due and :expiry (sorted
sets). Each envelope contains delivery_id, immutable pair, created_at/expires_at,
attempt_count, next_attempt_at, status and bounded last_error_category; attempts
add last_attempt_at. Defaults are code constants, not another feature authority.

At most 1,024 retained entries, including terminal diagnostics. New work at limit
returns FULL without evicting valid existing records. Pending and terminal records
expire 86,400 seconds after enqueue. Worker/enqueue scripts prune expired entries;
shared keys also receive a 24-hour TTL on enqueue, so stopped deployments do not
retain the data indefinitely. Terminal records deliberately consume capacity until
expiry; operators can inspect the bounded Redis state without trace payload logs.
Expiry is a deliberate retention loss boundary, not successful delivery.

## Retry and acknowledgement

One worker per process polls due work, including at application startup with no
new attacker query. HTTP timeout remains 0.5 seconds. A valid 2xx receipt must
contain decision/application = inserted or unchanged. Network errors/timeouts,
429, 5xx and malformed/uncertain acknowledgements retry. 409 becomes terminal
CONFLICT; other 4xx become PERMANENT_FAILURE. Redirect/other uncertain results
retry rather than acknowledge. No response bodies or exception text are stored.

Retry schedule is deterministic: min(2 ** attempt_count, 300) seconds, first retry
after 2 seconds, no jitter. At 20 observed failed attempts, EXHAUSTED is terminal.
Retries stop at retention expiry. Evidence Store's current default retention is
30 days, longer than this retry window; deployments overriding receiver retention
below one day need review. Retries resend exactly the original records and UUIDs.

## Recovery and concurrency

Success removes the envelope/index entries atomically. Failure updates metadata
and scheduling atomically. Both use compare-and-set against the originally read
envelope: a stale worker cannot resurrect a delivered record or overwrite newer
retry state. Multiple replicas can send the same due item; duplicates are safe
because receiver persistence is idempotent. There is no exactly-once HTTP claim,
distributed lease or new locking framework. Crashes before updating retry metadata
can repeat an attempt; expiry still bounds lifetime.

Lost HTTP acknowledgement -> same pair retries -> receiver unchanged -> outbox
acknowledged. Decision stored/application failed -> same pair retries -> decision
unchanged/application inserted. Decision/application writes remain non-atomic.
TraceConflict never counts as delivered; original receiver record remains intact,
and the outbox retains terminal diagnostics until expiry. No replacement UUID is
generated to disguise a conflict.

## Lifecycle and availability

api.lifespan starts recovery at startup and calls close on shutdown. close stops
acceptance and sets a stop event, joining for at most 1.5 seconds. It does not
require pending work to drain. An in-flight iteration may finish; all unacknowledged
entries remain in Redis for another worker/startup. A process killed before local
enqueue acknowledgement has no guaranteed accepted trace. Redis loss or absent
configured persistence remains outside transport guarantees.

Pending/retry/terminal states are test-visible and inspectable in Redis; failures
and retry status have bounded logs without payloads or identity labels. No new
Prometheus labels. Producer order, experiment metadata, strategy selection, SQL,
transaction/commitment semantics and Evidence Store validation remain unchanged.

## Guarantee and limitations

Durable-before-send means acknowledged storage in the configured Redis; existing
AOF/volume configuration determines disk durability. Automatic at-least-once
reattempts operate while retained pending work can be read, until success, terminal
rejection, attempt exhaustion or expiry. It is not an unconditional eventual-
delivery guarantee. Receiver logical storage is idempotent by ID within retention;
overall delivery is not exactly once and pairs are not transactionally atomic.

No outcome linkage/scoring, reward, learner, adaptive selector, graph, gap detector,
candidate generation or promotion. Recommended Pass 7: scoped outcome linkage and
deterministic scoring after reviewing this delivery evidence; not started here.

## Verification

New test_trace_outbox.py covers atomic-script contract behavior through a Redis
model (not actual Lua): enqueue/round trip before send, stable identities, capacity,
classification/backoff, lost acknowledgement, partial-pair retry with TraceStore,
recreated worker recovery, shutdown, expiry, stale-worker CAS, exhaustion and live
SQL/state preservation on full/unavailable outbox. Existing live HTTP failure and
conflict preservation plus Pass 6 causal tests remain passing.

PowerShell environment and bundled interpreter are documented in
STRATEGY_DECISION_TRACE.md. Actual target commands:

```text
# deception_engine
python -m pytest -q -p no:cacheprovider test_trace_outbox.py test_live_trace.py test_decision_trace.py test_action_provenance.py test_strategy_version_integrity.py test_strategy_commitment_preconditions.py test_world_commitments.py test_world_commitment_lifecycle.py
# after additional stale/exhaustion/SQL tests
python -m pytest -q -p no:cacheprovider test_trace_outbox.py test_live_trace.py
# evidence_store
python -m pytest -q -p no:cacheprovider test_strategy_trace_endpoint.py test_strategy_traces.py test_evidence_store.py
```

Results: 75 PASS (49.63s); final outbox/live selection 26 PASS (4.33s); Evidence
Store 24 PASS (1.10s). git diff --check passes. No proxy edits or Go/full-suite run.

docker ps found Evidence Store restarting. An isolated Lua/enqueue/recreated-worker
test was attempted through the already-running engine container, with unique test
namespace and cleanup of only its keys. Configured Redis returned ConnectionError.
No services restarted or volumes changed. REAL REDIS RECOVERY: NOT VERIFIED.

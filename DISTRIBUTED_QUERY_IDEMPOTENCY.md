# Pass 8F — Distributed and Restart-Safe Query Request Idempotency

2026-10-31. IMPLEMENTED / VERIFIED BY TEST / VERIFIED IN RUNTIME for the covered
query paths below. Interrupted work was preserved, reviewed and completed.

## 1. Purpose and preserved work

The previous process-local cache could not recognize completed requests routed to
another process or after an engine restart. Redis now owns duplicate suppression
and completed-response replay. Starting continuation branch was
feature/config-observability, HEAD 3fdba02, clean: the user had committed the earlier
Pass 6–8E and interrupted Pass 8F work. This continuation does not alter Git history.

## 2. Threat/failure model

Duplicate HTTP delivery, concurrent processes and engine process restart are in
scope. Both current proxies issue one HTTP attempt for /decide and private principal
calls, with no application-level retry loop. PostgreSQL simple and MySQL text
requests retain their existing 2.5-second engine budget; no proxy retry was added.
The protection is useful for repetition and future replica routing, not evidence
that the current proxies routinely retry.

## 3. Non-guarantee

This is NOT transactional exactly-once execution. Exposure, synthetic mutations,
principal state, commitments, outbox and replay completion do not share one atomic
transaction. Owner death after side effects can leave an ambiguous execution.
No safe takeover is inferred. Redis loss/eviction/corruption/failover can undermine
retained-state guarantees; no disk-loss or distributed transactional claim.

## 4. Query identity authority

The proxy still creates UUID4 query_execution_id and UTC request_started_at at
request acceptance. Engine replay never regenerates them. The global Redis lookup
member is the execution UUID, independent of SQL/session/scope. Reusing a retained
UUID for another scope/session/protocol conflicts rather than creating another owner.

## 5. Redis authority

Existing redis-deception:6379 DB 0 owns the synchronous replay state, separate from
Evidence Store and trace outbox keys. Keys are:

```text
deception:query-idempotency:v1:records   hash: execution UUID -> canonical JSON
deception:query-idempotency:v1:expiry    sorted set: execution UUID -> expiry ms
deception:query-idempotency:v1:bytes     retained encoded byte accounting
```

No new service/database or feature flag. The existing AOF/volume configuration is
unchanged. The only cached process object is the Redis connection pool/store client.

## 6. State machine and record

Schema idempotency_schema_version=1. Records contain execution UUID, request digest,
owner UUID token, claimed_at/expires_at as Redis UTC epoch milliseconds and status.
COMPLETE adds a bounded JSON replay payload containing exact body bytes, status,
headers and the original private _correlation IDs where present.

| State/result | Creator/transition | Producer/replay semantics | Retention |
| --- | --- | --- | --- |
| OWNER / CLAIMED | One atomic absent-record claimant | Only owner invokes semantic work | Until request start +600s |
| CLAIMED observed | Matching duplicate | Wait boundedly; never execute independently | Original expiry unchanged |
| COMPLETE | Matching owner CAS after final response | Return stored response, no semantic work | Original expiry unchanged |
| AMBIGUOUS | Owner exception or observer of claim aged >=5s | HTTP503, no takeover/producer/replay payload | Original expiry unchanged |
| COMPLETE_UNREPLAYABLE | Owner result cannot fit replay contract/budget | First result preserved; duplicate HTTP503, no producer | Original expiry unchanged |
| CONFLICT | Retained UUID with changed digest | HTTP409, original record untouched | Original expiry unchanged |
| EXPIRED | Absent record but old/far-future request start | HTTP503, no new owner | No admission |
| FULL | No room for new request | HTTP503, no eviction or unprotected execution | Existing entries retained |

The five-second stale threshold is NOT a lease. A stale observer can mark ambiguity;
it cannot become the execution owner. A late original owner cannot overwrite an
AMBIGUOUS record. No second semantic execution follows a timeout.

## 7. Request digest

SHA-256 over sorted canonical JSON containing scope, every supplied body field
except deadline_ms, and the authenticated principal binding key for principal
queries. This includes actual raw/normalized SQL, SQL/fingerprint hints, protocol,
session, database, username, risk/deception/table/transaction context, execution UUID
and request start when supplied. Key order does not matter; other values are exact.
Scope and principal binding distinguish operations even where SQL is identical.

deadline_ms is excluded because each private proxy retry could carry a fresh
transport budget. Headers, authentication proofs, request objects and source network
address are not persisted or digested. Raw SQL/request bodies are not stored
separately: Redis retains only the digest and completed response. This is an
integrity comparison, not authentication or password protection. Canonical digest
input is bounded at192 KiB, accommodating both existing64-KiB query fields/context.

## 8. Atomic claim

One Lua call validates key types/cardinality, removes expired members within the
1,024-record bound, compares existing digest/state, and creates a single owner if
the request is fresh and capacity permits. No GET-then-SET ownership race. Redis
TIME is the clock authority for admission/staleness/expiry. No SCAN/KEYS needed.

## 9. Owner token and completion

Each attempt has an opaque random UUID token. Completion CAS requires the retained
CLAIMED state, original digest and matching token. Expired/missing or stale state
returns STALE. Owner exceptions conservatively mark AMBIGUOUS; normal HTTPException
results may be completed and replayed without repeating the error transition.

If completion storage/acknowledgement fails, the already-produced first response
is preserved. A retained CLAIMED/AMBIGUOUS record suppresses repetition; if the
completion actually persisted, replay succeeds. The uncertainty is logged without
SQL, stored digest, Redis key, credentials or response payload.

## 10. Completed response replay

JSONResponse/Response stores exact bytes as base64 plus status and content headers.
Principal dictionaries and bounded HTTP exceptions serialize as JSON, never pickle
or arbitrary Python objects. Load validates size, structure, status, base64, header
allowlist/content length and any correlation UUIDs. Exact HTTP body/status/content
headers and private IDs survive Redis roundtrip. Python-only provenance objects
are not deserialized or needed by HTTP replay.

The private proxy decoder already limits responses to2 MiB. Replay uses that body
bound,3 MiB per encoded record and32 MiB aggregate encoded storage budget. Ordinary
/decide has no single global response-byte cap, so this does not promise to cache
every possible oversized ordinary response. Oversize/unsupported headers/budget
pressure produces COMPLETE_UNREPLAYABLE, preserving first SQL output and suppressing
duplicate execution. It never claims COMPLETE without replay data. Metadata remains
bounded in the1,024-entry population; no live request is evicted to free payload space.
Only content-type/content-length are replayed; cookies/authentication headers are
not cached. Synthetic response rows are replay data, not real authentication proofs.

## 11. Concurrent duplicates

Matching CLAIMED duplicates poll with50-ms sleeps for at most250ms of wait budget,
using Redis calls with0.2s connect/read timeouts and no timeout retry. Redis work is
offloaded from the async event loop. Completion during this period returns the
same stored result. Otherwise return bounded HTTP503. Network/DNS/OS scheduling is
not an absolute wall-clock guarantee; no proxy timeout was increased.

## 12. Conflicting reuse

Changed request digest under the same retained execution UUID returns
IDEMPOTENCY_CONFLICT/HTTP409. It never executes new semantics, returns an unrelated
old response or overwrites the record. Conflict details expose no SQL or digest.

## 13. In-flight ambiguity

An observer can mark a claim aged five seconds AMBIGUOUS. This includes process
loss, slow/unknown producer outcome and cancellation. No automatic reclaim or action
family safety classifier. A duplicate does not infer that side effects never happened.

## 14. Crash semantics

Before claim acknowledgement, Redis outcome may be unknown; no producer is invoked
without an acknowledged OWNER. After OWNER and before COMPLETE, owner loss is
ambiguous. After COMPLETE, another process/engine restart returns the cached result.
Side effects and completion are not atomic. Existing proxy fallback on engine HTTP
failure remains unchanged; this pass does not coordinate physical backend execution.

## 15. Exact600-second horizon and expiry fence

Expiry is request_started_at +600 seconds, not the last retry or completion time.
CLAIMED, COMPLETE, AMBIGUOUS and UNREPLAYABLE entries share this immutable expiry.
After cleanup, admission still checks the original proxy-authored start: an old
request is EXPIRED and cannot become a new owner. This closes the interrupted
implementation's TTL-only takeover hole, including requests never observed as stale.

Up to30 seconds of future clock skew is accepted; later starts fail admission.
Record expiry follows the accepted proxy timestamp, so a future start cannot leave
a gap between record expiry and age rejection. Shared Redis container keys expire
after631 seconds from newest admission to outlive every allowed-skew member; SET
KEEPTTL preserves that housekeeping TTL during completion/cleanup. Per-member
eligibility/replay remains600 seconds from its proxy timestamp, not631 seconds.

After the horizon, the original request is rejected rather than replayed or executed.
Response replay is not permanent. An internal sender forging a fresh timestamp for
an old UUID after all retained evidence expires violates the proxy identity contract;
no bounded store can remember arbitrary UUID reuse forever. Correct proxy UUID/start
values and reasonable clock synchronization remain assumptions.

## 16. Capacity

1,024 retained records, including incomplete/ambiguous/unreplayable entries, plus
the32-MiB encoded-response accounting budget. Expired members are pruned atomically;
active records are not evicted or silently bypassed. FULL -> HTTP503 before producer.
No automatic tuning or public-traffic sizing claim. Cleanup never deletes principal,
world, mutation or outbox state.

## 17. Process-local cache relationship

Old OrderedDict/Future result cache: REMOVED. query_replay.py remains the coordinator,
not an L1 or fallback result store. Its ContextVar only identifies nested calls in
one owned lifecycle. The lru_cache caches a Redis client/store pool, not responses,
ownership decisions or completed UUIDs. Redis is the sole replay authority.

## 18. Redis failure behavior

Unavailable/corrupt claim state -> internal HTTP503 before semantic execution.
There is no local fallback or unprotected path for correlated requests. Legacy
requests without correlation retain old behavior without a distributed guarantee.
Completion failure preserves the first result but does not invent a durable receipt.
Existing principal failure and ordinary proxy fallback behavior are unchanged.

## 19. Trace and outbox relationship

The first owner retains Pass6B decision-before-producer/application-after-producer
ordering. Completed replay bypasses finalize, registry selection, producer, decision/
application construction and outbox submit. It references the original pair, and
only the outbox retries trace delivery. A trace lost before durable enqueue is not
reconstructed by request replay. Evidence Store identity/index/scoring unchanged.

## 20. Mutable state and principal boundary

Principal guard rechecks deadline, binding and enabled account before lookup and
adds its trusted binding key to the digest. Then one outer claim covers principal
restore, transaction operations, nested /decide, mutation promotion and final save.
The same owned principal request bypasses only its nested /decide replay decorator;
it is not a second request/claim. COMPLETE returns before any of these operations.
Mid-operation crashes remain ambiguous; no new lock/version/transaction model.

Tests prove mutations once, exposure1->2 then stable replay, unchanged commitment
first provenance/revision after receipt, and unchanged IDLE/ACTIVE/FAILED and
COMMIT/ROLLBACK behavior. The observe receipt is still outside query replay, at the
post-write boundary; its existing monotonic semantics remain authoritative.

## 21. PostgreSQL coverage

Correlated ordinary simple queries and supported virtual-principal simple queries
are covered. Tests exercise actual ordinary/principal mutable paths. A live simple
query through the proxy retained matching event/trace linkage and no metadata leak.

## 22. MySQL coverage

Correlated COM_QUERY and supported principal query paths use the same authority.
Both protocol fixtures pass mutation/exposure/principal replay. Live MySQL text
query/event/trace linkage passed using existing container-held credentials.

## 23. Uncovered paths

PG extended/prepared/portal, MySQL binary prepared execution and legacy requests
without execution metadata remain outside scope. Authentication/admin endpoints
and world receipt processing do not gain a speculative separate idempotency system.
No protocol functionality or HTTP retry was added.

## 24. Real Redis and cross-process verification

VERIFIED IN RUNTIME against redis-deception using isolated exact prefixes, cleaned
afterward. Two independent Python processes handled10 matching requests: one semantic
producer call, one real decision/application-builder pair, exact body/header replay.
Concurrent changed semantics yielded one success/one409 and one pair. Distinct IDs
with identical SQL produced two pairs. Owner exit after claim yielded ambiguity
without execution takeover; short retention rejected the old request after cleanup.
Future-clock expiry fencing, capacity2, malformed records and shared-key TTLs passed.

The private multi-process harness uses a safe test producer and real builders,
not physical SQL or production principal keys. Actual daemon/HTTP behavior is
separately exercised by the restart and live wire checks. No Redis/database restart
or aggressive load test. Redis process/disk-loss durability remains NOT VERIFIED.

## 25. Engine restart and local runtime verification

Final-code runtime checkpoint: four isolated requests across PostgreSQL/MySQL
(synthetic update plus read per session), each initially replayed once. COMPLETE
state was read from Redis; the engine container alone was restarted, Redis remained
running. All four replayed exact responses/IDs after readiness, mutation/exposure
and replay-state hashes were unchanged, and indexed trace count stayed four.

Final fixture sessions: pass8f_postgres_f5017c65145c4e9ba6799178d4b49f61 and
pass8f_mysql_9946dccd2ca6405db7bb3df800fc9a4d. Earlier checkpoint sessions were
pass8f_postgres_b6fec956d6094036ae4b9e307b29918b and
pass8f_mysql_b3bc5a9f446e44938af541d6d8889108. They are engineering fixtures, not
attacker research data. Synthetic overlay/exposure keys have existing session TTL;
replay records expire normally; historical traces retain the existing30-day TTL.

On continuation, core dependencies were stopped again. Validated config and started
only those existing stopped containers on retained volumes, then rebuilt/restarted
only the engine. No running Redis/database was restarted. Loki readiness settled;
nginx's proven stale replay backend address was refreshed by config reload, without
container restart or config edits. Final runtime verifier result in AGENTS.md.

## 26. Tests, commands and remaining boundaries

First continuation run:26 PASS/2 FAIL (test fixture incorrectly used .data rather
than .values/.hashes). Corrected fixture snapshot; no assertion weakening. Later
full run had one inherited-deadline fixture failure: direct q() reused an earlier
end/observe HTTP budget. It now starts the same2.5-second budget per modeled RPC;
production timeouts and explicit expired-deadline checks are unchanged.

Bundled Python, PYTHONDONTWRITEBYTECODE=1 and PYTHONPATH pointing to existing ignored
F:\b\Capstone-main\.runtime\pass2-tooling. From deception_engine:

```text
python -m pytest -q -p no:cacheprovider test_query_idempotency.py test_query_correlation.py
python -m pytest -q -p no:cacheprovider test_query_idempotency.py test_query_correlation.py test_live_trace.py test_decision_trace.py test_trace_outbox.py test_world_commitments.py test_world_commitment_lifecycle.py test_principal_state.py test_principal_registry.py test_postgres_error_state.py test_phase_b_invariants.py
```

Observed checkpoints:28 PASS (5.92s),31 PASS (6.12s); broader146 PASS (68.64s),
148 PASS (69.35s); then148 PASS/1 FAIL before the deadline-fixture correction.
The final superseding result is recorded in AGENTS.md. Both proxies' existing
go test ./internal/protocol -count=1 -timeout60s pass (PG1.954s/MySQL1.767s), no Go
source changed. No Evidence Store production/schema changes or full-repository run.

Runtime harness commands and stages:

```text
docker exec -e PYTHONDONTWRITEBYTECODE=1 capstone-main-deception-engine-1 python /opt/honeypot/pass8f_runtime_20261031/validate_query_idempotency_runtime.py
python scripts/validate_query_idempotency_restart.py prepare
python scripts/honeypot.py compose restart deception-engine
python scripts/validate_query_idempotency_restart.py check
python scripts/validate_query_trace_runtime.py --protocol postgres
python scripts/validate_query_trace_runtime.py --protocol mysql
python scripts/verify_runtime.py
```

The harness and two coordinator modules were staged temporarily under shared/ for
the existing read-only /opt/honeypot mount. Only its tracked private keys/files are
cleaned. First post-restart HTTP comparison arrived before readiness; the harness
now waits for /readyz before sending the unchanged checkpoint requests.

DEFERRED: transactional exactly-once during semantic crashes; Redis failure/disk
recovery; public sizing; uncovered protocols; pre-index historical repair;
commitment/exposure outcome deltas; cross-session attribution; calibration; learner,
adaptive selector, graph, candidates and promotion. No scientific-data claim.
Recommended next step: freeze deterministic baseline and begin controlled Internet
deployment/data collection under a separately scoped request. No deployment started.

# Pass 8E — Real Redis and End-to-End Trace Runtime Validation

> Pre-deployment hardening 1 — 2026-10-31: real restricted PG/MySQL runtime grants,
> seed login, HR catalogs/rows/traps, D6 and administrative rejection PASS. Virtual
> principal committed state/exposure survives reconnect on both protocols. Six
> bounded live checks PASS; generic verifier13/13 PASS. No Redis/DB restart, host
> process/file/plugin payload or public exposure. Details and commands in
> BACKEND_PRIVILEGE_CONTAINMENT.md; historical pass records remain below.


> Pass 8F continuation — 2026-10-31: new distributed query-idempotency Lua was
> verified against redis-deception. Two Python processes handling ten duplicates
> produced one producer call/pair and exact replay. Conflicts, owner loss, expiry
> fencing (including clock skew), corruption and capacity passed. Four completed
> engine requests across both protocols replayed exact responses/IDs after an
> engine-only restart with no new state/trace effects. Live PG/MySQL proxy linkage
> passed. See DISTRIBUTED_QUERY_IDEMPOTENCY.md; Pass 8E history below is unchanged.

2026-10-30. COMPLETE for the bounded local validation below. This is engineering
verification using synthetic fixtures, not attacker research data or production sizing.

## 1. Purpose

Pass 8D tested a Python model of Lua contracts. This pass executed the actual Lua
against the existing containerized Redis authorities, exercised HTTP delivery and
the real query path, and corrected one reproduced entry-point defect.

## 2. Environment

Windows workspace F:\b\Capstone-main, branch feature/config-observability, HEAD
ec82fd9 unchanged. Docker Desktop Linux engine 29.8.2. Canonical deterministic
configuration remained unchanged; all future features remain disabled. Existing
Pass 6–8D unstaged/untracked work was preserved. No credentials were changed or
printed, no volumes deleted and no external exposure configured.

## 3. Pre-validation service state

Both Redis containers, Redpanda, PostgreSQL and MySQL were Exited (255).
Evidence Store, scaling and replay engine were restarting. Proxies and deception
engine were running against stopped dependencies. The old deception image had
neither live_trace.py nor trace_outbox.py. Images were from October 28 and did not
validate the current work. Existing Redis volumes were confirmed before startup.

## 4. Configuration checks

CONFIGURATION VALID from config-check; config-status selected
deterministic_rule_based with all six future features disabled. Canonical compose
config --quiet passed with Docker access. The initial sandbox Docker pipe denial
was resolved through approved tool escalation, not a configuration change.

## 5. Startup/rebuild actions

Used the supported launcher only, without down or volume deletion:

```powershell
$py = 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $py scripts/honeypot.py config-check
& $py scripts/honeypot.py config-status
& $py scripts/honeypot.py compose config --quiet
& $py scripts/honeypot.py compose up -d --build
```

The launcher applied its normal remove-orphans behavior; no orphan removal was
reported. It rebuilt the enabled application images, recreated changed services
and started existing dependencies on their existing named volumes. Databases were
started from stopped state, not reset or deliberately restarted for testing.

After diagnosing nginx's cached old replay-engine address, restarted only
sandbox-replay-api. After the entry-point fix, rebuilt/recreated only
deception-engine (the launcher also reran its existing redpanda-init dependency):

```powershell
& $py scripts/honeypot.py compose restart sandbox-replay-api
& $py scripts/honeypot.py compose up -d --build deception-engine
```

## 6. Root cause of prior Evidence Store restart

VERIFIED: bounded logs showed socket.getaddrinfo failure during Runtime's Redis
PING, followed by startup exit. redis-mitre was stopped, leaving its service name
unavailable. Starting existing dependencies restored Evidence Store readiness.
There was no TraceStore/index startup defect and no credential repair.

The post-rebuild replay 502 had a separate operational cause: nginx still tried
the old upstream IP, while Docker DNS resolved the newly recreated backend to a
different IP. Restarting only nginx resolved it. Prometheus and Loki initial
startup failures settled without configuration or code changes.

## 7. Redis topology

| Authority | Existing service | Persistence observed |
| --- | --- | --- |
| Evidence records and TraceStore index | redis-mitre:6379, DB 0 | capstone-main_redismitre at /data; appendonly=no |
| Engine trace outbox | redis-deception:6379, DB 0 | capstone-main_redisdeception at /data; appendonly=yes, appendfsync=always |
| Principal/world state | Same redis-deception authority, separate existing keys | Existing volume/AOF retained |

Both application-side Redis PING checks passed. Evidence Store's actual resolved
EVIDENCE_TTL_SECONDS was 2,592,000 (30 days). No Redis port was published for testing.
RDB/AOF settings were inspected, not altered. Disk durability is not proven by PING.

## 8. Real Lua validation

VERIFIED: actual TraceStore WRITE/READ/ACTIVATE Lua and outbox enqueue/update/prune
scripts ran against real Redis. Index version 1, activation timestamp, epoch and
sequence metadata were returned. Native production HTTP writes/read snapshots also
executed the unmodified production namespace path.

Private tests substituted only literal namespace prefixes in test-process copies
of scripts, and subclassed the existing key helper. Capacity injection was confined
to that isolated process. Production modules, configuration and bounds were unchanged.

## 9. Atomic index validation

VERIFIED: unique decision, application and outcome were retrievable with one index
entry each and sequences 1/2/3. Admission used one actual Redis Lua operation per
record. Normal execution and concurrent writers passed. This does not prove safety
under arbitrary memory exhaustion, corruption, disk loss or Redis failover.

## 10. Replay/conflict validation

VERIFIED: exact replay of all three kinds returned unchanged, preserved sequence
and membership, and did not renew TTL. Conflicting decision content raised
TraceConflict without changing the original record or index. The real HTTP endpoint
returned inserted, unchanged and HTTP 409 for the corresponding pair checks.

## 11. Snapshot/pagination validation

VERIFIED: wrote 132 decisions, captured a boundary, then admitted another decision.
The old boundary returned exactly the original 132 in sequence order, on pages
128 and 4, with no duplicates or omissions. The later admission was excluded.

## 12. Expiry validation

VERIFIED: an isolated one-second TTL expired. Actual enumeration excluded the
record, removed stale membership and reported zero retained decisions. Re-admission
used sequence 2 rather than reusing sequence 1. Production TTL was unchanged.

## 13. Concurrency validation

VERIFIED: 12 same-ID deliveries from four threads yielded one insertion and eleven
unchanged results. Twelve concurrent distinct-ID writes remained distinct; the
retained decision count was 13. This was bounded functional concurrency, not load.

## 14. Outbox Redis validation

VERIFIED: a real envelope was acknowledged DURABLE_PENDING in redis-deception,
reloaded with the original pair/IDs, updated through retry and removed after
delivery. Test outbox keys used a unique namespace and were deleted afterward.

## 15. End-to-end outbox delivery

VERIFIED: a test-only sender returned 503 on the first attempt. Redis retained the
pair with attempt_count=1 and RETRY_PENDING. A new Python worker process read the
same pending entry and delivered over real HTTP, then deliberately discarded the
successful acknowledgement locally. Redis retained retry state. Another new worker
process resent the unchanged pair, received an idempotent acknowledgement and
removed the outbox entry. Injected clock offsets advanced only this test worker's
schedule; no production clock, network or service was disrupted.

Thus real retry, lost-ACK replay, receiver persistence and application-level worker
process recreation are VERIFIED. Recovery of pending work across a restart of the
production daemon container itself was not separately fault-injected.

## 16. Indexed denominator validation

VERIFIED against actual HTTP and Redis: three indexed applications with matching
outcomes for the first and third returned AUTHORITATIVE_INDEXED_SCOPE:

```text
retained applications: 3
applications with outcomes: 2
applications without outcomes: 1
coverage: 0.6666666666666666
eligible applications: 2
eligible coverage: 1.0
```

The second application was BLOCKED, so operational and eligible denominators were
distinct. An empty exact scope returned zero applications and null coverage. An
isolated orphan outcome produced a diagnostic and no denominator application.

## 17. Capacity behavior

Functional capacity bound: VERIFIED using injected isolated capacity 3. Fourth
admission failed with IndexCapacityError; no fourth record or sequence appeared,
and all existing records remained intact. Pagination bound 128: VERIFIED.
Production limit remains 1,000 per kind. Full configured-capacity admission test:
NOT VERIFIED. No live namespace was filled for capacity testing.

## 18. Representative timing

| Synthetic records per kind | Total records | Indexed report elapsed | Timeout/memory error |
| --- | --- | --- | --- |
| 100 | 300 | 0.027229 seconds | None observed |
| 500 | 1,500 | 0.117345 seconds | None observed |

These are one local measurement at each size, using small synthetic records and
the actual indexed_aggregate path. They include Redis snapshot retrieval, parsing
and Python aggregation; they are not worst-case 16-KiB records, HTTP tail latency,
throughput/soak tests, sizing validation or a calibrated pass/fail threshold.

## 19. Restart durability

New test-worker process recovery from retained Redis work: VERIFIED. Engine was
recreated for the real fix without resetting Redis; subsequent daemon delivery
passed. Deliberate Redis process-restart persistence: NOT VERIFIED. Disk disaster
recovery, failover, and unsaved RDB recovery: NOT VERIFIED. No Redis restart was
performed for testing; initial stopped services were started on existing volumes.

## 20. Generic runtime verifier and live query

Initial verifier: 10 of 13 checks passed; replay readiness, Prometheus targets and
Loki readiness initially failed. After settling, only replay remained failed.
Final verify_runtime.py: exit 0, all 13 checks PASS, including nine Prometheus
targets and 53 dashboard expressions. Missing-traffic notes remain informational.
All relevant final Compose services were Up; this is bounded local health, not soak.

The first controlled PostgreSQL SELECT version() succeeded by the existing backend
fallback, but the engine returned HTTP 500 and emitted no strategy trace. After
the minimal fix, the exact same query check passed: real proxy execution ID/start,
decision/application pair, daemon outbox delivery/acknowledgement, retained indexed
application and Redpanda query-event correlation all matched. Private fields were
absent from SQL output. PostgreSQL simple-query runtime linkage is VERIFIED; MySQL
and prepared/extended runtime linkage were not exercised in this pass.

## 21. Fixes required and regression tests

The live failure was DuplicateTimeseries for honeypot_dependency_up. Docker invokes
python api.py, loading it as __main__; producer wrappers import api, which executed
the module a second time and re-registered collectors. A new subprocess regression
executing that entry-point/import sequence failed with the same exception.

Minimal production fix: the script entry point aliases its active module as api
before uvicorn starts. No SQL/strategy/selection/state/scoring semantics changed.
Rebuilt only the engine and reran the exact failing live query successfully. API,
live_trace and trace_outbox container SHA-256 hashes matched working-tree sources;
Evidence Store trace_index hash matched as well.

Test-only repair: test_live_trace now reuses the current Evidence Store Redis/Lua
contract double and exposes its module directory to the test loader. The old
SET-only helper predated Pass 8D and could not model indexed storage.

Automated commands used bundled Python, ignored pass2-tooling PYTHONPATH and
PYTHONDONTWRITEBYTECODE=1:

```text
# deception_engine: before production fix
python -m pytest -q -p no:cacheprovider test_query_correlation.py -k script_entrypoint
# 1 FAILED, 12 deselected; DuplicateTimeseries reproduced

# deception_engine: after fix
python -m pytest -q -p no:cacheprovider test_trace_outbox.py test_live_trace.py test_decision_trace.py test_query_correlation.py
# 46 PASS, 7.36s

# evidence_store: focused regressions
python -m pytest -q -p no:cacheprovider test_trace_index.py test_strategy_traces.py test_strategy_trace_endpoint.py test_strategy_outcomes.py test_outcome_aggregation.py test_query_application_correlation.py test_evidence_store.py
# 71 PASS, 1.31s
```

Runtime harness used scripts/validate_trace_runtime.py plus unchanged
deception_engine/trace_outbox.py, staged temporarily in
shared/pass8e_runtime_20261030 and executed as:

```text
docker exec -e PYTHONDONTWRITEBYTECODE=1 capstone-evidence-store python /opt/honeypot/pass8e_runtime_20261030/validate_trace_runtime.py
python scripts/validate_query_trace_runtime.py
python scripts/verify_runtime.py
```

The read-only container rootfs refused an initial docker cp attempt; no rootfs or
mount setting was changed. The existing /opt/honeypot mount exposes shared/, not
the repository root. Test files were instead staged through that existing mount
and removed afterward. To rerun, stage those same two files in a fresh unique
folder under shared/. The harness cleans only explicitly tracked private Redis
keys; it performs no SCAN/KEYS/FLUSH or principal/world mutation.

## 22. Fixture inventory, cleanup and remaining limits

Private index, expiry, concurrency, timing, capacity and orphan namespaces were
cleaned, as was the private outbox. Three production HTTP-path applications and
their decisions plus two outcomes intentionally retain the normal 30-day TTL.
Their session marker is pass8e_c244619ab80f433c99bc7d88ae62e779 and their synthetic
definition digest is 6b7132a6597baa2c26e125fef4db924d46214f1458c9d6a1ae6584844217df3d.
This digest denotes a validation fixture, not a registered strategy definition.
Exclude this group from research. Application IDs:

```text
d609fabd-e053-43a7-b851-6d7901d27282
86aab90e-8201-439d-a1e5-c564ec94438f
c214f418-7cef-4922-8460-07f2fbde214c
```

Successful live-query validation session: 94b31e92-d4d5-4e86-96fc-c98c873f3fc7;
execution 351631d5-94f7-4cdb-b428-2c8a0dfabca7; decision
cb8c3912-31c9-4741-9512-f813a15fdaed; application
3feb38e3-a04c-49e8-907a-e4d2c37e7e4f. The initial failed trace attempt used session
230b3eec-b618-4721-9af1-661be7df6ecc. These sessions are engineering evidence, not
attacker behavior. No synthetic principal or physical schema/user was created.

Remaining limits: pre-index history, bounded retention/capacity/delivery loss,
unverified Redis restart/disk durability, process-local request replay across
replicas/restarts, uncovered protocols, commitment/exposure deltas, cross-session
delayed outcomes and calibration. Learner, adaptive selector, attack graph and
automatic promotion remain disabled/deferred. No Internet deployment or scientific
effectiveness conclusions. Next recommendation: distributed/restart-safe query
request idempotency. No next-pass implementation started.

# Dynamic D1 — Persistent Experiment Assignment and Idempotency

## Checkpoint identity

```text
Status: VERIFIED
Date: 2026-09-01
Assignment contract: experiment-assignment-v1
Control contract: experiment-control-v1
Experiment: two-stage-factorial-v1
Dynamic execution authority: disabled
Next phase: D2 — attack graph, path registry, and commitment ledger
```

Dynamic Phase D1 establishes the durable research/control boundary required
before any attack path can influence an attacker-facing result. It does not
implement steering, path commitments, or interventions.

## 1. Implemented capability

### Sticky factorial assignment

Each eligible proxy session receives one of the four primary research arms:

| Arm | Assigned mode |
|---|---|
| A | `STATIC_FIXED` |
| B | `ADAPTIVE_STEERING` |
| C | `STATIC_INTERVENTION` |
| D | `ADAPTIVE_STEERING_INTERVENTION` |

Assignment uses HMAC-SHA256 over the normalized protocol and bounded cohort
identity. The HMAC selects the arm deterministically, keeping the same observed
cohort and protocol in the same arm across sessions. Redis persists only the
HMAC, protocol, session identifier, assignment metadata, and control state; it
does not persist the raw source/cohort value.

MITRE-first or legacy events without both a recognized protocol and a source
identity cannot prematurely assign a session. Assignment waits for eligible
proxy evidence.

The assignment write and assignment-index update are one atomic Redis Lua
operation. An existing session assignment is immutable and wins every
concurrent or replayed first-assignment attempt.

### Secret handling

An explicit `EXPERIMENT_ASSIGNMENT_SECRET` must contain at least 32 bytes. If it
is not configured locally, the private persistent Redis volume atomically
provisions and retains a random 256-bit key. The key is never returned by an
API or stored inside assignment records.

AWS must inject a stable secret from its secrets manager for the complete
experiment epoch. Rotating that key changes future cohort assignment and must
therefore occur only between versioned research epochs.

### Persistent operator control

The versioned global control record contains:

```text
safe_mode
forced_arm
monotonic control revision
bounded audit history
actor, reason, before/after state, and audit identity
```

`safe_mode` prevents new world-revision commits without changing an existing
assignment. A forced arm affects only sessions assigned after the override;
existing assignments remain sticky. Safe rollback enables safe mode and forces
new assignments to arm A. Every mutation requires a bounded non-empty actor and
reason and uses Redis compare-and-set semantics.

### World revision and event idempotency

Every persisted assignment starts with `world_revision=0`. The internal D1
event-claim primitive atomically:

1. detects a duplicate before any other transition;
2. rejects a new commit while safe mode is active;
3. rejects an unexpected/stale world revision;
4. stores the event identity once;
5. optionally advances the world revision exactly once; and
6. bounds retained identities to 10,000 per session by default.

This is a control-plane primitive for D2 and later. D1 does not call it to
change live database behavior.

### Failure behavior

If Redis, persisted control state, or secret initialization is unavailable or
invalid:

```text
assignment → non-persistent arm A fallback
effective mode → SAFE_MODE
new dynamic commit → rejected
session-module readiness → degraded when persistence is required
attacker-facing SQL → existing deterministic D0 behavior continues
```

Any runtime persistence error permanently removes dynamic authority from that
process until a controlled restart.

## 2. Internal operator API

The existing session-module state API remains host-loopback bound at port 8003.

```text
GET  /experiment/status
GET  /experiment/assignments?limit=100
GET  /experiment/assignment/{session_id}
POST /experiment/control/safe-mode
POST /experiment/control/forced-arm
POST /experiment/control/rollback
```

Examples:

```json
{
  "enabled": true,
  "actor": "blue-team-operator",
  "reason": "freeze new dynamic decisions"
}
```

```json
{
  "arm": "A",
  "actor": "research-operator",
  "reason": "bounded static-control collection"
}
```

An empty `arm` clears the forced-arm override. Unknown JSON fields, invalid
arms, missing audit fields, malformed JSON, and oversized bodies are rejected.
These endpoints must remain private in AWS.

Every assignment/status response explicitly reports:

```text
dynamic_execution_enabled=false
steering_authority=false
intervention_authority=false
```

## 3. Files and integration

- `session_module/experiment_assignment.py` implements validated in-memory and
  Redis persistence, HMAC assignment, atomic controls, event claims, and safe
  fallback.
- `session_module/authoritative_state.py` projects assignment metadata and
  exposes the bounded internal API without putting Redis on the proxy fast path.
- `session_module/redpanda_consumer.py` initializes the persistent controller.
- `session_module/config.py`, `session_module/requirements.txt`,
  `docker-compose.yml`, and `.env.example` define the bounded runtime settings.
- `session_module/test_experiment_assignment.py` contains focused assignment,
  restart, concurrency, safe-mode, API, cohort-redaction, and replay tests.
- `scripts/predeploy_security_gate.ps1` now verifies persistent dynamic state,
  the zero-authority boundary, and the dynamic kill switch.

Only `session-module` was rebuilt and recreated for live D1 validation. No
proxy, deception-engine, database, public service, cloud resource, or LLM
runtime was changed.

## 4. Verification record

### Automated regression matrix

| Component | Result |
|---|---:|
| D1 focused tests | 11/11 PASS |
| Complete session module | 254/254 PASS plus 10 subtests |
| Deception engine | 58/58 PASS |
| MITRE agent | 32/32 PASS |
| Learning agent | 55/55 PASS |
| Evidence store | 15/15 PASS |
| Sandbox replay and hardening | 15/15 PASS |
| AI Agent v1 | 4/4 PASS |
| LLM Agent v2 | 9/9 PASS |
| MySQL proxy tests and `go vet` | PASS |
| PostgreSQL proxy tests and `go vet` | PASS |
| Scaling agent tests and `go vet` | PASS |

### Exact-final-image live gates

```text
Frozen baseline:
  baseline-1788244003-262e53
  40/40 PASS

Authoritative state:
  PostgreSQL session 17225353-84d0-40af-8cdc-7dc5cec75f2a
  19 verified outcomes
  MySQL session 7cddfc9a-0a37-404a-a71e-c34030b23a1f
  13 verified outcomes
  CRUD, transaction, role/permission, discovery, and consistency PASS

Local predeployment security gate:
  PASS_LOCAL_PREDEPLOY 19/19
  includes persistent dynamic-state authority boundary and kill switch
```

Live restart/idempotency session
`e7c72a42-ed49-4c58-a2b6-809ef8795d94` demonstrated:

```text
assigned arm before restart: C
assigned arm after restart:  C
world revision:              0 → 1 exactly once
first event:                 ACCEPTED
same event replay:           DUPLICATE
new event in safe mode:      SAFE_MODE
safe mode after restart:     preserved
cohort HMAC after restart:   unchanged
```

The pre-validation non-safe control state was restored. Closing PostgreSQL
session `ae934419-4766-4911-9c5c-76f763b8b355` produced a persistent arm-C
assignment under the exact final image with revision zero and no execution
authority.

## 5. D1 acceptance decision

Dynamic Phase D1 is **VERIFIED**:

- one session retains one experiment arm across process restarts;
- cohort assignment is deterministic and raw source identity is not persisted;
- safe mode and operator controls survive restart and are auditable;
- world revisions are monotonic;
- duplicate events cannot advance a revision twice; and
- D0 attacker-facing behavior remains reproducible.

The next permitted phase is D2: define the attack graph, path registry, edge
observability predicates, and append-only commitment ledger. D2 must remain
shadow/non-attacker-facing until its consistency and stale-revision tests pass.


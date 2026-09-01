# Dynamic D0 Baseline Verification

## Checkpoint identity

```text
Status: VERIFIED
Date: 2026-09-01
Repository: F:\b\Capstone-main
Branch / HEAD at start: main / 50617e8
Scope: verification and documentation only
Dynamic execution authority added: none
```

This checkpoint freezes the starting boundary for the two-stage dynamic
roadmap in `TWO_STAGE_DYNAMIC_HONEYPOT_PLAN.md`. It verifies that the existing
asynchronous strategy machinery can recommend and store a future strategy, but
does not yet make a later attacker-facing database result depend on that
recommendation.

The result is deliberately an open-loop baseline. It must not be described as
implemented attack-path steering or intervention.

## 1. Verified open-loop boundary

The current flow is:

```text
structured query/MITRE evidence
        ↓
asynchronous rule or bounded learned selector
        ↓
validated next_strategy_id stored in session projection
        ↓
no proxy request field consumes next_strategy_id
        ↓
attacker-facing response remains query/schema/rule derived
```

Repository evidence:

- `session_module/authoritative_state.py` defines the `next_strategy_*` fields
  separately from the authoritative current strategy and
  `set_next_strategy(...)` only validates and stores the prepared decision.
- `session_module/async_adaptation.py` writes the accepted asynchronous result
  through `set_next_strategy(...)`.
- The MySQL and PostgreSQL proxy deception request structures do not contain a
  current/next strategy, experiment arm, path plan, world revision, or
  intervention field.
- `deception_engine/api.py` still derives response strategy annotations from
  the current SQL category and schema/table mapping. Registry and policy checks
  validate that annotation but do not consume session `next_strategy_*` state.
- Existing asynchronous, shadow-bandit, and learned-selection tests explicitly
  assert that a next strategy may change while the current strategy remains
  `D0`.

Live evidence from session
`67b88200-dc29-49a9-a3a8-9f7d544491c0` confirmed the same boundary:

```text
authoritative current strategy: D0
strategy history:              [D0]
prepared next strategy:        D1
next strategy ready:           true
accepted rule decision:        D1
proxy event strategy field:    empty
attacker-visible behavior:     existing deterministic catalog behavior
```

Therefore:

```text
asynchronous recommendation exists          VERIFIED
bounded learned next-strategy selection     VERIFIED historically/regression
attacker-facing strategy consumption        PENDING
path/world commitment                       PENDING
post-success intervention                   PENDING
```

## 2. Regression and live validation record

Docker Desktop was unavailable at the beginning of the checkpoint. It was
started, and the existing Compose topology was restored without rebuilding
images or changing configuration. All long-running services returned to `Up`;
the sandbox MySQL and PostgreSQL services were healthy.

### Dependency-accurate test suites

| Component | Result |
|---|---:|
| Deception engine | 58/58 PASS |
| Session module | 243/243 PASS |
| MITRE agent | 32/32 PASS |
| Learning agent | 55/55 PASS |
| Evidence store | 15/15 PASS |
| Sandbox replay and hardening | 15/15 PASS |
| AI Agent v1 | 4/4 PASS |
| LLM Agent v2 | 9/9 PASS |
| Controlled workloads | 7/7 PASS |
| Local LLM client/runtime contracts | 17/17 PASS |
| Decoy Generation Agent | 25/25 PASS |
| MySQL proxy Go tests and `go vet` | PASS |
| PostgreSQL proxy Go tests and `go vet` | PASS |
| Scaling agent Go tests and `go vet` | PASS |

Python suites requiring service dependencies were run in their corresponding
repository containers. Go checks used a checkpoint-specific temporary build
cache so host cache cleanup permissions could not produce a false failure.

### Live gates

```text
Frozen baseline:
  run_id: baseline-1788241784-560f72
  result: 40/40 PASS
  coverage: benign MySQL/PostgreSQL, catalog, trap, MITRE, scaling,
            AI Agent v1, and stored evidence linkage

Authoritative state:
  PostgreSQL session: 8dacdbff-83a4-4a5a-b6a7-b6b0bbe05165
  PostgreSQL outcomes: 19 verified
  MySQL session: 49e37163-854f-4013-b38a-c0715f167afa
  MySQL outcomes: 13 verified
  CRUD, rollback, role/permission, schema discovery, and consistency: PASS

Local predeployment security gate:
  result: PASS_LOCAL_PREDEPLOY 17/17
  published services: loopback only
  back-end databases: not published
  isolated networks, container hardening, secret checks, kill switch,
  and alert configuration: PASS
```

Published readiness checks for the deception engine, session/evidence/replay
path, scaling, AI reporting, Redis, Redpanda, and sandbox databases passed.

## 3. Frozen D0 guarantees

The following behavior is the baseline that later dynamic phases must preserve:

- Current SQL responses remain deterministic and do not wait for an adaptive
  decision.
- The database engines and explicit session state remain authoritative.
- Invalid, stale, unavailable, unapproved, or uncalibrated adaptive decisions
  cannot expand the rule-approved action space.
- `D0` remains the universal fail-closed strategy fallback.
- Raw attacker SQL is not introduced into privileged learner decisions.
- The local LLM remains optional, offline/asynchronous, and unnecessary for
  live steering or intervention.
- Existing static behavior remains reproducible through the 40-assertion
  baseline gate.

## 4. Explicitly unimplemented at D0

This checkpoint does not provide:

```text
persistent experiment-arm assignment
restart-safe dynamic session state
duplicate-event protection for new dynamic decisions
attack-path or edge registry
world/commitment ledger
diagnostic-lure evidence for path selection
attacker-facing consumption of a committed path
defender intervention transitions
four-arm factorial experiment
AWS/public deployment
```

PostgreSQL extended-protocol outcome correlation also retains its previously
documented verification boundary; it must not mutate projected authoritative
state until its correlation acceptance tests pass.

## 5. Decision and next phase

Dynamic Phase D0 is **VERIFIED**. The next permitted implementation phase is:

```text
D1 — Persistent experiment assignment and idempotency
```

D1 must establish versioned arm assignment, global operator overrides,
restart-safe assignment/world revision/safe-mode state, and duplicate-event
handling before any attack path receives live execution authority. D1 must not
close the attacker-facing steering loop; that remains ordered after the attack
graph, registry, commitment ledger, and shadow steering checks.


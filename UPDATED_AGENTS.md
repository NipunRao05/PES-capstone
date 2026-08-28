# AGENTS.md

## Project: Hybrid Adaptive & Evolving Database Honeypot Platform

This file is the execution handoff for Codex or any code-generation agent working on this repository.

The project is **not** a chatbot attached to a database honeypot.

The target system is:

> **A state-grounded hybrid adaptive and evolving database honeypot that preserves deterministic rule-based safety and protocol correctness, adapts deception strategies to attacker behavior, learns from historical outcomes, proposes new deception capabilities for human review, safely validates new decoys, scales under attack pressure, replays captured behavior in a sandbox, generates hardening recommendations, and produces evidence-grounded blue-team/research reports.**

The current observed development root is:

```powershell
F:\b\Capstone-main
```

If the repository is opened from a different path, verify the actual project root before running commands.

Always begin with:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git log --oneline -10
docker compose -f docker-compose.yml ps
```

Do not push to GitHub unless the user explicitly asks.


---

# 0. Prototype v1 Review Boundary and Current Execution Rule

This handoff now has **two different timelines** that must not be confused.

## 0.1 Current review milestone — engineering integration

The immediate engineering target is a bounded **Prototype v1 review** covering:

```text
Phase 19.0  hardware/storage/runtime preflight
Phase 19.1  bounded Ornith semantic-proposal prototype
Phase 20    evidence-store verification/completion
Phase 21    replay verification/completion
Phase 22    hardening verification/completion
Phase 23    evidence-grounded Analyst Agent v2
Phase 24    persistent adaptive/learning state
Phase 25    event idempotency/replay safety
Phase 26    operator controls
Phase 27    adaptive observability/Grafana
Phase 28    physical KEDA/HPA verification
```

This is a **review-driven engineering milestone**. It does not prove the research
hypotheses and it does not supersede `Research_Decisions.md`.

## 0.2 Research milestone — after Prototype v1 is frozen

After Phase 28, stop feature expansion and return to the research design:

```text
behavior-model refinement
strategy vs asset vs control separation
Base World v1
session commitment/compatibility overlay
reactive adversary emulator
STATIC-MATCHED vs RULE-ADAPTIVE H1 experiment
learned-selector H2 only if H1 supports adaptation
evolution/LLM H3 only after a measured asset/capability gap
```

Do not use Prototype v1 completion to claim:

```text
AI is better
learned adaptation is better
Ornith is the best model
evolution improves deception
final reward weights are optimized
public deployment is safe/validated
```

## 0.3 Verify before rebuild

Phases 20–22, scaling, evidence, replay, hardening, and some operator/observability
artifacts already exist historically. For every such phase:

```text
inspect current code
run current tests
run bounded live verification
identify the exact missing acceptance item
modify only what is missing
```

Do not create a replacement service merely because the roadmap uses the word
"Agent". Reuse modules/containers that already satisfy the responsibility.

## 0.4 Core availability rule

The following core services must remain independent of the local LLM:

```text
mysqlproxy
pgproxy
deception-engine
session-module
mitre-agent
redpanda
redis services
MySQL/PostgreSQL decoy databases
```

The local LLM is optional and offline/asynchronous. If it cannot load, times out,
OOMs, returns invalid structured output, or is intentionally stopped, the core
honeypot must continue with deterministic behavior.

---

# 1. Non-Negotiable Architecture

The system must remain **hybrid**.

```text
RULES
= safety + protocol correctness + deterministic fallback

STATE
= database/session consistency + authoritative truth

STRATEGY AGENT
= selects the best currently approved deception strategy

LEARNING & POLICY IMPROVEMENT AGENT
= evaluates previous decisions, ranks alternatives, detects policy/action-space gaps, and proposes improvements

GENERATIVE AI
= creates candidate synthetic deception assets offline/asynchronously

BLUE TEAM / HUMAN REVIEW
= approves, rejects, or modifies proposed new deception capabilities

DATABASE ENGINE
= source of truth for SQL/database state

SCALING AGENT
= infrastructure adaptation

REPLAY + HARDENING
= defensive validation loop

ANALYST AGENT
= evidence-grounded blue-team/research reporting
```

The LLM or any AI agent must **never** become the database protocol/state authority.

The attacker-facing query path must stay deterministic and fast.

---

# 2. Core System Loops

## 2.1 Live deception loop

```text
Attacker
   ↓
MySQL/PostgreSQL proxy
   ↓
Deterministic protocol/rule kernel
   ↓
Authoritative database/session state
   ↓
Approved deception strategy
   ↓
Database response
   ↓
Attacker
```

## 2.2 Asynchronous adaptation loop

```text
Query/session event
   ↓
Redpanda
   ↓
Behavior + MITRE profile
   ↓
Rule-approved action space
   ↓
Strategy Agent
   ↓
Next approved strategy
   ↓
Session state
```

The current attacker query must **not wait** for the AI/learning layer.

If the adaptive decision is unavailable, continue with the existing deterministic rule strategy.

## 2.3 Slow learning/evolution loop

```text
Completed sessions
   ↓
Learning & Policy Improvement Agent
   ↓
Decision quality analysis
   ↓
Existing-strategy ranking
   ↓
Counterfactual estimates
   ↓
Action-space gap detection
   ↓
New strategy proposal
   ↓
Blue-team review
   ↓
Validation + sandbox testing
   ↓
Approved strategy registry
   ↓
Future sessions
```

## 2.4 Defensive loop

```text
Evidence
   ↓
Sandbox replay
   ↓
Hardening recommendation
   ↓
Before/after validation
   ↓
Analyst Agent
   ↓
Blue-team / research report
```

## 2.5 Infrastructure loop

```text
Attack pressure / MITRE risk / telemetry
   ↓
Scaling Agent
   ↓
KEDA/HPA
   ↓
Physical honeypot scaling
```

---

# 3. Existing Work That Must Be Preserved

Do not remove or rewrite working deterministic components unless a failing test proves a change is required.

Historically implemented/validated components include:

```text
mysqlproxy
pgproxy
deception-engine
fake/deceptive schema responses
trap-table behavior
deterministic fake data
query/session event production
session-module
MITRE agent
MITRE event/session production
scaling-agent
Prometheus integration
KEDA/HPA structure
AI Agent v1 deterministic incident reporting
hardening phases 1-9
```

Known existing responsibilities:

```text
MySQL/PostgreSQL protocol handling
deterministic deception
request validation
rate limiting
session profiling
MITRE mapping
risk scoring
logical scaling
health/readiness endpoints
```

These become the **deterministic safety kernel and baseline** for future adaptive experiments.

---

# 4. Trust Policy

Do not trust old checkmarks blindly.

Use:

```text
VERIFIED      = proven by current command/test output or committed artifact
CLAIMED       = present in code/docs but not verified in this checkpoint
PENDING       = not implemented
BROKEN        = implemented but currently failing acceptance tests
DO NOT START  = intentionally deferred
```

Before starting a downstream phase, verify all required upstream phases.

If a phase is `CLAIMED`, test it before modifying dependent components.

---

# 5. Mandatory Safety Rules

## 5.1 Never use real production data

Never use:

```text
real citizen data
real healthcare data
real financial/customer records
real passwords
real credentials
real production secrets
real customer PII
```

Use only synthetic/fake/sanitized data.

## 5.2 Never connect attackers to production

Attackers interact only with controlled decoy services.

Captured attacker payloads must never be replayed against production.

## 5.3 Never retaliate

Do not:

```text
scan attackers back
exploit attacker hosts
credential-stuff remote systems
attack remote systems
publish raw secrets
```

## 5.4 Agent authority must remain bounded

No live AI/agent may:

```text
execute arbitrary shell commands
change Docker arbitrarily
change Kubernetes arbitrarily
change cloud firewall rules
expose new network services
connect to production databases
execute unvalidated generated SQL
override safe mode
expand its own action space
deploy new deception strategies without approval
```

## 5.5 Failure must degrade safely

```text
AI unavailable
→ rule-based honeypot continues

AI timeout
→ rule default

invalid AI output
→ reject + rule default

low confidence
→ rule default

LLM hallucination
→ validator rejects

new strategy proposal
→ human approval required
```

Never expose:

```text
LLM errors
API errors
stack traces
prompt text
model names
internal agent state
```

to attackers.

---

# 6. Current Conservative Status

Before Codex starts new development, verify the repository and update this table.
Do not infer `VERIFIED` merely because a container is `Started`.

```text
Database deception layer                 VERIFIED historically
MITRE/session layer                      VERIFIED historically
Hardening phases 1-9                     VERIFIED historically
Logical scaling-agent                    VERIFIED historically
AI Agent v1                              VERIFIED historically
KEDA/HPA structural validation           VERIFIED historically

Full physical KEDA scaling               CLAIMED/VERIFY
Evidence store                           CLAIMED/VERIFY
Sandbox replay engine                    CLAIMED/VERIFY
Hardening recommendation engine          CLAIMED/VERIFY
Persistent scaling/adaptation state      CLAIMED/VERIFY
Prometheus consistency                   CLAIMED/VERIFY
Kafka idempotency/replay safety          CLAIMED/VERIFY
Operator controls                        CLAIMED/VERIFY

Explicit state-grounded deception        VERIFIED (Phase 2, 2026-08-24)
Strategy registry                        VERIFIED (Phase 3, 2026-08-24)
Behavior-state feature model             VERIFIED (Phase 4, 2026-08-24)
Policy guard/action-space engine         VERIFIED (Phase 5, 2026-08-24)
Strategy Agent                           VERIFIED rule-only v1 (Phase 6, 2026-08-24)
Two-speed asynchronous adaptation        VERIFIED (Phase 7, 2026-08-24)
Reward/outcome telemetry                 VERIFIED (Phases 8-9, 2026-08-24)
Contextual bandit                        VERIFIED shadow v1 (Phase 11, 2026-08-24)
Bounded learned strategy selection       VERIFIED safety scaffold (Phase 12, 2026-08-24)
Learning & Policy Improvement Agent      VERIFIED retrospective v1 (Phase 13, 2026-08-24)
Similar-session counterfactual analysis VERIFIED observational v1 (Phase 14, 2026-08-24)
Action-space gap proposals               VERIFIED recommendation v1 (Phase 15, 2026-08-24)
Blue-team review workflow                VERIFIED bounded v1 (Phase 16, 2026-08-25)
Candidate-strategy validation pipeline   VERIFIED deterministic v1 (Phase 17, 2026-08-25)
Local CPU LLM runtime                    VERIFIED Qwen baseline (Phase 18, 2026-08-25)
Decoy Generation Agent                   VERIFIED fail-closed v1 (Phase 19, 2026-08-25)

Phase 19.0 resource/storage preflight     VERIFIED (2026-08-27)
Phase 19.1 Ornith semantic proposal      INCOMPLETE / INTERRUPTED (2026-08-27)
Evidence-store end-to-end chain          CLAIMED/VERIFY (Phase 20)
Replay current acceptance                CLAIMED/VERIFY (Phase 21)
Hardening before/after acceptance        CLAIMED/VERIFY (Phase 22)
Analyst Agent v2                         PENDING (Phase 23)
Durable adaptive/learning state          CLAIMED/VERIFY (Phase 24)
Event idempotency/replay safety          CLAIMED/VERIFY (Phase 25)
Research operator modes                  CLAIMED/VERIFY/REFINE (Phase 26)
Final adaptive Grafana dashboards        PENDING (Phase 27)
Physical KEDA/HPA scale proof            CLAIMED/VERIFY (Phase 28)
Comparative research experiments         PENDING
Public fictional-company deployment      PENDING
Final research validation package        PENDING
```

Prototype v1 completion requires Phase 19.0/19.1 and 20–28 to pass their current
acceptance criteria. It does **not** convert H1/H2/H3 from hypotheses into findings.

---

# 7. Execution Phases

Do the following phases in order.

---

## Phase 0 — Verify Current Checkpoint

### Goal

Prevent new work from building on false assumptions.

### Required checks

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git log --oneline -10
docker compose -f docker-compose.yml ps
```

Verify:

```text
mysqlproxy
pgproxy
deception-engine
redpanda
redis services
session-module
mitre-agent
scaling-agent
ai-agent
evidence-store
sandbox replay
hardening engine
Prometheus
Grafana
KEDA-related artifacts
```

### Output

Create/update:

```text
VALIDATION_CHECKPOINT.md
```

For every component record:

```text
status
files
container/service
test commands
result
known issues
```

### Acceptance

No downstream phase starts until the required upstream services are `VERIFIED` or intentionally marked `PENDING`.

---

## Phase 1 — Freeze the Deterministic Baseline

### Goal

Create a reproducible baseline before adaptive changes.

### Required work

Capture current behavior for:

```text
benign MySQL session
benign PostgreSQL session
catalog enumeration
trap-table interaction
MITRE mapping
scaling decision
AI Agent v1 brief
```

Record:

```text
response output
latency
MITRE events
risk score
trap behavior
current rules
```

### Output

```text
BASELINE_BEHAVIOR.md
baseline test fixtures
```

### Acceptance

Existing rule-based behavior can be reproduced before and after later refactors.

---

## Phase 2 — Build Explicit Authoritative Session/Database State

### Goal

Ensure the honeypot is stateful and internally consistent.

### Required state

Per session track:

```text
session_id
protocol
persona_id
strategy_id
schema_version
database
user
role
permissions
transaction_state
visible_databases
visible_tables
visible_columns
created_objects
modified_objects
dropped_objects
discovered_objects
triggered_traps
MITRE_stage
risk_score
query_count
session_depth
strategy_history
```

Prefer actual isolated MySQL/PostgreSQL instances as the SQL state authority where possible.

### Principle

```text
Do not ask AI to remember the database.
Let the database remember the database.
```

### Required tests

```text
CREATE → SELECT
INSERT → SELECT
UPDATE → SELECT
DROP → SELECT failure
transaction behavior
role/permission behavior
schema discovery
session consistency
```

### Acceptance

No later response contradicts an established database/session fact unless a legitimate database operation changed it.

### Current verification (2026-08-24)

~~~text
VERIFIED
- MySQL/PostgreSQL text/simple query events are emitted after confirmed outcomes.
- MySQL prepared executions also carry confirmed outcomes.
- Backend, deterministic deception, and policy outcomes are authority-labeled.
- Only confirmed successful backend outcomes mutate projected database objects.
- Transaction rollback restores projected state; failed queries do not mutate it.
- Required state is exposed by session-module on a Compose host-loopback API.
- MITRE stage/risk and trap evidence are joined asynchronously by session_id.
- 197 Python tests, both Go proxy suites/vet, and bounded live CRUD/transaction/
  permission/discovery/consistency validation passed.
- Frozen Phase 1 baseline re-passed 40/40 after targeted AI v1 attribution was
  made deterministic.

KNOWN SAFE BOUNDARIES
- The SQL engines remain authoritative; the projector never connects to or
  executes against a database.
- Phase 2 state is bounded in memory; restart persistence remains Phase 24.
- PostgreSQL extended-protocol executions remain explicitly unverified until
  Sync/ReadyForQuery correlation is implemented and cannot mutate projected
  authoritative state.
~~~

---

## Phase 3 — Refactor Existing Rules into a Deception Strategy Registry

### Goal

Preserve existing rules while creating an explicit safe action space.

### Initial strategies

```text
D0 BASELINE
D1 CATALOG_RECON_LURE
D2 BACKUP_LURE
D3 CREDENTIAL_LURE
D4 SENSITIVE_DATA_LURE
D5 PRIVILEGE_LURE
D6 DESTRUCTIVE_OPERATION_SIMULATION
D7 HIGH_INSTRUMENTATION_MODE
```

Do not invent strategies merely to fill this list. Map existing behavior first.

### Strategy metadata

Each strategy should define:

```text
strategy_id
name
description
supported_protocols
required_state
forbidden_state
activation_conditions
compatible_personas
schema_assets
trap_assets
risk_level
resource_cost
validation_version
approval_status
```

### Required behavior

Existing rule behavior remains the default.

Example:

```text
rules determine:
allowed = {D2, D3, D4}
default = D2
```

If any adaptive component fails:

```text
use default D2
```

### Acceptance

All existing regression tests still pass.

### Phase 3 validation record (2026-08-24)

~~~text
Registry version: strategy-registry-v1
Default/fallback: D0 BASELINE

APPROVED:
D0 BASELINE
D1 CATALOG_RECON_LURE
D2 BACKUP_LURE
D3 CREDENTIAL_LURE
D4 SENSITIVE_DATA_LURE
D6 DESTRUCTIVE_OPERATION_SIMULATION

REQUIRES_REVIEW:
D5 PRIVILEGE_LURE
  Existing MITRE rule/profile metadata is present, but standalone
  attacker-facing execution is not verified.

UNMAPPED:
D7 HIGH_INSTRUMENTATION_MODE
  No distinct existing behavior was found, so no strategy was invented.
~~~

Implemented:

- deception_engine/strategies/registry.yaml contains versioned metadata and
  repository evidence for mapped deterministic strategies.
- deception_engine/strategy_registry.py validates IDs, protocols, approval
  states, assets, required/forbidden state, and provides a built-in D0 fallback.
- Missing, invalid, or unapproved strategy IDs resolve to approved D0.
- /decide responses are annotated with strategy_id and
  strategy_registry_version; existing response rows/protocol behavior remains.
- Read-only GET /strategies and GET /strategies/{strategy_id} endpoints expose
  registry status without activating or approving anything.
- Managed INSERT/UPDATE/DELETE classification now precedes generic fake-table
  reads, making the existing D6 simulator reachable.
- No learner, policy guard, dynamic action space, or deployment was added.

Validation:

~~~text
deception-engine tests                  32/32 PASS
session/state tests                     197/197 PASS
MITRE tests                             32/32 PASS
AI Agent v1 tests                       4/4 PASS
MySQL proxy tests + go vet              PASS
PostgreSQL proxy tests + go vet         PASS
authoritative state live validation     PASS (PostgreSQL 19, MySQL 13)
frozen baseline                         PASS 40/40
local predeployment security gate       PASS 17/17
live registry readiness                 ready, degraded=false
~~~

---

## Phase 4 — Build the Behavior-State Feature Model

### Goal

Convert raw hostile activity into structured, safe learning features.

### Example state

```json
{
  "protocol": "postgresql",
  "mitre_stage": "collection",
  "risk_score": 0.81,
  "catalog_enumeration": 7,
  "credential_interest": 2,
  "backup_interest": 6,
  "sensitive_data_interest": 3,
  "privilege_attempts": 1,
  "destructive_attempts": 0,
  "trap_interactions": 1,
  "session_depth": 14,
  "current_strategy": "D1"
}
```

### Candidate deterministic features

```text
catalog_query_count
metadata_query_count
credential_keyword_count
backup_keyword_count
sensitive_table_interest
role_enumeration_count
privilege_escalation_attempts
destructive_query_count
trap_trigger_count
unique_table_count
unique_query_family_count
MITRE technique count
session_duration
queries_per_minute
risk_score
current_strategy
previous_strategies
```

### Security rule

Prefer:

```text
raw SQL
→ parser/classifier
→ structured features
→ learning system
```

Avoid passing unnecessary raw attacker text to privileged agent logic.

### Acceptance

The same deterministic session generates the same normalized behavior state.

### Phase 4 validation record (2026-08-24)

```text
Implementation: session_module/behavior_state.py (behavior-v1), integrated into
session_module/authoritative_state.py.

Inputs: existing structured proxy/session and MITRE events only.
Outputs: deterministic bounded counters, normalized risk, event-time duration,
query rate, MITRE stage/technique count, trap count, and structured strategy history.
Raw SQL, source addresses, database users, and database names are not retained or
returned by the behavior-state API.

Read-only loopback endpoints:
GET /behavior/session/{session_id}
GET /behavior/sessions?limit={1..250}

Validation: session-module 207/207; deception-engine 32/32; MITRE 32/32;
AI Agent v1 4/4; both Go proxy suites and go vet; live authoritative-state
PostgreSQL 19 and MySQL 13 outcomes; frozen baseline
baseline-1787558106-faee3a 40/40; local security gate 17/17.

Runtime change: only session-module was rebuilt/recreated. No new service, port,
database connection, load test, deployment, or GitHub push was introduced.
```

---

## Phase 5 — Build the Policy Guard and Safe Action-Space Engine

### Goal

Ensure live adaptation can only choose approved strategies.

### Input

```text
current session state
behavior state
MITRE state
operator mode
strategy registry
```

### Output

```json
{
  "allowed": ["D2", "D3", "D4"],
  "default": "D2"
}
```

### Hard rule

```text
Rules define what is LEGAL.
The learner decides what is PREFERRED.
The deterministic engine executes it.
```

### Acceptance

An invalid/unapproved strategy can never reach attacker-facing execution.

### Phase 5 validation record (2026-08-24)

```text
Implementation: deception_engine/policy_guard.py (policy-guard-v1), integrated
at the deception-engine response boundary.

Input boundary: structured session, behavior, and MITRE state plus operator mode
and strategy-registry-v1. Raw query text is ignored by action-space evaluation.

Output: deterministic allowed/default strategy IDs with policy and registry
versions. Only approved, protocol-compatible, persona-compatible strategies with
required state and explicit activation rules are allowed. Unapproved, missing,
unsupported, degraded, unsafe-mode, or unknown choices fail closed to D0.

Validation: focused policy/registry/readiness 26/26; deception-engine 44/44;
session-module 207/207; MITRE 32/32; evidence-store 8/8; replay/hardening
15/15; LLM Agent v2 9/9; AI Agent v1 4/4; MySQL, PostgreSQL, and scaling Go
suites plus go vet; live authoritative PostgreSQL 19 and MySQL 13 outcomes;
frozen baseline baseline-1787559435-403780 40/40; local security gate 17/17.

Runtime change: only deception-engine was rebuilt/recreated. No new service,
port, database connection, load test, deployment, or GitHub push was introduced.
```

---

## Phase 6 — Build the Rule-Only Strategy Agent

### Goal

Create the adaptive orchestration component before adding ML.

### Strategy Agent responsibility

```text
read structured behavior state
read allowed actions
read rule defaults
select approved strategy
write strategy decision
```

### Output

```json
{
  "strategy_id": "D2",
  "confidence": 1.0,
  "selector_type": "rule",
  "policy_version": "rule-v1"
}
```

### Important

Version 1 uses existing deterministic rules only.

### Acceptance

Behavior remains equivalent to the current rule engine.

### Phase 6 validation record (2026-08-24)

```text
Implementation: deception_engine/strategy_agent.py (rule-v1), integrated at
the existing deception-engine response boundary.

The agent reads the policy guard action space and selects only its deterministic
default. Output is exactly strategy_id, confidence=1.0, selector_type=rule, and
policy_version=rule-v1. Every selected ID is revalidated by policy-guard-v1;
malformed, forged, unapproved, missing, degraded, safe/static, and unknown-mode
inputs fail closed to D0. Raw query text cannot expand or alter the action space.

Validation: focused selector/guard/registry/readiness 36/36; complete affected
deception-engine suite 54/54; live loopback rule-equivalence D0/D1/D2/D3/D4/D6
6/6; frozen baseline baseline-1787559912-137cbc 40/40.

Runtime change: only deception-engine was rebuilt/recreated. No persistence,
asynchronous processing, ML, new service, port, database connection, load test,
deployment, or GitHub push was introduced.
```

---

## Phase 7 — Add Two-Speed Asynchronous Adaptation

### Goal

Keep SQL responses fast while preparing the next strategy asynchronously.

### Fast path

```text
Query N
→ proxy
→ database/session state
→ current deterministic strategy
→ response
```

### Slow path

```text
Query N event
→ Redpanda
→ behavior state update
→ Strategy Agent
→ next strategy
→ session state
```

### Fallback

If the new strategy is not ready:

```text
continue current/default strategy
```

### Acceptance

Adaptive processing never blocks the current SQL response.

### Phase 7 validation record (2026-08-24)

```text
Implementation: session_module/async_adaptation.py (async-adaptation-v1),
structured-only POST /strategy/next in deception_engine/api.py, and validated
next-strategy fields in the authoritative session projection.

Fast path: proxy /decide behavior and current strategy are unchanged.
Slow path: Redpanda query/MITRE projection performs only a nonblocking bounded
enqueue. One dedicated worker reads a minimized structured snapshot, calls the
rule-v1 selector with a 0.5 second timeout, rejects stale/invalid/unapproved
results, and stores a ready next strategy without changing current strategy.
Queue overflow, timeout, endpoint failure, closed session, or stale state leaves
the current deterministic D0/rule behavior unchanged.

Validation: focused deception endpoint/selector/guard 25/25; focused async,
authoritative-state, and behavior 27/27; complete affected deception-engine
57/57; complete affected session-module 215/215; live Redpanda query event
projected current=D0 and next=D1 with selector=rule and policy=rule-v1.

Runtime change: only deception-engine and session-module were rebuilt/recreated.
No proxy fast-path change, persistence, decision/outcome telemetry, ML, new
service, port, database connection, load test, deployment, or GitHub push was
introduced.
```

---

## Phase 8 — Build Decision and Outcome Telemetry

### Goal

Collect the data required for learning.

### Decision record

```text
decision_id
session_id
timestamp
state_before
allowed_actions
rule_default_action
selected_action
selector_type
confidence
policy_version
```

### Outcome record

```text
queries_after_decision
session_duration_after_decision
new_query_families
new_tables_accessed
new_MITRE_techniques
trap_interactions
attacker_progression
disconnect_time
errors
latency
CPU_cost
memory_cost
```

### Acceptance

Every strategy decision can be linked to what happened afterward.

### Phase 8 validation record (2026-08-24)

```text
Implementation: session_module/strategy_telemetry.py
(strategy-telemetry-v1), integrated with the existing asynchronous selector and
authoritative structured session projection.

Accepted rule-v1 decisions record a bounded decision ID, event timestamp,
minimized state_before, policy-approved allowed/default actions, selection,
confidence, and policy version. Each decision ID has one linked evolving outcome
covering subsequent query/duration/family/table/MITRE/trap/error/progression and
disconnect evidence plus measured strategy-call latency, process CPU time, and
serialized request/response bytes. Read-only loopback endpoints expose decision,
session, and bounded recent telemetry. Raw SQL and fingerprints are not retained.

Outcome observation remains on the asynchronous evidence path and is independent
of adaptation-queue admission. Invalid, unapproved, stale, failed, or malformed
selector responses cannot create accepted decision telemetry. No reward, learner,
persistence, new topic/service/port, database connection, or deployment was added.

Validation: focused deception decision/action-space 13/13; focused telemetry,
adaptation, authoritative-state, and behavior 33/33; complete affected
deception-engine 57/57; complete affected session-module 221/221. Full live
synthetic Redpanda validation produced three accepted rule decisions for session
phase8-final-0ca48d6c; every decision/outcome ID linked, all outcomes finalized on
disconnect, and the first outcome recorded one later query, one new family, one
new table, one new MITRE technique, and attacker progression. Raw SQL keys and
fingerprints were absent from returned telemetry. A closing smoke against the
exact final image (`phase8-closing-cf28afd1`) linked and finalized two decisions
with disconnect evidence and the same raw-SQL/fingerprint-key exclusion.

Runtime change: only deception-engine and session-module were rebuilt/recreated.
Telemetry is deliberately bounded in memory until Phase 24; Phase 9 owns reward
semantics and weights.
```

---

## Phase 9 — Define the Deception Reward Model

### Goal

Measure whether a strategy was useful.

Do not optimize only for session duration.

### Reward dimensions

```text
engagement
intelligence_gain
behavior_novelty
MITRE_progression
meaningful_trap_interaction
latency_penalty
resource_penalty
protocol_error_penalty
state_inconsistency_penalty
safety_penalty
```

### Example conceptual function

```text
Reward =
  engagement
+ intelligence_gain
+ behavior_novelty
+ MITRE_progression
+ meaningful_trap_interaction
- latency
- resource_cost
- protocol_errors
- inconsistencies
- safety_risk
```

Do not freeze numeric weights until calibration tests exist.

### Acceptance

A completed session can produce reproducible per-decision and per-session reward values.

### Phase 9 validation record (2026-08-24)

```text
Implementation: session_module/reward_model.py (deception-reward-v1), computed
on demand from linked strategy-telemetry-v1 records.

Every completed decision produces the ten required deterministic dimensions:
engagement (queries plus duration), intelligence gain, behavior novelty, MITRE
progression, meaningful verified trap interaction, latency, resource, protocol
error, authoritative-state inconsistency, and policy-safety penalties. Completed
session output contains every per-decision vector plus a labeled arithmetic mean
for each numeric dimension. Open outcomes remain PENDING; invalid linkage,
duplicates, cross-session records, missing penalty evidence, negative/nonfinite
values, and forged action spaces fail closed.

GET /reward/decision/{decision_id}
GET /reward/session/{session_id}

No numeric weights were frozen: calibration_status is
REQUIRES_PHASE_10_CALIBRATION, weight_profile is null, and composite_reward is
null. This prevents uncalibrated session duration or any single dimension from
silently becoming the optimization target.

Validation: focused reward/telemetry/adaptation/state 31/31; complete affected
session-module 229/229. Live synthetic Redpanda session phase9-live-0083d098
produced four completed per-decision vectors and one reproducible session vector;
all ten dimensions were present, repeated JSON was identical, protocol error
evidence was counted, state/safety penalties were zero, and raw SQL/fingerprint
evidence was absent.

Runtime change: only session-module was rebuilt/recreated. No calibrated weights,
scalar reward, learner, workload generator, persistence, new topic/service/port,
database connection, deployment, load test, or GitHub push was introduced.
```

---

## Phase 10 — Build Controlled Attack Workloads

### Goal

Solve the cold-start problem without waiting for public internet data.

### Required profiles

```text
BENIGN
CATALOG_RECON
USER_ENUMERATION
BACKUP_SEARCH
CREDENTIAL_SEARCH
SENSITIVE_DATA_SEARCH
PRIVILEGE_PROBING
DESTRUCTIVE_INTENT
MIXED_MULTI_STAGE
```

### Vary

```text
query ordering
database/table names
usernames
timing
attack depth
protocol
session duration
```

### Acceptance

Hundreds/thousands of repeatable controlled sessions can be generated locally without real data.

### Phase 10 validation record (2026-08-24)

```text
Implementation: scripts/controlled_workloads.py (controlled-workload-v1) plus
tests/workloads/test_controlled_workloads.py and operator README.

The offline standard-library generator covers BENIGN, CATALOG_RECON,
USER_ENUMERATION, BACKUP_SEARCH, CREDENTIAL_SEARCH, SENSITIVE_DATA_SEARCH,
PRIVILEGE_PROBING, DESTRUCTIVE_INTENT, and MIXED_MULTI_STAGE. Every labeled
session is guaranteed to contain its defining query families. Same-seed prefixes
are stable and the generator varies query ordering, synthetic databases/tables,
synthetic usernames, bounded timing mode, attack depth, MySQL/PostgreSQL protocol,
and planned duration.

Safety: generation never opens a network connection or executes SQL; every plan
is synthetic and LOCAL_DECOY_ONLY. Queries are individually marked DECOY_ONLY or
SIMULATE_ONLY, all destructive statements are SIMULATE_ONLY, external URLs/IPs,
shell/database command escapes, unsafe identifiers, production scope, multi-query
statements, and out-of-bound timing are rejected. Output creation refuses to
overwrite an existing file. Maximum generation is bounded at 10,000 sessions.

Validation: workload tests 7/7. In-memory validation generated 1,000 sessions
across all nine profiles and both protocols with 208 query-order signatures,
five databases, five usernames, three timing modes, depths 2-7, and durations
41-4,672 ms. Two independently written 1,000-session JSONL plans using seed
20260824 were byte-identical by SHA-256:
c6ba15f67aaa31ed40889c7867dc56921be69b5214f40b4ac8ddcdfce856ac67.

No plan was executed. No application service, container, port, database, reward
weight, learner, deployment, load test, or GitHub push was changed.
```

---

## Phase 11 — Add a Contextual Bandit in Shadow Mode

### Goal

Introduce learning without changing attacker-facing behavior.

### Candidate algorithms

Start simple:

```text
LinUCB
Thompson Sampling
epsilon-greedy contextual policy
```

Do not start with deep reinforcement learning.

### Shadow behavior

```text
Rule selected: D2
Model recommended: D4
Actual execution: D2
```

Record both.

### Acceptance

The model can be evaluated against the rule baseline without controlling the honeypot.

### Phase 11 validation record (2026-08-24)

```text
Implementation: session_module/shadow_bandit.py (linucb-shadow-v1,
bandit-context-v1), integrated only into the existing asynchronous evidence path.

The disjoint LinUCB model reads a deterministic 24-feature vector built from
structured protocol, normalized risk, MITRE stage, bounded behavior counters, and
current approved strategy. Raw SQL, fingerprints, source identities, prompts,
nonfinite values, unsupported protocols, and unapproved current/action-space IDs
are rejected. Recommendations are restricted to policy-allowed actions.

Every accepted strategy telemetry record may now contain shadow-only evidence:
rule_selected, model_recommended, actual_execution, allowed actions, scores,
confidence, context/model versions, and agreement. The model recommendation is
never passed to set_next_strategy; actual_execution remains rule-v1 and the
attacker-facing current strategy is unchanged. Invalid/forged shadow metadata is
discarded without losing rule telemetry. Read-only evaluation endpoints are:

GET /shadow/model
GET /shadow/decision/{decision_id}
GET /shadow/session/{session_id}

Session evaluation reports agreement/disagreement and the observed actual-rule
reward. It explicitly makes no counterfactual performance claim. LinUCB updates
require an explicit versioned CALIBRATED scalar in [-1,1]; Phase 9 currently has
no scalar/weight profile, so runtime updates remain zero. Calibrated fixtures prove
the implementation can learn, but no experimental fixture reaches runtime state.

Validation: focused shadow/adaptation/telemetry/reward/state 38/38; complete
affected session-module 236/236. Live session phase11-live-fb5bfff9 produced
three completed shadow comparisons: the first recorded rule D1, model D0, actual
D1, controls_execution=false, current strategy D0, next rule strategy D1, zero
model updates, completed actual reward, and no retained raw SQL/fingerprint.

Runtime change: only session-module was rebuilt/recreated. No learned action was
executed, no Phase 12 confidence/control path, calibrated runtime reward, model
persistence, new topic/service/port, database connection, deployment, load test,
or GitHub push was introduced.
```

---

## Phase 12 — Enable Bounded Learned Strategy Selection

### Goal

Allow the learner to choose only among rule-approved actions.

### Logic

```text
SAFE_ACTIONS = policy_guard(current_state)

MODEL_CHOICE = learner(context, SAFE_ACTIONS)

if MODEL_CHOICE not in SAFE_ACTIONS:
    use rule default

if confidence < threshold:
    use rule default

if model unavailable:
    use rule default
```

### Acceptance

Learning can change strategy selection, but cannot expand the action space or violate rules.

### Phase 12 validation record (2026-08-24)

```text
Implementation: session_module/learned_selection.py
(bounded-learned-selection-v1), integrated only in the existing asynchronous
next-strategy worker. The database proxy/query fast path is unchanged.

The deterministic policy guard computes the same legal action space for
RULE_ADAPTIVE and HYBRID_LEARNED_ADAPTIVE. Learned execution additionally
requires an exact allowed-action match, same-session evidence, consistent model
scores/recommendation/confidence, a versioned calibrated reward profile, at
least 20 model updates, and confidence >= 0.75. Every condition is redundantly
validated before next-strategy state, telemetry, and reward acceptance.

Rule mode, unavailable/invalid/uncalibrated/low-confidence output, stale state,
action-space expansion, unapproved strategies, cross-session evidence, and
validation failure preserve the deterministic rule default. The Compose runtime
remains RULE_ADAPTIVE by default; its model is UNCALIBRATED with zero updates.

Validation: focused Phase 12/session regressions 45/45; focused policy/strategy
regressions 26/26; complete session-module 243/243; complete deception-engine
58/58. A calibrated deterministic fixture changed next strategy D0 -> D2 while
current strategy remained D0 and produced zero safety penalty. Live hybrid policy
smoke returned allowed D0,D2/default D2. Live Redpanda session
phase12-live-a31b8227 retained current D0 and selected rule D0 with
learned_control=false, model updates=0, and no raw SQL field/text in telemetry.
Frozen baseline baseline-1787565357-1fceb4 passed 40/40; the local
predeployment security gate passed 17/17 with no public exposure.

Runtime change: only deception-engine and session-module were rebuilt/recreated.
No runtime model training, persistence, new service/port/topic, database
connection, proxy change, load test, deployment, or GitHub push was introduced.
```

---

## Phase 13 — Build the Learning & Policy Improvement Agent

### Goal

Perform retrospective analysis after sessions close.

### Responsibilities

For every important strategy decision:

```text
reconstruct session
calculate observed reward
rank currently approved alternatives
compare similar historical sessions
estimate counterfactual alternatives
identify weak policy decisions
identify action-space coverage gaps
```

### The agent may analyze outside the current action space only in offline recommendation mode.

### Acceptance

The agent produces evidence-backed evaluation of past decisions without modifying live policy.

### Phase 13 validation record (2026-08-24)

```text
Implementation: learning_agent/retrospective.py
(retrospective-learning-v1) plus a bounded GET-only internal evidence client and
local CLI. It is a standalone offline module: no new service, port, topic, or
live query-path integration was added.

Inputs are completed strategy-telemetry-v1 records, linked
deception-reward-v1 vectors, and a non-degraded approved strategy-registry-v1
snapshot. The analyzer rejects raw SQL/source/fingerprint fields, incomplete or
cross-session evidence, duplicate IDs/actions, unapproved action spaces, forged
telemetry/decision contracts, nonfinite/fractional counts, and reward vectors
that do not exactly match their observed outcomes.

Output reconstructs the protocol and selected-strategy sequence, evaluates every
decision, identifies important decisions from deterministic evidence, attaches
verified observed reward dimensions, emits policy-review signals, and ranks only
currently allowed/approved alternatives by evidence availability with supporting
decision IDs. No performance rank is claimed because the reward scalar remains
uncalibrated.

Phase boundaries are explicit: similar-session retrieval and counterfactual
estimates return DEFERRED_PHASE_14 with no claim/confidence; coverage-gap and
proposal work returns DEFERRED_PHASE_15. Authority flags prove read-only=true,
live_policy_mutation=false, model_training=false, strategy_activation=false,
and infrastructure_authority=false.

Validation: focused learning-agent tests 8/8. Completed trap session
2b0de47f-b6d6-48d2-9c69-a22efdfaaaea produced deterministic analysis
LA-3efb4787482bb1d27a80a506 for 2/2 decisions, with input SHA-256
0d446d6a52a4dd15fdfe1431ba92a65975c9c87c43fbdc3410435811bd4191aa,
approved-only alternatives, no deterministic policy failure, null
counterfactual claim, and no raw SQL/source/database fields. Benign session
fb76ece8-9dc7-4eea-b88e-bc9685a6af3a also completed; missing evidence was
rejected with a bounded error.
Frozen baseline baseline-1787566523-0fe5cb passed 40/40, and the local
predeployment security gate passed 17/17 with no public exposure.

Runtime change: none. No existing image/service was rebuilt or recreated. No
policy/model write, training, persistence, database connection, shell authority,
load test, deployment, or GitHub push was introduced.
```

---

## Phase 14 — Add Similar-Session Retrieval and Counterfactual Evaluation

### Goal

Estimate what other approved strategies might have done.

### Initial implementation

Start with deterministic/simple methods:

```text
feature normalization
nearest-neighbor retrieval
similar-context grouping
historical reward comparison
```

Add vector/semantic retrieval later only if it improves measurable performance.

### Required wording

Never claim:

```text
D4 definitely would have worked.
```

Use:

```text
D4 is estimated to have performed better under similar contexts.
```

### Acceptance

Counterfactual estimates include uncertainty/confidence and supporting session IDs.

### Phase 14 validation record (2026-08-24)

```text
Implementation: learning_agent/similarity.py (similar-session-v1 and
counterfactual-estimate-v1), a bounded history loader in learning_agent/client.py,
and counterfactual_main.py for offline/local analysis.

Method: independently validated completed telemetry/reward bundles are converted
to deterministic bounded structured features. Same-protocol nearest decisions are
ordered by normalized RMS distance. Only alternatives inside the target decision's
recorded approved action space and actually observed in qualifying historical
decisions may receive an estimate. Estimates include per-dimension uncertainty,
evidence confidence, and supporting session/decision IDs. Unsupported alternatives
remain INSUFFICIENT_EVIDENCE. No causal or uncalibrated composite better/worse claim
is produced.

Validation: learning-agent 21/21 tests passed. Tests cover deterministic bounded
normalization, uncertainty/confidence/support linkage, target exclusion, duplicate,
malformed-target, and forged evidence rejection, same-protocol isolation, incomplete-history filtering,
required non-causal wording, zero live authority, and the Phase 15 boundary. Live
target 2b0de47f-b6d6-48d2-9c69-a22efdfaaaea completed twice as
CF-367a998a4e9c1d786ec44d0d with 2 decisions, 7 completed historical sessions,
10 historical decisions, and one incomplete session explicitly excluded. Missing
target evidence was rejected without internal details.

Runtime change: none. No image/service was rebuilt or recreated. No policy/model
write, training, proposal, strategy activation, database connection, new service,
port, topic, deployment, or GitHub push was introduced. Phase 15 was not started.
```

---

## Phase 15 — Add Action-Space Gap Detection

### Goal

Allow the Learning Agent to recognize when existing strategies appear insufficient.

### Example

```text
Observed behavior:
cloud backup
migration history
S3/export/snapshot interest

Existing strategies:
generic backup lure
credential lure
sensitive-data lure
```

Possible output:

```text
Coverage gap:
cloud-migration deception
```

### Proposal object

```json
{
  "proposal_id": "P017",
  "name": "CLOUD_MIGRATION_LURE",
  "trigger_context": {},
  "reason": "...",
  "supporting_sessions": [],
  "estimated_benefit": 0.21,
  "confidence": 0.69,
  "proposed_assets": [],
  "risks": [],
  "resource_cost": "low",
  "status": "REQUIRES_REVIEW"
}
```

### Hard rule

The Learning Agent may propose new actions.

It may **not activate them**.

### Acceptance

New capabilities always enter a human-review queue.

### Phase 15 validation record (2026-08-24)

```text
Implementation: learning_agent/gap_detection.py (action-space-gap-v1 and
strategy-gap-proposal-v1) plus the bounded gap_main.py CLI.

Classification: deterministic ACTION_SPACE_GAP, NO_GAP_DETECTED, or
INSUFFICIENT_EVIDENCE. A proposal requires a recurring high-diversity structured
behavior pattern not mapped to an existing strategy theme, at least three distinct
comparable completed historical sessions, repeated weak safe outcomes, and evidence
across at least two existing strategies. One weak session, one disconnect, missing
counterfactual support, or insufficient alternatives cannot create a proposal.

Proposal authority: recommendation-only, read-only, non-deployable, and always
REQUIRES_REVIEW. Registry, policy, rules, live responses, strategy activation,
infrastructure, and approval state cannot be changed. Phase 16 review workflow and
queue writes are explicitly NOT_IMPLEMENTED. No LLM is used.

Validation: 10/10 focused Phase 15 tests and 31/31 complete learning-agent tests
passed. Coverage includes GAP/NO_GAP/INSUFFICIENT classification, stable proposal
IDs/evidence under reordered identical history, structured evidence linkage,
confidence cap, known-theme coverage, malformed target/history rejection,
incomplete-history exclusion, zero authority, and preservation of Phase 14 tests.
Live target 2b0de47f-b6d6-48d2-9c69-a22efdfaaaea returned NO_GAP_DETECTED twice
as GD-63f2162c0ec0088673dc4d98 with 2 decisions, 7 completed historical sessions,
1 incomplete session excluded, and 0 proposals. Missing target evidence was rejected.

Runtime change: none. No service/image was rebuilt or recreated. No registry,
policy, rule, database, persistence, service, port, topic, LLM, deployment, or
GitHub push change was introduced. Phase 16 was not started.
```

---

## Phase 16 — Build the Blue-Team Review Workflow

### Goal

Make strategy evolution human-governed.

### Review actions

```text
APPROVE
REJECT
MODIFY
REQUEST_MORE_EVIDENCE
```

### Store

```text
proposal_id
reviewer
timestamp
decision
reason
modifications
```

Blue-team feedback should later become learning data.

### Acceptance

No new strategy can reach `APPROVED` state without explicit review.

### Phase 16 validation record (2026-08-25)

```text
Implementation: learning_agent/review.py (blue-team-review-v1 and bounded-review-
store-v1) plus review_main.py. The explicit state machine maps APPROVE, REJECT,
MODIFY, and REQUEST_MORE_EVIDENCE from REQUIRES_REVIEW to
APPROVED_FOR_VALIDATION, REJECTED, MODIFICATION_REQUESTED, and
MORE_EVIDENCE_REQUIRED respectively. A different second transition is rejected;
an identical repeat is idempotent.

Input boundary: only complete strategy-gap-proposal-v1 ACTION_SPACE_GAP proposals
in REQUIRES_REVIEW state with bounded confidence, supporting session/decision
references, non-deployable human-review authority, and the exact structured schema
are accepted. NO_GAP_DETECTED and INSUFFICIENT_EVIDENCE are not reviewable.
Malformed, forged, oversized, nonfinite, executable-field, missing-reviewer, and
Learning-Agent self-review inputs fail closed.

Audit/authority: the bounded in-memory store preserves an immutable original
proposal snapshot, proposal digest, reviewer, timestamp, decision, reason,
modifications/evidence requests, deterministic review ID, and validation handoff.
APPROVE means only APPROVED_FOR_VALIDATION: deployable=false,
strategy_registry_approved=false, requires_phase_17_validation=true, and
validation_started=false. No registry, policy, rules, live strategy, asset,
infrastructure, or database write authority exists. Durable persistence remains
Phase 24.

Validation: 12/12 focused Phase 16 tests and 43/43 complete learning-agent tests
passed. Deterministic Phase 15 fixture smoke produced APPROVED_FOR_VALIDATION as
RV-090dd92b0c24c20e8017aedd for P-72e05e173839e626f79389bc while remaining
non-deployable and registry-unapproved. NO_GAP contract smoke returned
NOT_REVIEWABLE with review_created=false. The previously verified live NO_GAP
session was unavailable after session-module restart and current telemetry was
empty, consistent with the documented Phase 24 persistence boundary; no live gap
or review item was manufactured. Registry and policy-guard files remained
byte-identical during authority testing.

Runtime change: none. No service/image was rebuilt or recreated. No new database,
Redis schema, Kafka topic, persistence service, authentication system, LLM,
deployment, registry/policy mutation, or GitHub push was introduced. Phase 17 was
not started.
```

---

## Phase 17 — Build the Candidate-Strategy Validation Pipeline

### Goal

Ensure human-approved proposals are still technically/safely validated before deployment.

### Pipeline

```text
proposal
→ schema validation
→ SQL validation
→ type validation
→ PK/FK validation
→ synthetic-data validation
→ security validation
→ sandbox import
→ protocol tests
→ state-consistency tests
→ controlled attack tests
→ approved strategy registry
```

### Automatic rejection

Reject candidates containing:

```text
invalid SQL
broken relationships
real PII
real credentials
real company information
unexpected external URLs
outbound-network requirements
protocol failures
state contradictions
unsafe unsupported operations
```

### Acceptance

Only fully validated strategies may move to the live approved registry.

### Phase 17 validation record (2026-08-25)

```text
Implementation: learning_agent/candidate_validation.py
(candidate-validation-v1) and JSON-stdin validation_main.py.

The validator accepts only an intact Phase 16 APPROVED_FOR_VALIDATION review and
runs twelve ordered, deterministic, fail-closed checks: proposal/review linkage,
registry-compatible metadata, read-only registry collisions, bounded CREATE TABLE
assets, PK/FK/index schema consistency, secret/PII patterns, network/egress,
protocol declarations, authoritative-state contradictions, record-only traps,
resource limits, and sandbox applicability. Invalid required checks are REJECTED.

Metadata-only candidates may be VALIDATED with sandbox NOT_APPLICABLE. Database
asset candidates are VALIDATION_INCOMPLETE because the existing captured-evidence
sandbox has no candidate-import contract; no SQL or fake sandbox evidence is
created. VALIDATED remains non-deployable, registry-unapproved, inactive, and
requires a future registry-promotion workflow.

Validation: 12/12 focused Phase 17 tests and 55/55 complete learning-agent tests.
Deterministic fixture smoke against live read-only strategy-registry-v1 produced
VALIDATED result VAL-a9f989a91768c45ff48dcaa0 for D8 with all eleven required
pre-sandbox stages passing and sandbox NOT_APPLICABLE. Direct in-network sandbox
readiness passed with captured_evidence_only=true and both disposable databases
ready. Registry, policy guard, and authoritative-state files stayed byte-identical.

Runtime change: only the existing sandbox-replay-api Nginx container was restarted
after its cached upstream address returned 502; localhost readiness then passed.
No service/image rebuild, database write, SQL execution, Compose/port/topic change,
registry/policy mutation, activation, deployment, LLM runtime, model download,
Phase 18 work, or GitHub push occurred.
```

---

## Phase 18 — Add a Local CPU LLM Runtime

### Goal

Provide optional generative capabilities without paid API dependency.

### Requirements

Use one shared local inference runtime, for example:

```text
llama.cpp-compatible server
or another local CPU inference server
```

Target initial model class:

```text
1B-4B
quantized
CPU-capable
```

Do not select the final model until benchmarked on the user's machine.

### Resource assumptions

The earlier 64-GB assumption was incorrect for the current college PC. The
measured checkpoint on 2026-08-27 is:

```text
CPU                    Intel Core i7-7700 @ 3.60 GHz
physical cores         4
logical processors     8
installed RAM          31.89 GiB
free RAM at checkpoint 16.76 GiB
GPU                     Intel HD Graphics 630 / no useful discrete inference GPU
Docker-visible memory  15.56 GiB
Docker-visible CPUs    8 logical CPUs
C: free at checkpoint  6.4 GiB
H: free at checkpoint  893.77 GiB
```

These are observations, not permanent guarantees. Re-measure RAM, Docker headroom,
and disk free space before every large-model benchmark.

The adaptive strategy learner should **not require an LLM**.

The LLM is for asynchronous/offline tasks.

### Runtime design

Prefer a persistent inference server:

```text
model resident in RAM
CPU mostly idle when unused
```

Do not load/unload the model for every incident.

### Acceptance

LLM failure has zero impact on attacker-facing honeypot availability.

### Phase 18 validation record (2026-08-25)

```text
Implementation: one optional Ollama 0.32.5 service plus local_llm/config.py and
local_llm/client.py (local-llm-client-v1). No attacker-facing service depends on
the local-ai profile. The service has no host/public port, GPU device, production
credential, Docker/Kubernetes socket, or registry/policy/state authority. Its only
network is internal=true; cloud features are disabled. The pre-provisioned named
model volume is mounted read-only at runtime.

Model: qwen2.5:1.5b-instruct-q4_K_M, Qwen2 family, 1.5B parameter class,
Q4_K_M GGUF, 986,061,892 bytes, Apache-2.0 source metadata. Only this one model
was downloaded. The runtime is limited to 4 CPUs/4 GiB, one loaded model, one
parallel inference, queue depth 2, 2K context, persistent keep-alive, bounded
prompt/output/response sizes, 30-second default client timeout, and no retries.

Validation: 9/9 focused tests passed configuration, disabled mode, health,
readiness/model metadata, bounded generation, oversized/invalid input rejection,
timeout/unavailable/invalid-output handling, queue/concurrency admission, and
read-only authority. Compose validation proved zero dependents, zero host ports,
and internal-only networking.

Live CPU benchmark: four harmless synthetic requests completed. The recorded
three-request benchmark had first latency 6,086.400 ms, warm median 1,592.850 ms,
and 94 generated tokens; the CPU-observation request completed in 1,526.643 ms.
Container memory was 11.56 MiB before model load and 1.066 GiB loaded/idle.
Observed inference CPU peaked at 327.38% under the 4-CPU cap. Ollama reported the
model resident Forever and 100% CPU.

Failure isolation: after local-llm was stopped, the client returned bounded
UNAVAILABLE; deception-engine and session-module stayed ready, and a synthetic
SHOW DATABASES decision still returned the deterministic fake D1 response.
The optional runtime remains stopped after validation while the model volume
persists. No Phase 19 agent, generation workflow, deployment, or GitHub push was
introduced.
```

---

## Phase 19 — Build the Decoy Generation Agent

### Goal

Use generative AI to propose new synthetic deception assets offline.

### Tasks

```text
generate candidate schemas
generate fake rows
generate fictional database names
generate realistic metadata
generate backup/archive structures
generate migration artifacts
generate audit histories
```

### Input

Use:

```text
fictional company persona
current approved schema
identified coverage gap
strategy requirements
```

### Flow

```text
LLM
→ candidate asset
→ validators
→ sandbox DB
→ automated tests
→ approval
→ strategy registry
```

Never:

```text
LLM
→ attacker directly
```

### Acceptance

Generated content is never live until deterministic validation succeeds.

### Phase 19 validation record (2026-08-25)

```text
Implementation: decoy_generation_agent/ (decoy-generation-agent-v1), a local
CLI/library that reuses local_llm/client.py. It accepts only an intact Phase 15
proposal, Phase 16 APPROVED_FOR_VALIDATION review, fictional persona, bounded
strategy requirements, one supported protocol, a synthetic schema summary, and
explicit requested asset types. The deterministic prompt marks all context as
untrusted data and never includes raw SQL, source addresses, credentials, or
fingerprints.

Output is exact-schema JSON with at most 5 tables, 12 columns/table, 20
rows/table, bounded backup/migration/audit metadata, stable content IDs/digests,
model/runtime/settings evidence, and fixed nondeployable authority. Generated
SQL is not accepted from the model; safe CREATE TABLE candidate text is rendered
deterministically only after metadata validation. Secret/PII, external network,
unsafe operation, schema/type/PK/FK/index, duplicate, asset-scope, and resource
checks fail closed. One initial inference plus at most one fresh structural
repair is permitted; invalid output is never inserted into the repair prompt.

Every request passes a Phase 17 approval/registry preflight before inference.
Accepted metadata-only output reaches Phase 17 VALIDATED. Candidate database
assets retain the existing Phase 17 VALIDATION_INCOMPLETE sandbox-import boundary
and are never executed. Registry, policy, strategy selection, session state,
database state, containers, and attacker-facing services remain outside agent
authority.

Validation: Phase 19 focused tests 15/15; directly relevant Phase 17 tests
12/12. The pinned Ollama 0.32.5 / Qwen2.5 1.5B Instruct Q4_K_M live smoke made
exactly three generator requests (schema, backup/migration, audit): 0 first-pass
successes, 3 bounded repairs, 0 candidates ready, and 3 deterministic safe
rejections; median request latency was 48,356.184 ms. Invalid live model output
was not manually repaired and no database asset was executed.

The local-llm container was stopped after the smoke. Deception-engine and
session-module readiness remained true. No attacker-facing rebuild, service,
port, registry/policy change, Phase 20 work, deployment, or GitHub push occurred.
```

---


## Phase 19.0 — Hardware, Storage, and Runtime Preflight

### Goal

Prove that the current college PC can run the selected prototype model without
turning memory pressure, disk exhaustion, or CPU starvation into a hidden system
failure.

This phase performs **no model-quality claim**.

### Current observed machine

Use the measured 2026-08-27 checkpoint as the starting reference only:

```text
Intel Core i7-7700
4 physical cores / 8 logical processors
31.89 GiB installed RAM
16.76 GiB host RAM free at measurement
Intel HD Graphics 630 only
Docker memory ceiling ~15.56 GiB
Docker CPU visibility 8 logical processors
C: only 6.4 GiB free at measurement
H: ~893.77 GiB free at measurement
```

### Mandatory preflight commands

Run with the normal stack started:

```powershell
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem

[PSCustomObject]@{
    Installed_RAM_GB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    Free_RAM_GB      = [math]::Round($os.FreePhysicalMemory * 1KB / 1GB, 2)
    Used_RAM_GB      = [math]::Round(($cs.TotalPhysicalMemory - ($os.FreePhysicalMemory * 1KB)) / 1GB, 2)
}

docker info --format 'Docker CPUs: {{.NCPU}} | Docker memory bytes: {{.MemTotal}}'
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"

Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID,
        @{N="Size_GB";E={[math]::Round($_.Size/1GB,2)}},
        @{N="Free_GB";E={[math]::Round($_.FreeSpace/1GB,2)}}
```

### Storage rule

Do **not** pull the Ornith package into a Docker/Ollama data location backed by
`C:` while `C:` remains near the measured 6.4-GiB free-space state.

Before any pull:

```text
identify the actual Docker/Ollama data root
verify its backing drive
prefer H: or another drive with substantial headroom
leave additional free space for image layers, temporary data, logs, and rollback
```

Do not move Docker/Ollama storage blindly. Record the current location first and
use the platform-supported relocation mechanism.

### Memory/headroom rule

Do not copy the old `4 GiB` profile and do not hard-code the proposed `12–16 GiB`
profile from the earlier plan.

The full Docker memory ceiling at the measured checkpoint is only ~15.56 GiB.
Therefore:

```text
1. measure total running-container memory first
2. preserve memory for the core honeypot services
3. require practical headroom before starting local-ai
4. if headroom is insufficient, do not weaken core service limits
5. do not increase Docker's memory ceiling unless host RAM still preserves a
   safe Windows/host reserve
```

Initial local-AI target:

```text
container memory cap     9 GiB target
raise to 10 GiB only after measured need + sufficient headroom
never assume 12–16 GiB is available under the current Docker ceiling
```

If the full review stack does not leave sufficient headroom, it is acceptable to
run the **offline LLM demonstration sequentially** while preserving the core
honeypot services. Grafana/Loki/sandbox/Kubernetes proof may be demonstrated in
separate bounded segments or from saved validation artifacts.

Never stop the core honeypot merely to make the model fit.

### CPU rule

The i7-7700 has only four physical cores.

Start with:

```text
local-ai CPU cap = 4 logical CPUs
parallel inference = 1
```

Do not default to all eight logical processors. A 6-thread/CPU comparison belongs
in the later resource-feasibility experiment unless Phase 19.1 cannot complete at
all under the 4-CPU cap.

### Acceptance

```text
[x] current host RAM recorded
[x] current Docker memory/CPU ceiling recorded
[x] per-container memory recorded
[x] model-storage backing drive verified
[x] no low-space model pull to C:
[x] core honeypot services remain healthy
[x] a bounded local-AI resource profile is selected from measured headroom
[x] no Docker/WSL limit is increased without preserving host reserve
```

### Phase 19.0 validation record (2026-08-27)

```text
VERIFIED. Host measurements: Intel i7-7700, 4 physical/8 logical CPUs,
31.89 GiB installed RAM, 16.36 GiB free RAM, Intel HD 630, C: 6.29 GiB
free, and H: 893.77 GiB free. Docker exposes 8 CPUs and 15.56 GiB RAM;
the running 25-container stack used approximately 2.102 GiB, leaving
approximately 13.46 GiB inside the Docker ceiling at the snapshot.

The named Phase 18 model volume resolves through /var/lib/docker to
C:\Users\ISFCR\AppData\Local\Docker\wsl\disk\docker_data.vhdx. Because C:
has insufficient safe pull headroom, no Ornith pull was attempted. A read-only,
network-isolated volume inspection found only the preserved 941-MiB Qwen2.5
1.5B Q4_K_M baseline. Phase 19.1 must use an explicit Docker Desktop-supported
H:-backed bind path and recheck disk/RAM immediately before pulling.

Twelve HTTP readiness checks passed for the core, evidence, replay, and
observability services; both Redis services returned PONG; MySQL/PostgreSQL and
Redpanda native health checks passed. Compose validation passed. Focused Phase
18 tests passed 9/9, Phase 19 tests 15/15, and Phase 17 compatibility tests
12/12. The optional local LLM remained stopped, internal-only, unexposed, and
without dependents. No Docker/WSL limit, model, service, image, port, database,
policy, registry, or attacker-facing path was changed.

Selected Phase 19.1 start profile: 4 logical CPUs, 9 GiB memory, one parallel
inference, queue depth 2, 4096 context, 512 output tokens, five-minute keep-alive,
and 300-second bounded benchmark timeout. Detailed evidence is retained in
PHASE_19_0_PREFLIGHT.md and VALIDATION_CHECKPOINT.md.
```

If this phase fails, Phase 19.1 is `BLOCKED_RESOURCE`. Do not paper over the
failure with an unbounded container.

---

## Phase 19.1 — Bounded Ornith Semantic-Proposal Prototype

### Goal

Demonstrate one stronger local-model path for the current engineering review
without pretending the model has been scientifically selected or optimized.

The existing Qwen2.5 1.5B Phase 18/19 path remains the verified baseline and must
not be deleted.

### Prototype model

Use:

```text
runtime/package     Ollama
model tag           ornith-1.5:9b
model class         ~8.95B dense reasoning model
quantization        Q4_K_M
role                offline/asynchronous semantic proposal only
```

This is the **Prototype v1 candidate**, not the final production/research model.
Model comparison remains Phase 31 / the later research-model benchmark.

### Versioning rule

Preserve the old Phase 19 contract/tests. Add a versioned path such as:

```text
legacy candidate contract     decoy-generation-agent-v1
new semantic contract         semantic-proposal-v1
```

Do not rewrite history so that old Qwen validation results appear to have used
Ornith.

### Initial runtime profile for this exact PC

Start conservatively:

```text
CPU cap             4 logical CPUs
memory cap          9 GiB target; max 10 GiB only after Phase 19.0 evidence
parallel            1
queue               2
context             4096
max output          512 tokens initially; <=768 only if required
keep-alive          5 minutes / configurable, not permanent by default
hard client timeout 300 seconds for prototype benchmark only
retries             0 automatic retries beyond the existing bounded workflow
```

Why:

```text
4 physical CPU cores are the main performance bottleneck
Docker currently has only ~15.56 GiB total memory
permanent 9B residency can unnecessarily compete with the rest of the stack
Phase 19.1 is offline and must never set attacker-facing latency
```

If measured prompt size genuinely requires more than 4096 context, document the
reason and increase only to 8192. Do not use the advertised long-context window.

### Sampling starting point

Use the model author's precise-coding settings only as an **initial reproducible
configuration**, not as an optimized project result:

```text
temperature          0.6
top_p                0.95
top_k                20
min_p                 0.0
presence_penalty     0.0
repetition_penalty   1.0
fixed seed           yes, if supported by the runtime path
```

Do not tune parameters extensively during Prototype v1.

### Reasoning-output rule

Ornith is a reasoning model. The project must not persist, expose, test against,
or depend on chain-of-thought/reasoning text.

```text
reasoning text       discard
reasoning as evidence forbidden
reasoning as authority forbidden
reasoning to attacker forbidden
```

If the runtime separates reasoning from final content, ignore the reasoning field.
If it does not, the adapter must prevent `<think>`/reasoning material from entering
validated proposal fields.

### Semantic-proposal contract

Do **not** ask Ornith to generate a complete deployable relational database.

Input:

```text
validated fictional persona summary
Phase 15 evidence/gap proposal
Phase 16 APPROVED_FOR_VALIDATION review context
strategy objective / bounded requirements
existing semantic themes to avoid duplication
synthetic schema summary only where needed
```

LLM final structured output:

```text
proposal_name
theme
narrative
2–5 semantic entities
1–6 semantic relationships
1–6 clues/traps
expected attacker interests
rationale
```

Deterministic code owns:

```text
IDs
authority flags
normalization
schema/model/runtime versions
provenance
digests
validation status
future SQL/type/PK/FK mechanics
```

Full SQL/PK/FK/row construction remains research/H3 work after a measured asset
or capability gap. It is not required for Prototype v1.

### Structured-output requirement

Use runtime-constrained JSON Schema where supported, then validate again with the
application schema.

```text
Ornith
→ constrained structured output
→ application/Pydantic/schema validation
→ deterministic semantic/safety validation
→ NONDEPLOYABLE candidate
```

Do not weaken deterministic validators to improve the apparent pass rate.

### Fixed benchmark set

Run exactly 10 bounded synthetic cases for the review. Keep inputs/version/seed
fixed and save result metadata.

Record for every case:

```text
schema-conforming yes/no
semantic-validator result
safety-validator result
repair used yes/no
latency
prompt/output tokens if available
CPU
peak/loaded RAM
model/runtime/settings version
```

### Mandatory integration acceptance

```text
[ ] Phase 19.0 passed.
[ ] Ornith loads only in the internal/local-AI path.
[ ] No attacker-facing service depends on Ornith.
[ ] Structured JSON Schema constraint is active.
[ ] 10/10 outputs are parser/schema conforming OR any structural failure is
    recorded as a Phase 19.1 defect rather than manually fixed.
[ ] 0 real-secret/PII/external-network candidates are accepted.
[ ] >=1 safe complete Phase15→16→19.1→17 metadata candidate succeeds.
[ ] Candidate remains NONDEPLOYABLE and REGISTRY_UNAPPROVED.
[ ] Reasoning text is absent from persisted proposal/evidence fields.
[ ] Stopping/unloading Ornith leaves core honeypot readiness intact.
[ ] Exact CPU/RAM/latency/settings are recorded.
```

### Quality observation — not final model selection

Also report:

```text
semantic passes / 10
validator rejection reasons
repair rate
median and worst latency
loaded/peak RAM
CPU utilization
```

Do not make `>=8/10` a research-quality claim for this review. If it happens,
record it. If no safe end-to-end candidate succeeds, Phase 19.1 remains `BROKEN`
and Prototype v1 cannot claim successful generative proposal integration.

Phase 20 verification may still be investigated independently, but do not mark
Prototype v1 complete until Phase 19.1's mandatory integration gate passes.

### Interrupted benchmark checkpoint (2026-08-27)

```text
Phase 19.0 resource preflight        VERIFIED
Ornith local provisioning            VERIFIED
Ornith runtime isolation             VERIFIED
Focused Phase 19.1 tests             VERIFIED (18/18)
Preliminary CPU/RAM feasibility      VERIFIED from observed cases
10-case quality benchmark            INCOMPLETE / INTERRUPTED
Phase 19.1 overall acceptance        NOT YET COMPLETE
```

The interrupted fixed run attempted 3 cases: cases 1 and 2 completed their
invocations, case 2 used its single allowed fresh repair, and case 3 had already
started when its disposable client was stopped. Case 3 produced no completed
result; cases 4-10 were not attempted. The wrapper writes only the final
ten-case aggregate, so no aggregate result file exists and the two completed
invocation outputs must not be inferred as passes or failures.

Observed feasibility was approximately 3.9 tokens/second, 368-375% container
CPU, and 6.7-6.95 GiB RAM under the 4-CPU/9-GiB cap. The runtime is stopped and
the H:-backed model remains intact. The authoritative preservation record is
`PHASE_19_1_INTERRUPTED_CHECKPOINT.md`. Resume Phase 19.1 later; Phase 20 was not
started.

---

## Phase 20 — Verify/Complete the Evidence Store

### Goal

Make the current adaptive/deception chain traceable end-to-end without rebuilding
an evidence service that already exists.

### First action — verify/reuse

The repository already has an evidence-store container/artifacts historically.
Start by locating its current implementation, tests, schema, API, persistence,
and live links.

Do not create another evidence service unless current evidence proves the existing
one cannot satisfy the acceptance contract.

### Required current chain

At minimum one bounded evidence bundle must link:

```text
session
→ behavior/MITRE
→ strategy decision
→ outcome/reward
→ retrospective analysis
→ counterfactual analysis
→ gap proposal
→ blue-team review
→ Phase 19.1 semantic proposal
→ Phase 17 validation result
```

Phase 21–23 references may be nullable until those phases are completed.

### Required design

Use stable IDs and explicit versions:

```text
session_id
trace_id / evidence_bundle_id
decision_id
proposal_id
review_id
semantic_proposal_id
validation_id
policy_version
strategy_registry_version
behavior/reward/model/runtime versions
```

The evidence schema must tolerate later research refactors such as strategy-vs-
asset separation. Avoid logic that assumes forever that `D2` means one specific
lure theme.

Evidence storage is an audit/research source, not SQL database-state authority.

### Safety

```text
no production connection
no live infrastructure authority
no model/policy write authority from read-only evidence APIs
bounded/redacted sensitive fields
raw attacker SQL never becomes privileged learner/model instruction by default
```

### Acceptance

```text
[ ] existing evidence implementation inspected and documented
[ ] one read-only end-to-end bundle returned successfully
[ ] stable IDs and version fields link every present artifact
[ ] referential-integrity failures fail closed
[ ] nullable future replay/hardening/analyst links behave correctly
[ ] restart behavior is documented; Phase 24 owns missing durability
[ ] no live policy/registry/database authority is introduced
```

---

## Phase 21 — Verify/Complete the Replay Agent

### Goal

Safely and reproducibly replay captured/synthetic decoy activity in the existing
disposable sandbox.

### First action — verify/reuse

Inspect and test the existing:

```text
sandbox-replay-engine
sandbox-replay-api
sandbox MySQL/PostgreSQL services
existing replay safety/classification modules
```

Do not add a duplicate replay service unless a failing acceptance test requires it.

### Workflow

```text
evidence session
→ safety classification
→ disposable sandbox
→ safe operation executes
→ dangerous/unsupported operation blocks or simulates
→ results linked back to evidence bundle
```

### Hard safety rules

```text
never replay against production
never replay against a public/external target
never execute captured shell/OS/network activity outside the bounded sandbox
never convert blocked dangerous activity into a real external side effect
```

Verify the sandbox network topology itself, not merely configuration intent.

### Acceptance

```text
[ ] one reproducible safe replay from evidence fixture
[ ] same fixture/version → same safety classification
[ ] dangerous operation is blocked/simulated as designed
[ ] sandbox has no production/external target path required by replay
[ ] replay result links to the originating session/evidence bundle
[ ] no new public port or authority is introduced
```

---

## Phase 22 — Verify/Complete the Hardening Agent

### Goal

Convert one replay finding into a defensible before/after mitigation result without
modifying production or attacker-facing infrastructure.

### First action — verify/reuse

Inspect the existing hardening/replay modules and prior validation fixtures before
creating anything new.

### Workflow

```text
replay result
→ weakness
→ deterministic/evidence-grounded candidate mitigation
→ apply only in disposable sandbox
→ replay the identical behavior/fixture
→ compare before/after
→ persist hardening evidence
```

### Required output

```text
issue
supporting evidence
severity/rationale
affected sandbox object
recommended mitigation
before_result
after_result
verification_step
hardening_version
```

### Acceptance

```text
[ ] one controlled weakness reproduced
[ ] one bounded mitigation applied only in sandbox
[ ] identical replay demonstrates before=weak and after=mitigated
[ ] evidence IDs link before/after to the source session/replay
[ ] no production/database/infrastructure write authority exists
```

---

## Phase 23 — Build/Upgrade the Evidence-Grounded Analyst Agent v2

### Goal

Produce a human-readable report whose claims are grounded in the evidence bundle,
with deterministic validation separating observed facts from estimates and missing
evidence.

### First action — inspect existing LLM components

The stack already contains `llm-agent` / `llm-agent-api` style components
historically. Inspect them first.

Do not create a second analyst LLM service if the existing module can be upgraded.
Use the **same local inference runtime/model instance** as Phase 19.1; never run a
separate 9B model for reporting.

### Input boundary

Use a bounded structured evidence bundle, not arbitrary raw logs.

```text
session evidence
MITRE/behavior evidence
strategy decisions/outcomes/reward
scaling evidence where present
replay results
hardening results
learning/counterfactual findings
proposal/review/validation references
operator mode/version evidence
missing-evidence markers
```

### Workflow

```text
evidence store
→ deterministic evidence bundle
→ bounded local LLM narrative
→ deterministic claim/reference validator
→ final report
```

### Analyst task profile for current PC

Reuse Phase 19.0 resource gating and one-at-a-time inference.

Start with:

```text
parallel             1
CPU cap              same bounded local-AI cap
context              4096; increase to 8192 only if measured evidence bundle needs it
output               512–1024 bounded tokens
sampling             low-variance / temperature 0 where supported
fixed seed           where supported
```

Do not run Phase 19.1 generation and Analyst inference concurrently.

### Required claim classes

Every material claim must be one of:

```text
OBSERVED
ESTIMATED
MISSING_EVIDENCE
```

An `ESTIMATED` claim must cite the evidence/analysis object that generated the
estimate. Missing evidence must remain visible instead of being filled by the LLM.

### Acceptance

```text
[ ] one evidence-grounded report generated
[ ] material claims contain evidence/claim references
[ ] unsupported factual claims are rejected or marked missing
[ ] observed vs estimated vs missing is explicit
[ ] repeat run preserves factual conclusions/evidence references
[ ] byte-identical prose is NOT required
[ ] LLM unavailable → bounded deterministic/error-report path
[ ] no second LLM service/model is introduced
```

---

## Phase 24 — Persist Adaptive and Learning State

### Goal

Restarting adaptive services must not erase governance, operator state, processed
IDs, or learned-state metadata.

### Persist only what needs durability

```text
policy version
strategy registry version
bandit/model state
reward-calibration state
approved/candidate strategy metadata
review status
processed event IDs
operator deception mode
scaling mode where applicable
safe-mode state
generative-promotion state
```

Do not persist a second copy of database truth and do not turn the persistence
layer into SQL/state authority.

### Backend rule

Reuse current durable infrastructure where practical. Inspect the existing Redis,
evidence-store, and persistence configuration first. Do not add a new database
merely because persistence is a separate phase.

If Redis is used for state that must survive restart, configure and verify the
appropriate bounded persistence mechanism rather than assuming an in-memory Redis
container is durable.

### Acceptance

```text
[ ] record policy/registry/model/operator state
[ ] restart relevant adaptive services
[ ] state/version restored exactly
[ ] approved/reviewed candidate status preserved
[ ] processed-event identity state preserved for Phase 25
[ ] deterministic database state authority remains MySQL/PostgreSQL/session logic
```

---

## Phase 25 — Add Event Idempotency and Replay Safety

### Goal

Consumer restart or Redpanda replay must not create duplicate logical effects.

### Event identity

New events should receive a unique stable `event_id` at the producer boundary
wherever possible.

Required logical fields:

```text
event_id
session_id
timestamp
event_type
```

Also preserve transport provenance where available:

```text
topic
partition
offset
producer/schema version
```

Do not deduplicate merely by SQL text or coarse timestamp. The same attacker may
legitimately issue the same SQL twice.

### Duplicate events must not

```text
double-count reward
double-trigger strategy transition
double-update bandit/model state
double-create proposal/review artifact
double-trigger scaling logical effect
double-create evidence links
```

### Acceptance

```text
[ ] controlled duplicate-event fixture processed
[ ] exactly one logical effect is present
[ ] consumer restart + replay preserves exactly-one logical effect
[ ] processed IDs survive restart through Phase 24 persistence
[ ] transport offset provenance is available for debugging/audit
```

Do not claim broker-level exactly-once semantics unless the broker configuration
actually proves it. The required claim is **application-level idempotent logical
effects**.

---

## Phase 26 — Add/Refine Operator Control Modes

### Goal

Allow an operator to immediately constrain deception/learning behavior without
confusing adaptive policy controls with scaling controls.

### Deception modes

```text
STATIC
RULE_ADAPTIVE
HYBRID_SHADOW
HYBRID_ACTIVE
SAFE_MODE
```

### Separate control dimensions

Do not overload one `safe_mode` variable for unrelated systems.

Prefer explicit state such as:

```text
deception_mode:
    STATIC | RULE_ADAPTIVE | HYBRID_SHADOW | HYBRID_ACTIVE | SAFE_MODE

scaling_mode:
    AUTO | MANUAL | DISABLED

generative_promotion:
    ENABLED | DISABLED
```

Existing scaling safe/manual behavior must not silently change meaning.

### Mode semantics

`STATIC`:

```text
no behavior-driven strategy change
fixed deterministic strategy/configuration
```

`RULE_ADAPTIVE`:

```text
policy guard + deterministic rule selector
no learned control
```

`HYBRID_SHADOW`:

```text
rule execution
learned recommendation recorded only
```

`HYBRID_ACTIVE`:

```text
learned selection permitted only when the existing Phase 12 bounded eligibility
and confidence/calibration checks pass
otherwise deterministic rule fallback
```

`SAFE_MODE`:

```text
deterministic safe/rule behavior only
no learned live influence
no generative promotion
no autonomous action-space expansion
honeypot remains online
```

Scaling remains governed by `scaling_mode`, not implicitly disabled by deception
SAFE_MODE unless explicitly configured.

### Versioned rollback

Persist:

```text
policy_version
strategy_registry_version
model_version
operator-state version
```

Support bounded rollback to a previously verified version.

### Acceptance

```text
[ ] every deception mode visible through bounded operator API/config
[ ] mode state persists across restart
[ ] invalid/unknown mode fails closed
[ ] HYBRID_ACTIVE falls back safely when learner is ineligible
[ ] SAFE_MODE keeps honeypot available
[ ] generative promotion disabled in SAFE_MODE
[ ] scaling control remains independently testable
[ ] version rollback demonstrated without public exposure
```

---

## Phase 27 — Add Adaptive Observability and Grafana

### Goal

Make the engineering chain understandable to a reviewer without tying dashboards
to a soon-to-be-refactored strategy taxonomy.

### Metrics

#### Adaptation

```text
strategy_selected_total
strategy_changes_total
strategy_reward / reward dimensions where appropriate
strategy_confidence
rule_fallback_total
adaptation_failure/block reason counts
```

#### Learning

```text
model/shadow recommendation count
shadow disagreement rate
model update count
counterfactual estimate count/confidence summary
```

#### Evolution/governance

```text
strategy_proposals_total
review_outcomes_total
validation_outcomes_total
semantic_proposals_total
new_strategy_promotions_total (may remain zero)
```

#### AI

```text
inference_count
inference_latency
inference_failures
queue/admission failures
fallback/unavailable count
loaded RAM / peak RAM where available
CPU utilization where available
model/runtime version
```

#### Defensive loop

```text
replay_total
replay_blocked_total
hardening_findings_total
hardening_verified_total
```

#### Operator

```text
current deception_mode
current scaling_mode
generative_promotion state
```

### Label/cardinality rule

Use version/strategy/selector/status labels that survive future registry changes.
Do not put high-cardinality `session_id`, `decision_id`, raw SQL, or proposal text
into Prometheus labels. Use the evidence store for per-session drill-down.

### Minimum panels

```text
sessions
MITRE/risk
current strategy/selector
strategy transitions
rule vs learner/shadow
a reward summary plus access to vector dimensions
fallbacks/blocked adaptations
gap proposals/review outcomes
AI requests/latency/failures/CPU/RAM
replay/hardening events
operator modes
```

One reviewer should be able to follow at a high level:

```text
session
→ behavior/MITRE
→ strategy decision
→ learning/gap
→ review
→ semantic proposal
→ validation
```

### Acceptance

```text
[ ] required metrics exposed without high-cardinality leakage
[ ] dashboards render from current metrics
[ ] model/runtime versions visible
[ ] operator mode visible
[ ] at least one saved dashboard/screenshot/validation artifact captured
[ ] dashboard does not require Ornith to be running
```

---

## Phase 28 — Re-Verify Physical Kubernetes/KEDA Scaling

### Goal

Re-establish current proof of actual physical scaling. Do not redesign a scaling
algorithm that has already been demonstrated historically unless current
verification fails.

### Required proof

Capture from the current repository/image/version:

```text
current Git commit
Kubernetes deployment/workload
KEDA ScaledObject
HPA
external metric / trigger evidence
scaling-agent decision
pod count before
pressure event
1 → 2/3 pod scale-up
safe scale-down
all relevant timestamps
```

### Experimental isolation

Do not run Ornith inference during the KEDA scaling verification unless the test
explicitly studies AI resource pressure. The Phase 28 target is honeypot scaling,
not local-LLM contention.

If a prior saved artifact is shown during the review, also run a bounded current
readiness/structural check so stale evidence is not presented as current proof.

### Acceptance

```text
[ ] ScaledObject ready
[ ] HPA/metric readable
[ ] actual pod count increases under controlled pressure
[ ] actual pod count safely decreases after stabilization
[ ] scaling-agent decision/timestamps captured
[ ] no model/LLM resource load contaminates the proof
```

### Prototype v1 stop rule

After Phase 28 passes:

```text
STOP feature expansion
freeze/tag or commit the Prototype v1 checkpoint
update VALIDATION_CHECKPOINT.md
update AGENTS.md status table
prepare review artifacts
return to Research_Decisions.md for H1-facing redesign/experiments
```

Do not begin Phases 29–35 merely because Phase 28 is complete.

---

## Phase 29 — Comparative Research Experiments

Run four configurations.

### Experiment A — Static

```text
fixed deception persona
no strategy adaptation
```

### Experiment B — Rule-Adaptive

```text
existing deterministic rule-based adaptation
```

### Experiment C — Hybrid Learned-Adaptive

```text
rules define safe options
learner selects among them
```

### Experiment D — Evolving

```text
hybrid adaptive
+
human-approved new strategies derived from observed gaps
```

### Compare

```text
session duration
queries/session
unique SQL operations
objects explored
MITRE techniques
MITRE progression
trap interaction
intelligence richness
protocol error rate
state inconsistency
early disconnect
latency p50/p95/p99
CPU
RAM
AI inference count
reward
resource cost
```

### Acceptance

Results are reproducible from saved workloads and configuration versions.

---

## Phase 30 — Learning-Agent Evaluation

### Decision quality

Measure:

```text
average reward
rule vs learner reward
shadow disagreement
counterfactual estimated gain
confidence calibration
```

### Proposal quality

Measure:

```text
proposals generated
approval rate
rejection rate
modification rate
validated-strategy success rate
```

### Acceptance

The project can quantify whether the Learning Agent improves deception and whether its proposed new strategies are useful to defenders.

---

## Phase 31 — Explicit Resource Feasibility Experiment

### Goal

Prove the system remains practical on commodity CPU hardware.

Compare:

```text
Rules only
Rules + small ML
Rules + ML + local LLM offline
Full hybrid system
```

Measure:

```text
CPU
RAM
response latency
throughput
AI inference latency
queue depth
```

### Acceptance

Attacker-facing response latency remains dominated by deterministic processing, not LLM inference.

---

## Phase 32 — Security Gate Before Public Internet Exposure

Mandatory checks:

```text
No real database connected
No real customer data
No real credentials
Only fictional company/brand
Only honeypot ports public
Grafana private
Prometheus private
Redis private
Redpanda private
AI/LLM runtime private
control APIs private
sandbox APIs private
egress restricted
budget controls enabled
kill switch ready
logs redact secrets
safe mode tested
```

### Acceptance

Only controlled honeypot endpoints are publicly reachable.

---

## Phase 33 — Fictional-Company Public Deployment

Public:

```text
fake company website
fake MySQL endpoint
fake PostgreSQL endpoint
```

Private/internal:

```text
Redpanda
Redis
Prometheus
Grafana
AI/LLM runtime
learning services
sandbox replay
operator controls
```

### Post-deployment checks

```text
public honeypot reachable
admin services not public
scanner connection captured
session created
MITRE generated
strategy selected
evidence stored
alerts work
kill switch works
budget controls work
```

---

## Phase 34 — Real-World Observation Period

Suggested progression:

```text
24-hour safety run
3-day initial dataset
7-day main dataset
optional extended window
```

Monitor:

```text
cost
disk usage
outbound traffic
alerts
DLQ
session count
trap triggers
strategy rewards
AI usage
learning proposals
```

Stop immediately for:

```text
unexpected outbound traffic
cloud abuse warning
cost spike
real secret capture
service compromise
uncontrolled scaling
```

---

## Phase 35 — Final Research Validation Package

Required experiment areas:

```text
1. Deception realism/state consistency
2. MITRE detection accuracy
3. Static vs rule-adaptive vs learned-adaptive vs evolving deception
4. Autoscaling effectiveness
5. Learning-agent decision quality
6. Action-space proposal quality
7. Sandbox replay and hardening loop
8. Analyst-agent grounding/reproducibility
9. Restart/replay/idempotency reliability
10. Resource feasibility
11. Real-world anonymized dataset summary
```

Required artifacts:

```text
experiment inputs
session evidence
strategy decisions
reward logs
policy versions
model versions
blue-team review decisions
replay results
hardening results
AI inputs/outputs
graphs
tables
methodology
limitations
```

---

# 8. Suggested Repository Structure

Do not create unnecessary microservices. Some items should remain modules.

```text
Capstone-main/

mysqlproxy/
pgproxy/
deception_engine/
session_module/
mitre_agent/
scaling_agent/

adaptive_deception/
    state/
    features/
    strategies/
    strategy_registry/
    policy_guard/
    strategy_agent/

learning_agent/
    reward/
    bandit/
    counterfactual/
    similarity/
    gap_detection/
    proposals/

decoy_generation_agent/
    prompts/
    generator/
    validators/
    schemas/

evidence_store/

sandbox_replay/

hardening_agent/

analyst_agent/
    prompts/
    validators/
    reports/

operator_control/

tests/
    baseline/
    state/
    strategies/
    learning/
    replay/
    safety/
    performance/
    experiments/
```

A practical first deployment should add as few new containers as possible.

Suggested new services:

```text
adaptive-deception
learning-agent
local-llm
```

Reuse/verify existing services where possible.

---

# 9. Agent Definitions

## 9.1 MITRE Agent

Type:

```text
deterministic
```

Responsibility:

```text
classify behavior
emit MITRE evidence
```

Must remain independent of LLM availability.

## 9.2 Scaling Agent

Type:

```text
deterministic control agent
```

Responsibility:

```text
resource/scaling decisions
```

Must not be controlled by LLM output.

## 9.3 Strategy Agent

Type:

```text
bounded live adaptive agent
```

Responsibility:

```text
choose among currently approved deception strategies
```

Cannot expand action space.

## 9.4 Learning & Policy Improvement Agent

Type:

```text
offline/retrospective learning agent
```

Responsibilities:

```text
evaluate decisions
rank existing alternatives
estimate counterfactuals
measure rewards
identify policy weaknesses
detect action-space gaps
propose new deception strategies
prepare evidence for blue-team review
```

Can reason outside the current action space only in proposal mode.

Cannot deploy proposals.

## 9.5 Decoy Generation Agent

Type:

```text
offline generative agent
```

Responsibility:

```text
generate candidate synthetic deception assets
```

Cannot publish directly.

## 9.6 Replay Agent

Type:

```text
bounded orchestration agent
```

Responsibility:

```text
coordinate safe sandbox replay
```

Actual execution policy remains deterministic.

## 9.7 Hardening Agent

Type:

```text
bounded defensive validation agent
```

Responsibility:

```text
derive candidate mitigations
apply only in sandbox
replay before/after
```

## 9.8 Analyst Agent

Type:

```text
evidence-grounded reporting agent
```

Responsibility:

```text
assemble evidence
detect missing evidence
generate human-readable report
validate claims
```

No infrastructure authority.

---

# 10. Resource Rules

The project must remain feasible on the **measured college PC**, not on the earlier
64-GB assumption.

## 10.1 Current measured hardware reference

Observed 2026-08-27:

```text
CPU                    Intel Core i7-7700 @ 3.60 GHz
physical cores         4
logical processors     8
installed RAM          31.89 GiB
free RAM               16.76 GiB at measurement time
GPU                     Intel HD Graphics 630 / no useful discrete inference GPU
Docker memory ceiling  ~15.56 GiB
Docker CPUs            8 logical CPUs
C: free                 6.4 GiB at measurement time
H: free                 893.77 GiB at measurement time
```

Never assume the free-RAM or free-disk figures remain unchanged. Re-measure before
large-model work.

## 10.2 Architectural allocation

```text
live adaptive strategy selection
→ deterministic rules + small ML/statistics

LLM semantic proposal
→ offline/asynchronous only

LLM analyst narrative
→ offline/on-demand only

one shared local inference runtime
→ never one LLM per agent
```

## 10.3 Prototype model policy

```text
Qwen2.5 1.5B Q4_K_M
→ preserve as verified Phase 18/19 baseline

Ornith-1.5 9B Q4_K_M
→ Prototype v1 candidate for Phase 19.1/23
→ not final model selection
```

Do not attempt Ornith 35B/397B as the local Prototype v1 model on this machine.
12–14B-class alternatives belong only in the later model/resource benchmark if
9B quality proves insufficient and measured headroom allows it.

## 10.4 Local-AI concurrency/resource policy

Start Prototype v1 with:

```text
CPU cap             4 logical CPUs
memory cap          9 GiB target, 10 GiB only after measured justification
parallel inference  1
queue                2
context              4096 default
output               bounded
keep-alive           short/configurable
```

Do not run semantic proposal and Analyst generation simultaneously.

Do not let model memory pressure force the project to shut down its core honeypot.
Sequential review segments are preferable to unsafe oversubscription.

## 10.5 Storage policy

The measured `C:` free space is too low for casual multi-GB model pulls.

```text
verify Docker/Ollama data root before pull
prefer H: or another high-headroom location
record model digest/version
retain Qwen baseline without duplicate unnecessary downloads
```

## 10.6 Required AI guards

```text
max concurrent inference = 1
bounded queue
context/output limits
timeouts
no unbounded automatic retries
circuit breaker / unavailable fallback
CPU/RAM limits
internal-only network
no GPU assumption
no Docker/Kubernetes socket authority
no production credentials
```

LLM downtime, timeout, OOM, invalid output, or model removal must not affect
attacker-facing service availability.

---

# 11. Research Baselines

Never remove the rule engine because it is a required scientific baseline.

Required comparison:

```text
STATIC
vs
RULE_ADAPTIVE
vs
HYBRID_LEARNED_ADAPTIVE
vs
EVOLVING
```

The project must be able to run all modes from operator configuration.

---

# 12. Git Policy

Do not push partial/broken work.

For each phase:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"

& $git status --short

# run phase acceptance tests

& $git add <changed-files>
& $git commit -m "<clear phase message>"

# push only when user explicitly approves
```

Suggested commit style:

```text
Verify current project checkpoint
Freeze deterministic honeypot baseline
Add authoritative deception session state
Refactor rules into deception strategy registry
Add behavior-state feature extraction
Add adaptive policy guard
Add rule-based strategy agent
Add asynchronous deception adaptation
Add strategy reward telemetry
Add controlled attack workloads
Add contextual bandit shadow mode
Enable bounded learned strategy selection
Add retrospective learning agent
Add deception coverage-gap proposals
Add blue-team strategy review workflow
Add strategy validation pipeline
Add local CPU LLM runtime
Add validated synthetic decoy generation
Add bounded Ornith semantic proposal prototype
Complete evidence store
Complete sandbox replay agent
Add hardening validation agent
Add evidence-grounded analyst agent
Persist adaptive policy state
Add event idempotency safeguards
Add adaptive operator controls
Add adaptive deception dashboards
Validate KEDA physical scaling
Add comparative adaptive honeypot experiments
Add resource feasibility experiments
Prepare public honeypot security gate
Add final research validation artifacts
```

---

# 13. Immediate Next Step for Codex

## 13.1 Current verified engineering checkpoint

~~~text
Phase 0  — Verify Current Checkpoint                VERIFIED
Phase 1  — Freeze Deterministic Baseline            VERIFIED
Phase 2  — Authoritative State                      VERIFIED
Phase 3  — Strategy Registry                        VERIFIED
Phase 4  — Behavior-State Feature Model             VERIFIED
Phase 5  — Policy Guard and Safe Action Space       VERIFIED
Phase 6  — Rule-Only Strategy Agent                 VERIFIED
Phase 7  — Two-Speed Asynchronous Adaptation        VERIFIED
Phase 8  — Decision and Outcome Telemetry           VERIFIED
Phase 9  — Deception Reward Model                   VERIFIED
Phase 10 — Controlled Attack Workloads              VERIFIED
Phase 11 — Contextual Bandit Shadow Mode            VERIFIED scaffold
Phase 12 — Bounded Learned Strategy Selection       VERIFIED safety scaffold
Phase 13 — Learning & Policy Improvement Agent      VERIFIED
Phase 14 — Similar-Session Counterfactuals          VERIFIED observational
Phase 15 — Action-Space Gap Detection               VERIFIED
Phase 16 — Blue-Team Review Workflow                VERIFIED
Phase 17 — Candidate-Strategy Validation            VERIFIED
Phase 18 — Local CPU LLM Runtime / Qwen baseline    VERIFIED
Phase 19 — Decoy Generation Agent / fail-closed v1  VERIFIED

Phase 19.0 — Hardware/storage/runtime preflight      VERIFIED
Phase 19.1 — Ornith semantic proposal                INCOMPLETE / INTERRUPTED; RESUME NEXT
Phase 20   — Evidence store                          CLAIMED/VERIFY
Phase 21   — Replay                                  CLAIMED/VERIFY
Phase 22   — Hardening                               CLAIMED/VERIFY
Phase 23   — Analyst Agent v2                        PENDING
Phase 24   — Persistent adaptive state               CLAIMED/VERIFY
Phase 25   — Idempotency/replay safety               CLAIMED/VERIFY
Phase 26   — Operator modes                          CLAIMED/VERIFY/REFINE
Phase 27   — Adaptive Grafana                        PENDING
Phase 28   — Physical KEDA/HPA                       CLAIMED/VERIFY
~~~

## 13.2 Mandatory first commands

Before changing code:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git branch --show-current
& $git rev-parse HEAD
& $git log --oneline -20

docker compose -f docker-compose.yml ps

docker info --format 'Docker CPUs: {{.NCPU}} | Docker memory bytes: {{.MemTotal}}'
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
```

Update `VALIDATION_CHECKPOINT.md` with the current commit, test counts, container
state, Docker resource ceiling, and any uncommitted files.

A `Started` container is not automatically `VERIFIED`; run its readiness/tests.

## 13.3 Ordered Prototype v1 work

Do this order:

```text
1. Phase 19.0 resource/storage/runtime preflight
2. Phase 19.1 bounded Ornith semantic proposal
3. Phase 20 verify/complete evidence store
4. Phase 21 verify/complete replay
5. Phase 22 verify/complete hardening
6. Phase 23 upgrade/reuse Analyst Agent v2
7. Phase 24 persist adaptive/learning/operator state
8. Phase 25 add application-level idempotency
9. Phase 26 refine separated operator modes
10. Phase 27 adaptive observability/Grafana
11. Phase 28 re-verify physical KEDA/HPA scaling
12. STOP and freeze Prototype v1
```

For Phases 20–22 and 28, **verify before modifying**.

Do not start with Phase 20 merely because the old roadmap said it was next. The
resource-gated Phase 19.0/19.1 review work now comes first.

## 13.4 Integrated review demonstration

Do not force every heavy subsystem to run simultaneously on this 4-core/32-GB PC.
A valid review may combine short live segments with saved, versioned validation
artifacts.

Recommended sequence:

```text
A. Core live honeypot
   MySQL/PostgreSQL response
   session + MITRE/behavior
   strategy decision + evidence

B. Governed evolution fixture
   use a prevalidated multi-session Phase 15 fixture
   → Phase 16 review
   → Phase 19.1 Ornith semantic proposal
   → Phase 17 deterministic validation

C. Defensive loop
   evidence bundle
   → replay
   → hardening before/after

D. Analyst
   reuse the same Ornith runtime sequentially
   → evidence-grounded report

E. Operator/observability
   SAFE_MODE and normal mode transition
   Grafana/Prometheus evidence

F. Scaling
   run/show bounded KEDA physical proof separately
   do not contaminate it with Ornith inference

G. Failure isolation
   stop/unload local LLM
   prove core attacker-facing honeypot still works
```

Do not manufacture a new action-space gap from one live review session. The Phase
15 proposal shown to a reviewer must come from evidence that satisfies the actual
gap thresholds or from an explicitly labeled deterministic test fixture.

## 13.5 Prototype v1 completion claim

When Phase 19.0/19.1 and 20–28 pass, the safe claim is:

> **The base engineering prototype is integration-complete through the bounded evolution-proposal and validation workflow. It integrates deterministic database deception and state, MITRE profiling, bounded adaptive/learning infrastructure, human-governed offline generative proposals, evidence persistence, replay/hardening, operator controls, observability, and scaling. Comparative effectiveness, learned-policy benefit, full evolved relational-asset construction, and final model optimization remain research-stage work.**

Do not call Ornith the final model and do not call the research complete.

## 13.6 What happens after Phase 28

Return to `Research_Decisions.md`.

The next research work is not Phase 32/public deployment. It is the H1-facing
research redesign and experiment sequence. Preserve the verified Prototype v1
checkpoint as an engineering baseline while doing that work.

---

# 14. Final Completion Definition

## 14.1 Prototype v1 is not research completion

Passing Phase 19.0/19.1 and 20–28 proves engineering integration and current
acceptance tests. It does not prove H1/H2/H3, model optimality, evolution benefit,
or public-deployment safety.

## 14.2 Final research completion

The project is complete for research purposes when all of the following are demonstrated:

```text
[ ] Fake MySQL/PostgreSQL endpoints are reachable.
[ ] Real databases are isolated.
[ ] Database/session state remains coherent.
[ ] Existing deterministic rules remain functional.
[ ] Rules are represented as approved deception strategies.
[ ] Behavior state is derived deterministically.
[ ] Policy guard defines a safe action space.
[ ] Strategy Agent adapts future interactions asynchronously.
[ ] Current SQL responses do not wait for AI.
[ ] Strategy decisions and outcomes are recorded.
[ ] Reward is reproducible.
[ ] Controlled cold-start workloads exist.
[ ] Contextual bandit works in shadow mode.
[ ] Bounded learned selection works only inside approved actions.
[ ] Learning Agent evaluates previous decisions.
[ ] Counterfactual estimates include uncertainty.
[ ] Learning Agent detects action-space gaps.
[ ] New strategies require blue-team review.
[ ] Approved strategies pass deterministic validation.
[ ] Local CPU LLM can generate candidate synthetic decoys offline.
[ ] LLM failure does not affect honeypot availability.
[ ] Evidence store provides end-to-end traceability.
[ ] Sandbox replay safely evaluates captured behavior.
[ ] Hardening recommendations are validated before/after.
[ ] Analyst Agent produces evidence-grounded reports.
[ ] Adaptive policy state survives restart.
[ ] Duplicate events are idempotent.
[ ] Operator can force STATIC/RULE/HYBRID/SAFE modes.
[ ] Grafana shows adaptation and learning behavior.
[ ] Kubernetes/KEDA physically scales under pressure.
[ ] Static vs rule-adaptive vs learned-adaptive vs evolving experiments are complete.
[ ] CPU/RAM/resource feasibility is documented.
[ ] Public deployment passes security gate.
[ ] Real-world sessions are anonymized and safely collected.
[ ] Final graphs, datasets, policy versions, prompts, model versions, and reports exist for the paper.
```

The defining principle of the final system is:

```text
Rules = safety and correctness
State = truth and consistency
Learning = strategy optimization
Generative AI = offline creativity
Human review = action-space governance
Database engine = authoritative state
```

The system must remain useful and safe even when every AI/learning component is disabled.

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
Strategy registry                        PENDING
Behavior-state feature model             PENDING
Policy guard/action-space engine         PENDING
Strategy Agent                           PENDING
Reward/outcome telemetry                 PENDING
Contextual bandit                        PENDING
Learning & Policy Improvement Agent      PENDING
Action-space gap proposals               PENDING
Blue-team review workflow                PENDING
Candidate-strategy validation pipeline   PENDING
Local CPU LLM runtime                    PENDING
Decoy Generation Agent                   PENDING
Analyst Agent v2                         PENDING
Final adaptive Grafana dashboards        PENDING
Comparative research experiments         PENDING
Public fictional-company deployment      PENDING
Final research validation package        PENDING
```

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

Current hardware constraint:

```text
No GPU
64 GB RAM total
~30 GB usually available
```

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

---

## Phase 20 — Verify/Complete the Evidence Store

### Goal

Make every incident traceable end-to-end.

Store per session:

```text
session_id
trace_id
protocol
source identifier/anonymized source
fingerprint
queries
responses
session state
MITRE events
risk
strategy decisions
strategy rewards
scaling events
trap events
AI Agent v1 output
replay results
hardening findings
learning-agent analysis
proposal IDs
analyst report IDs
```

### Acceptance

One session can be traced from connection to deception decision to replay/hardening/report.

---

## Phase 21 — Verify/Build the Replay Agent

### Goal

Safely test captured attacker behavior in a disposable environment.

### Workflow

```text
load session
→ classify queries
→ apply safety policy
→ safe operations execute in sandbox
→ dangerous operations block/simulate
→ collect results
```

### Never

Replay attacker content against production.

### Acceptance

Captured behavior can be replayed safely and reproducibly.

---

## Phase 22 — Verify/Build the Hardening Agent

### Goal

Convert replay findings into validated defensive improvements.

### Workflow

```text
replay result
→ weakness
→ candidate hardening
→ apply only in sandbox
→ replay same behavior
→ compare before/after
```

### Output

```text
issue
evidence
severity
affected_object
recommended_fix
before_result
after_result
verification_step
```

### Acceptance

At least one controlled weakness demonstrates:

```text
before = vulnerable/weak
after = mitigated
```

---

## Phase 23 — Build/Upgrade the Analyst Agent

### Goal

Replace a simple LLM summary with an evidence-grounded analyst workflow.

### Inputs

```text
session evidence
MITRE
deception decisions
strategy effectiveness
scaling events
replay results
hardening results
learning-agent findings
new deception proposals
```

### Workflow

```text
load evidence
→ identify missing evidence
→ construct structured evidence bundle
→ local LLM generates narrative
→ deterministic claim validation
→ final report
```

### Report sections

```text
executive summary
technical timeline
attacker behavior
MITRE mapping
deception strategies used
why strategies changed
strategy effectiveness
scaling response
sandbox results
hardening results
learning-agent findings
new strategy proposals
missing evidence
operator actions
research summary
```

### Acceptance

Unsupported claims are explicitly marked instead of hallucinated.

---

## Phase 24 — Persist Adaptation and Learning State

### Goal

Container/service restarts must not erase adaptation state.

Persist:

```text
strategy scores
bandit parameters
policy version
reward history
approved strategies
candidate strategies
review status
processed event IDs
manual/safe-mode state
```

### Acceptance

Restarting adaptive services preserves learned state and policy versions.

---

## Phase 25 — Add Kafka/Redpanda Idempotency and Replay Safety

### Goal

Duplicate events must not corrupt learning or scaling.

Required fields:

```text
event_id
session_id
timestamp
event_type
```

Duplicate events must not:

```text
double-count rewards
double-trigger strategy changes
double-update the learner
double-scale infrastructure
```

### Acceptance

Consumer restarts/replayed events remain idempotent.

---

## Phase 26 — Add Operator Control Modes

### Required modes

```text
STATIC
RULE_ADAPTIVE
HYBRID_SHADOW
HYBRID_ACTIVE
SAFE_MODE
```

### Behavior

`SAFE_MODE`:

```text
rules only
no learned live selection
no new adaptive changes
no generative promotion
```

### Versioned rollback

Persist:

```text
policy_version
strategy_registry_version
model_version
```

Support rollback:

```text
v8 → v7
```

### Acceptance

Operator can immediately disable learning/adaptation without taking the honeypot offline.

---

## Phase 27 — Add Adaptive Observability and Grafana

### Metrics

#### Adaptation

```text
strategy_selected_total
strategy_changes_total
strategy_reward
strategy_confidence
rule_fallback_total
```

#### Learning

```text
policy_updates_total
shadow_disagreement_rate
counterfactual_gain_estimate
```

#### Evolution

```text
strategy_proposals_total
proposals_approved
proposals_rejected
new_strategy_promotions
```

#### AI

```text
inference_count
inference_latency
inference_failures
fallback_count
CPU
RAM
```

### Grafana panels

```text
sessions
current strategies
strategy transitions
MITRE progression
reward by strategy
trap rate by strategy
rule vs model disagreement
model confidence
fallback rate
new proposals
blue-team decisions
AI resource usage
```

### Acceptance

An operator can visually follow:

```text
attack
→ MITRE
→ strategy choice
→ reward
→ learning
→ proposal
→ approval
```

---

## Phase 28 — Verify Physical Kubernetes/KEDA Scaling

### Goal

Prove actual infrastructure scaling, not only logical replica targets.

### Acceptance

Real Kubernetes workload demonstrates:

```text
1 → 2/3 pods under pressure
and
safe scale-down after stabilization
```

Capture:

```text
HPA
KEDA metric
pod count
scaling-agent decision
timestamps
```

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

The project must remain feasible without a GPU.

Design assumptions:

```text
64 GB RAM total
~30 GB typically free
CPU-only AI inference
```

Therefore:

```text
live adaptive strategy selection
→ small ML/statistics, not LLM

LLM synthetic generation
→ asynchronous/offline

LLM reporting
→ per incident/on demand

one shared local inference runtime
→ not one LLM per agent
```

Add:

```text
max AI calls/session
max concurrent inference
bounded queue
context/output limits
timeouts
circuit breaker
CPU/RAM limits
```

LLM downtime must not affect attacker-facing service.

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

Current verified checkpoint:

~~~text
Phase 0 — Verify Current Checkpoint              VERIFIED
Phase 1 — Freeze Deterministic Baseline          VERIFIED
Phase 2 — Authoritative State                    VERIFIED
~~~

Start **Phase 3 — Strategy Registry** only.

Do **not** start Phase 4 or any learning, local LLM, deployment, or public
exposure work until Phase 3 passes its acceptance checks. After Phase 3, follow
the existing ordered roadmap without skipping upstream verification.

---

# 14. Final Completion Definition

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

# Two-Stage Dynamic Honeypot Implementation Plan

## Document status

```text
Status: APPROVED DESIGN / NOT YET IMPLEMENTED
Created: 2026-08-31
Primary implementation order: PostgreSQL first, MySQL parity second
Live AI requirement: none
Local hardware target: Intel i7-7700, 32 GB RAM, no GPU
Cloud target: one cost-bounded AWS deployment with internal experiment assignment
```

This document is the implementation and research handoff for the next dynamic
honeypot work. It does not claim that path steering, world commitments, or
defensive interventions already exist. Current verified repository behavior and
historical phase results remain recorded in `AGENTS.md` and
`VALIDATION_CHECKPOINT.md`.

---

## 1. Executive decision

The project will implement a **two-stage, commitment-preserving adaptive
relational honeypot**.

```text
STAGE 1 — STEERING
Use structured attacker behavior to select one still-uncommitted,
internally consistent attack path.

STAGE 2 — INTERVENTION
After the attacker establishes progress, optionally apply one explicit,
realistic defensive state transition and observe the fallback strategy.
```

The central research question is:

> Can behavior-aware, late-bound attack-path steering lead attackers deeper
> than a statically configured relational attack graph, and can subsequent
> controlled defensive interventions reveal fallback behavior that passive
> observation misses?

The primary contribution is not dynamic table or row generation. The base
fictional database remains stable. Adaptation controls only facts the attacker
has not yet observed, such as whether a credential, role, permission boundary,
procedure route, or decoy namespace is viable.

### Definitions

| Property | Meaning in this project |
|---|---|
| Static | Attack-path outcomes are fixed before the session starts. |
| Dynamic | An unobserved graph-edge outcome may be resolved during the session. |
| Adaptive | Resolution depends on bounded structured attacker behavior. |
| Steering | The system selects a relevant still-consistent attack path. |
| Intervention | A later explicit defender event changes committed security state. |
| Learning | Bounded models rank only rule-approved paths or interventions. |
| Evolving | Human-reviewed evidence adds graph edges, path templates, or interventions between versioned experiment epochs. |

### Explicit non-goals for v1

Do not make any of the following part of the initial implementation:

- dynamic creation of attacker-facing tables or rows;
- complete parallel possible-world database replicas;
- one database container per attacker;
- deep reinforcement learning, graph neural networks, or a POMDP;
- autonomous strategy generation or promotion;
- live LLM calls in the attacker query path;
- retaliation, attacker scanning, or execution outside controlled decoys.

---

## 2. Why this fits the existing repository

The repository already contains most of the required control plane:

- authoritative session projection;
- structured behavior and MITRE state;
- strategy registry and safe action-space enforcement;
- asynchronous next-strategy computation;
- decision/outcome telemetry and reward vectors;
- shadow LinUCB and bounded learned selection;
- retrospective and similar-session analysis;
- action-space gap proposals;
- blue-team review and deterministic candidate validation;
- an offline optional local-LLM path;
- persistent evidence storage;
- sandbox replay, hardening, observability, and scaling foundations.

The principal missing runtime link is important:

> The current asynchronous next-strategy value is stored and measured, but the
> proxies do not feed it back into later `/decide` requests, and `/decide`
> continues to derive response behavior from SQL patterns and table mappings.

Therefore the first dynamic milestone is not another learner. It is a safe,
versioned connection between a future decision and a later attacker-visible
response.

The current `ExposureTracker` is also global-depth based. It advances every
session through depths 1–3 and is not path-aware. It may remain as an engagement
feature, but it must no longer be the sole authority for deep-path reachability.

---

## 3. Target architecture

### 3.1 End-to-end flow

```text
Fixed fictional PostgreSQL/MySQL world
        ↓
Identical initial diagnostic clues
        ↓
Attacker query N receives deterministic response
        ↓
Confirmed query/session/MITRE event
        ↓
Behavior state + attack-graph evidence update
        ↓
Asynchronous steering eligibility and safe action space
        ↓
Atomic path-plan commitment for world revision R+1
        ↓
Future untested edge reflects the selected path
        ↓
Attacker establishes path progress
        ↓
Observation/dwell window
        ↓
Asynchronous intervention eligibility and safe action space
        ↓
Atomic defensive event for a future world revision
        ↓
Observe fallback behavior and finalize outcomes
```

The current SQL response must never wait for steering, learning, or the LLM.
Every asynchronous decision is valid only for a future query and an exact
expected world revision.

### 3.2 Separate policy domains

Do not overload the existing D0–D6 IDs. Maintain three distinct registries:

1. **Content strategy registry** — existing D0–D6 classifications and assets.
2. **Path registry** — unobserved attack-path plans P0–P4.
3. **Intervention registry** — explicit defender actions I0–I3.

The policy guard must return separate legal action spaces:

```json
{
  "steering": {
    "allowed_paths": ["P0", "P1", "P2"],
    "default_path": "P0"
  },
  "intervention": {
    "allowed_actions": ["I0", "I1"],
    "default_action": "I0"
  }
}
```

The steering selector has no intervention authority. The intervention selector
cannot alter the selected path or rewrite a committed graph edge.

### 3.3 Initial path registry

| ID | Path | Intended controlled progression |
|---|---|---|
| P0 | BASELINE_DEAD_END | Realistic denials and ordinary dead ends. |
| P1 | BACKUP_PATH | Backup metadata → restore capability → decoy archive namespace. |
| P2 | CREDENTIAL_PATH | Service-account clue → synthetic credential → controlled namespace. |
| P3 | PRIVILEGE_PATH | Role/procedure clue → reviewed privilege transition → administrative decoy. |
| P4 | SENSITIVE_DATA_PATH | Normal relational discovery → permission-controlled high-value synthetic data. |

P2 and P3 must remain unapproved until repeated authentication and privilege
semantics are validated. The existing D5 privilege lure is currently
`REQUIRES_REVIEW`; this status must not be bypassed.

### 3.4 Initial intervention registry

| ID | Intervention | Preconditions |
|---|---|---|
| I0 | OBSERVE_ONLY | Always legal and always the fallback. |
| I1 | TIGHTEN_TABLE_PERMISSION | Target is managed synthetic, already discovered, and not transaction-inconsistent. |
| I2 | RECOVER_DROPPED_OBJECT | A managed synthetic DROP was confirmed and committed. |
| I3 | REVOKE_DECOY_ROLE | A validated decoy role was successfully obtained and remains active. |

At most one intervention may execute in a v1 session. Credential rotation,
query cancellation, and forced session termination are deferred until their
cross-session and protocol semantics are explicitly validated.

---

## 4. Diagnostic lures and path selection

### 4.1 Diagnostic clues

All primary experiment arms must begin with the same clues. Reuse stable,
believable content where possible:

- backup clue: job, archive, migration, or snapshot metadata;
- credential clue: service-account reference, token metadata, or integration identity;
- privilege clue: role references, grants, function ownership, or procedure metadata;
- sensitive-data clue: ordinary foreign-key and business relationships leading toward synthetic high-value objects.

A clue is evidence only. It does not guarantee that its corresponding path is
viable, and accessing it must not create or modify content.

### 4.2 Diagnostic evidence

Extend structured behavior state with bounded per-path evidence:

```text
direct clue interactions
related object discoveries
revisits
exposed-but-ignored clues
backup/credential/sensitive/privilege family counts
role and permission enumeration
relevant MITRE stages and techniques
successful and failed path transitions
session depth
event-time duration
```

Raw SQL is used only by the existing deterministic classifier and is not passed
to the steering selector or learner.

### 4.3 Steering decision timing

Resolve a path at the first applicable condition:

```text
at least 3 classified queries plus a direct clue interaction
OR
8 classified queries
OR
60 seconds after the first classified query
OR
the first attempt to traverse an unresolved distinguishing edge
```

If an edge has already been directly or indirectly observed, it is no longer
eligible for adaptive resolution.

### 4.4 Rule steering v1

Rank legal paths lexicographically:

1. direct diagnostic-clue interactions;
2. relevant behavior-family count;
3. compatible MITRE progression;
4. deterministic session-seeded tie-break.

This avoids pretending that arbitrary numeric weights are calibrated. If all
signals are absent, use the session-seeded default. Once a path is selected, it
cannot change for that session.

---

## 5. Commitment and world-state model

### 5.1 Ledger state machine

Every path edge follows:

```text
UNRESOLVED
    ↓ legal late-bound path decision
PLANNED_SUCCESS or PLANNED_FAILURE
    ↓ attacker tests the edge
COMMITTED_SUCCESS or COMMITTED_FAILURE
    ↓ optional explicit defender transition
REVOKED / RESTRICTED / RECOVERED
```

Store in `world-ledger-v1`:

```text
session_id
experiment_id and arm
base_world_version
attack_graph_version
path_registry_version
intervention_registry_version
path_plan_id
selector type, confidence, and policy version
diagnostic evidence snapshot
unresolved, planned, and committed edge outcomes
active defender effects
intervention history
transaction state
monotonic world revision
decision/event/evidence IDs
created_at and updated_at
```

### 5.2 Consistency rules

- A planned but untested outcome is not an observed fact.
- A committed success or failure cannot be rewritten.
- A later difference requires an explicit defender event.
- A rollback cannot create a committed mutation or recovery trigger.
- A stale decision with the wrong world revision is rejected.
- The same event ID cannot commit an edge, intervention, reward, or model update twice.
- Missing, invalid, or unavailable adaptive state resolves to the session's
  existing committed world plus P0/I0 behavior.

Use Redis atomic compare-and-set semantics, such as WATCH/MULTI or a bounded Lua
operation, for revision changes.

---

## 6. PostgreSQL execution design

Implement and validate PostgreSQL before MySQL.

Use one PostgreSQL engine with a bounded pool of resettable session namespaces
and roles. Do not launch a database container per session.

```text
Default local lease pool: 16
Lease failure: static-safe P0/I0 session
Reset failure: quarantine lease, never hand it to another session
Pool exhaustion: preserve SQL availability and record fallback
```

At session start, the proxy or a bounded internal world-runtime contract leases
the namespace. The attacker connection uses only the leased synthetic context.
A deterministic control component may execute precompiled, allowlisted
PostgreSQL operations against honeypot namespaces. No AI component receives
database credentials or arbitrary SQL authority.

Use native PostgreSQL roles, schemas, permissions, and SQLSTATE behavior where
practical. Virtualized catalog results must match the leased namespace and the
committed graph.

The runtime connection must be closed in two steps:

1. prove rule-selected path P1 changes a future attacker-visible result;
2. prove approved intervention I1 or I2 changes a later result without
   contradicting the earlier transcript.

---

## 7. Telemetry, outcomes, and rewards

### 7.1 Steering record

Create `path-commitment-decision-v1` containing:

```text
decision_id and session_id
experiment assignment
decision timestamp and query count
expected world revision
diagnostic evidence
allowed paths and default path
selected path
selector type and confidence
policy/model/registry versions
commit result and resulting revision
```

The steering outcome ends at the first of:

- selected path successfully traversed;
- intervention eligibility;
- disconnect;
- configured observation limit.

Primary steering outcome:

```text
selected_path_traversed
```

### 7.2 Intervention record

Create `intervention-decision-v1` containing:

```text
decision_id and linked path decision
established access/path
expected world revision
allowed/default/selected intervention
selector type and confidence
execution result and resulting revision
defender event
```

The reaction window is the first of:

```text
10 subsequent queries
5 minutes
disconnect
```

Primary intervention outcome:

```text
novel_fallback_path_observed
```

Secondary outcomes include path depth, relevant objects, alternate edges, MITRE
progression, fallback latency, continuation, disconnect, trap interactions,
protocol errors, state inconsistencies, CPU, memory, and latency.

Do not combine steering and intervention into a single scalar reward until both
independent reward vectors are calibrated.

---

## 8. Operator modes and research arms

### 8.1 Runtime modes

| Mode | Behavior |
|---|---|
| STATIC_FIXED | Path selected before the session; no intervention. |
| ADAPTIVE_STEERING | Rule path selected after diagnostic evidence; no intervention. |
| STATIC_INTERVENTION | Path fixed before the session; rule intervention after progress. |
| ADAPTIVE_STEERING_INTERVENTION | Rule steering followed by an eligible rule intervention. |
| STATIC_SATURATED | Every approved path viable at session start; no intervention; optional ablation. |
| HYBRID_SHADOW | Learned recommendations recorded; rules execute. |
| SAFE_MODE | Global deterministic override; no new adaptive commits. |

Safe mode preserves facts already observed. It disables new steering and
intervention decisions but does not rewrite a live session's transcript.

### 8.2 One deployment, not four

All experiment arms run inside one deployment. Assign sessions using a
secret-salted HMAC cohort key and protocol, persist only the HMAC, and keep the
assignment sticky to reduce repeat-attacker contamination.

The primary four-arm factorial study is:

| Arm | Path selection | Intervention |
|---|---|---|
| A | Fixed before session | Off |
| B | Adaptive after evidence | Off |
| C | Fixed before session | Rule intervention |
| D | Adaptive after evidence | Rule intervention |

Comparisons:

```text
A vs B → effect of steering
A vs C → effect of intervention
C vs D → effect of steering when intervention exists
B vs D → effect of intervention after adaptive steering
interaction term → whether steering creates better intervention opportunities
```

`STATIC_SATURATED` is an optional fifth ablation answering why every path should
not simply be enabled. Its allocation may remain zero if traffic or AWS credits
are insufficient. It does not require another deployment.

Learned and evolving evaluations occur in later frozen epochs so the research
does not confuse the mechanism with the learner.

---

## 9. Ordered implementation roadmap

### D0 — Re-verify and freeze the dynamic baseline

- Run the mandatory repository, Compose, full regression, baseline, and security checks.
- Capture transcripts proving current strategy selection does not yet control later responses.
- Update `VALIDATION_CHECKPOINT.md` with VERIFIED, CLAIMED, PENDING, or BROKEN status.
- Do not modify dynamic behavior in this checkpoint.

Acceptance: a current, reproducible starting record exists.

### D1 — Persistent experiment assignment and idempotency

- Implement versioned session assignment and global operator overrides.
- Persist assignment, world revision, processed event IDs, and safe-mode state.
- Add restart and duplicate-event tests before path steering.

Acceptance: one session retains one arm across restarts and event replays.

### D2 — Attack graph, path registry, and ledger

- Derive graph edges from verified current behavior.
- Define edge observability predicates and P0–P4 validation state.
- Implement the append-only ledger and atomic revision checks.
- Keep current D0 behavior as the universal fallback.

Acceptance: static same-seed worlds reproduce exactly; committed edges cannot be rewritten.

### D3 — Diagnostic evidence and rule steering in shadow

- Add per-path evidence to behavior state.
- Implement decision timing and rule ranking.
- Record what would be selected without changing attacker-visible behavior.
- Compare static assignments and rule recommendations on controlled traces.

Acceptance: raw SQL and identifying data are absent; shadow output has no execution authority.

### D4 — Close the PostgreSQL steering loop

- Add namespace/role leasing and reset quarantine.
- Connect a committed path plan to a future `/decide`/proxy/backend result.
- Implement P0 and P1 first.
- Add catalog, transaction, failure, and consistency tests.

Acceptance: adaptive P1 and static P0 produce different later transcripts while sharing identical prior observations.

### D5 — Add remaining reviewed PostgreSQL paths

- Implement and validate P4.
- Complete repeated-authentication design before P2 approval.
- Complete D5/privilege review and native semantics before P3 approval.
- Never invent approval to fill the registry.

Acceptance: each approved path has deterministic, differential, protocol-native tests.

### D6 — Add rule interventions

- Add the post-success dwell window.
- Implement I1 and transaction-aware I2.
- Add I3 only after P3 and D5 are approved.
- Enforce one intervention per v1 session.

Acceptance: the later state transition is explicit, consistent, and attacker-visible.

### D7 — Extend telemetry, evidence, replay, and hardening

- Add separate steering/intervention decisions and outcomes.
- Persist artifacts in the evidence store.
- Extend sandbox replay for path and intervention transcripts.
- Validate hardening findings against before/after replays.
- Integrate evidence-grounded analyst reporting.

Acceptance: one trace links query → behavior → path → intervention → fallback → replay → report.

### D8 — Reactive controlled workloads and factorial experiment

- Convert fixed query lists into response-aware attacker scripts.
- Pair identical seeds/personas across arms A–D.
- Add sham decision points to static controls.
- Run the controlled four-arm mechanism experiment.

Acceptance: results are reproducible and isolate steering and intervention effects.

### D9 — Learned steering and intervention

- Build separate LinUCB contexts/models for paths and interventions.
- Calibrate independent reward profiles.
- Run shadow mode before bounded active control.
- Freeze model versions during every experiment epoch.

Acceptance: learned selection never expands either legal action space.

### D10 — Evolution loop

- Detect recurring missing graph edges, fallback paths, ineffective clues, and fidelity gaps.
- Propose non-deployable versioned changes.
- Require blue-team review, validation, sandbox replay, and differential tests.
- Promote only between experiment epochs.

Acceptance: a reviewed graph/intervention version can be reproduced and rolled back.

### D11 — MySQL parity and AWS study

- Port accepted contracts using MySQL-native privileges, databases, errors, and transactions.
- Run protocol parity and resource-feasibility experiments.
- Deploy one private-control/public-honeypot AWS stack.
- Perform KEDA/multi-node scaling only as a separate bounded experiment if credits remain.

Acceptance: public exposure passes the full security gate, cost controls, and kill-switch test.

---

## 10. Testing matrix

### Unit and property tests

- legal and illegal ledger transitions;
- monotonic revisions and stale-decision rejection;
- observability predicates;
- deterministic path ranking and tie-breaking;
- action-space separation;
- bounded input and no raw SQL leakage;
- duplicate-event idempotency;
- reward-window boundaries.

### Integration tests

- same transcript before static/adaptive divergence;
- P0 denial versus P1 success on the first untested edge;
- catalog consistency before and after path commitment;
- committed failure remains failure;
- permission tightening produces native errors;
- committed DROP followed by explicit recovery;
- transaction rollback does not trigger recovery;
- worker/Redis/model failure produces existing-world P0/I0 behavior;
- restart preserves assignment, ledger, and decision versions.

### Adversarial consistency tests

- attacker tests multiple paths early;
- attacker revisits a failed path after steering;
- attacker queries catalogs before direct edge tests;
- attacker reconnects with synthetic credentials;
- attacker tries to infer whether viability followed its interests;
- corrupted Redis, forged versions, and cross-session decisions fail closed.

### Performance acceptance

Attacker-facing adaptive p95 overhead must not exceed the greater of:

```text
5 milliseconds
or
5 percent over the matched static path
```

The live response path must perform no LLM inference. Queue overflow, timeout,
or learner failure must not make SQL unavailable.

---

## 11. Research methodology

- Use identical diagnostic clues in primary arms A–D.
- Draw fixed paths uniformly from the same approved templates available to adaptive steering.
- Randomize only eligible sessions and use intention-to-treat analysis.
- Keep cohort assignment sticky and stratify by protocol and attacker persona.
- Predeclare exclusion of project-owned scans and incomplete evidence.
- Freeze world, graph, registry, policy, reward, and model versions per epoch.
- Record sham steering/intervention times in control arms.
- Analyze controlled workloads separately from live Internet traffic.
- Estimate required live sample sizes from pilot variance.
- Report effect sizes and confidence intervals, not only means or composite rewards.
- Treat `STATIC_SATURATED` as an optional ablation, not the primary control.

Primary endpoints:

```text
Steering: selected_path_traversed
Intervention: novel_fallback_path_observed
```

Do not make a causal claim from observational similar-session estimates. Causal
claims must come from the randomized controlled experiment or an explicitly
identified controlled workload.

---

## 12. Hardware and AWS constraints

The implementation is designed for the available i7-7700, 32-GB, no-GPU host:

- deterministic classifiers and guards on the fast path;
- small contextual bandits only;
- bounded Redis state;
- one shared database engine per protocol;
- pooled namespaces rather than per-session containers;
- local LLM stopped by default and used only for optional offline proposals;
- bounded queues, TTLs, and evidence retention.

AWS deployment uses one codebase and one experiment router. Only honeypot ports
are public. Redis, Redpanda, Prometheus, Grafana, learning, evidence, replay,
hardening, analyst, control, and LLM services remain private. Require encrypted
volumes, egress denial, budget alarms, storage alarms, retention limits, safe
mode, and an immediate shutdown procedure.

---

## 13. Security invariants

- Never use real production data, identities, credentials, or secrets.
- Never connect attackers or replay payloads to production.
- Never retaliate or scan an attacker.
- No AI component can execute arbitrary SQL, shell, Docker, Kubernetes, or cloud actions.
- The database/protocol layer remains authoritative for observed behavior.
- Rules define legal paths and interventions; learners only rank legal choices.
- Generated candidates remain offline, non-deployable, and human-reviewed.
- Failures preserve the deterministic honeypot and existing session commitments.
- Never expose prompts, model names, stack traces, internal state, or control metadata to attackers.

---

## 14. Completion definition

The two-stage dynamic capability is complete only when all of the following are
demonstrated:

```text
[ ] Static path outcomes are fixed before attacker behavior is processed.
[ ] Adaptive paths resolve only unobserved outcomes.
[ ] Diagnostic clues are identical across the primary comparison arms.
[ ] A selected path changes a future attacker-visible PostgreSQL result.
[ ] Committed facts cannot be rewritten.
[ ] A later intervention is represented as an explicit defender event.
[ ] Steering and intervention have separate telemetry and reward vectors.
[ ] Rule modes work without any learner or LLM.
[ ] Shadow models have no execution authority.
[ ] Learned modes remain inside exact rule-approved action spaces.
[ ] Restart and replay are persistent and idempotent.
[ ] Reactive controlled workloads reproduce fallback behavior.
[ ] The four-arm factorial experiment is reproducible.
[ ] Human-reviewed evolution produces a versioned, rollback-safe registry update.
[ ] MySQL parity is validated after PostgreSQL.
[ ] Commodity CPU feasibility is measured.
[ ] AWS exposure passes security, privacy, cost, and kill-switch gates.
```

Do not describe the system as dynamically steering or intervening until the
corresponding attacker-visible acceptance tests have passed and the checkpoint
has been updated with current evidence.

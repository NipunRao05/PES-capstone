# AGENTS.md

## Project: Deception-Driven Database Threat Intelligence and Hardening Platform

This file is intended for Codex or any code-generation agent working on this repository. It records the real project goal, the verified work so far, the claimed-but-must-verify work, and the future execution order.

The project root used during development is:

```powershell
F:\capstone-main\capstone-main
```

Always begin with:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git log --oneline -10
docker compose -f docker-compose.yml ps
```

Do not push to GitHub unless the user explicitly asks.

---

## 1. Core Vision

The project is not merely a database honeypot, an autoscaler, or an AI chatbot.

The real goal is:

```text
Expose controlled fake MySQL/PostgreSQL endpoints
→ attract scanners/attackers
→ capture their database attack behavior
→ classify behavior with MITRE ATT&CK
→ keep honeypot infrastructure alive using autoscaling
→ generate deterministic AI incident reports
→ replay captured attempts safely in a sandbox
→ produce hardening recommendations for the protected real database
→ optionally use an LLM to generate evidence-grounded research/operator reports
```

The protected real database may represent a sensitive-data environment such as a government citizen database, a financial institution, a credit-card processor, a healthcare database, or any organization storing high-value customer records.

However:

```text
Attackers must never touch any real production database.
Attackers interact only with controlled decoy services.
Captured attacker payloads must never be replayed against production.
Only fake/synthetic/sanitized data may be used.
```

Use this final framing:

```text
A deception-driven database threat intelligence and hardening platform for sensitive-data environments.
```

Suggested research claim:

```text
The system safely exposes realistic MySQL/PostgreSQL decoy endpoints, captures attacker behavior, maps it to MITRE ATT&CK, elastically scales honeypot resources under attack pressure, replays captured attempts in an isolated sandbox, and converts the results into evidence-based hardening recommendations with AI-assisted incident reporting.
```

---

## 2. Current High-Level Architecture

```text
External scanner / attacker
        ↓
Controlled decoy MySQL / PostgreSQL endpoint
        ↓
mysqlproxy / pgproxy
        ↓
deception-engine
        ↓
query/session event stream
        ↓
session-module
        ↓
MITRE agent
        ↓
mitre-events / mitre-sessions
        ↓
scaling-agent
        ↓
Prometheus / metrics-bridge / Grafana / KEDA
        ↓
AI Agent v1 deterministic incident brief
        ↓
sandbox replay engine
        ↓
hardening recommendation engine
        ↓
LLM Agent v2 evidence-grounded report generator
        ↓
research/operator report
```

Important local services currently known or planned:

```text
mysqlproxy
pgproxy
mysql
postgres
redpanda
redpanda-init
session-module
mitre-agent
deception-engine
redis-deception
redis-mitre
scaling-agent
metrics-bridge
prometheus
loki
promtail
grafana
ai-agent
evidence-store
sandbox-replay-engine
llm-report-agent
```

Important local ports:

```text
mysqlproxy:         127.0.0.1:3306
pgproxy:            127.0.0.1:5432
pgproxy metrics:    127.0.0.1:9090/metrics
mysqlproxy metrics: 127.0.0.1:9091/metrics
deception-engine:   127.0.0.1:8001
scaling-agent:      127.0.0.1:9095
metrics-bridge:     127.0.0.1:9100
prometheus:         127.0.0.1:9096
ai-agent:           127.0.0.1:8010
evidence-store:     127.0.0.1:8011
sandbox-replay:     127.0.0.1:8012
llm-report-agent:   127.0.0.1:8013
```

Important Redpanda/Kafka topics:

```text
mysql-query-events
mysql-session-events
pg-query-events
pg-session-events
session-closed-events
session-profiles
mitre-events
mitre-sessions
dead-letter-events
```

---

## 3. Verified Work Done So Far

The following work has been implemented and validated in this project history.

### 3.1 Database deception layer

Implemented and validated:

```text
MySQL proxy
PostgreSQL proxy
deception-engine
fake/deceptive schema responses
trap-table behavior
/deceive or /decide style decision flow
/health, /healthz, /ready, /readyz
input validation for malformed/unsupported requests
deterministic fake data generation
rate limiting on deception-engine decision flow
```

Known validation:

```text
Direct /decide returned fake schema rows.
PostgreSQL trap-table query emitted MITRE T1213.006.
Unsupported protocol returned 400.
Missing query_normalized returned 400.
```

### 3.2 MITRE detection layer

Implemented and validated:

```text
MITRE rule mapping for database reconnaissance/trap behavior
session profiling
MITRE event production to Redpanda
MITRE session output
trap-trigger classification
database collection mapping such as T1213.006
```

Relevant ATT&CK-style mapping:

```text
T1213.006
Data from Information Repositories: Databases
Collection
```

### 3.3 Hardening already completed

Completed historical hardening phases:

```text
Phase 1  - Kafka DLQ handling
Phase 2  - Baseline regression
Phase 3  - Health/readiness endpoints
Phase 4  - /decide validation
Phase 5  - Redis-backed /decide rate limiting
Phase 6  - Kafka publish failure hardening
Phase 7  - Deterministic fake data generation
Phase 8  - Security cleanup for .env and weak defaults
Phase 9  - Validation summary documentation
```

Important existing files:

```text
HARDENING_VALIDATION_SUMMARY.md
.env.example
```

Attack graph fix:

```text
mitre_agent/attack_graph.py patched for NetworkX compatibility.
NetworkX edges output normalized to links.
```

### 3.4 Scaling system

Implemented:

```text
Go scaling-agent
intent-based scaling from MITRE/session signals
metric-based scaling from Prometheus
EWMA smoothing
scale-up threshold
scale-down threshold
scale-up cooldown
scale-down stabilization window
trap-trigger scoring
scale event history
metrics endpoint
```

Current scaling model:

```text
score >= 0.6       → scale up, bounded by max step
0.3 <= score < 0.6 → hold
score < 0.3        → scale down only after stabilization window
```

Known parameters:

```text
ScaleUpCooldown    = 30s
MaxScaleUpStep     = 2
ScaleDownWindow    = 120s
ScaleUpThreshold   = 0.6
ScaleDownThreshold = 0.3
```

Metric-pressure model:

```text
connection_pressure = clamp01((pg_active + mysql_active) / active_capacity)
rate_pressure       = clamp01((pg_rate + mysql_rate) / rate_capacity)
backend_pressure    = 0.7 if backend health < 1
pressure            = max(connection_pressure, rate_pressure, backend_pressure)
```

Validated:

```text
High-risk MITRE event produced scaling-agent scale-up decision.
Repeated high-risk events respected cooldown.
Middle score range held replica target.
Low score scaled down after stabilization window.
Metric pressure signal worked through Prometheus collector.
```

Important limitation:

```text
In Docker Compose, scaling is logical inside scaling-agent.
Docker Compose does not automatically create more containers from this target.
Real physical autoscaling must be validated through Kubernetes/KEDA.
```

### 3.5 Kubernetes/KEDA work

Implemented/validated in project history:

```text
KEDA v2.20 installed successfully.
KEDA operator pods ran.
ScaledObject became Ready=True.
HPA was created.
HPA external metric s0-prometheus was readable.
```

Known manifests:

```text
k8s/README.md
k8s/namespace.yaml
k8s/deception-engine-deployment.yaml
k8s/deception-engine-service.yaml
k8s/scaling-agent-deployment.yaml
k8s/scaling-agent-service.yaml
k8s/keda-scaledobject-prometheus.yaml
k8s/keda-scaledobject-proxy.yaml
```

Important caution:

```text
If current repository claims full physical KEDA scaling has been completed, verify it with kubectl output before treating it as complete.
```

### 3.6 AI Agent v1

AI Agent v1 is deterministic. It is not an LLM.

Files created historically:

```text
ai_agent/Dockerfile
ai_agent/main.py
ai_agent/requirements.txt
docker-compose.ai.yml
```

Current expected service:

```text
container: capstone-ai-agent
port:      127.0.0.1:8010
runtime:   Python 3.12 + FastAPI + uvicorn + requests
```

Expected endpoints:

```text
GET /healthz
GET /readyz
GET /brief/latest
GET /brief/markdown
```

AI Agent v1 reads:

```text
scaling-agent /metrics
scaling-agent /scale/events
Prometheus: capstone_scaling_scale_pressure
Prometheus: capstone_scaling_current_replicas
Prometheus: capstone_mitre_trap_triggers_total
Prometheus: capstone_mitre_avg_actor_risk
```

AI Agent v1 outputs:

```text
risk_level
summary
scaling_interpretation
evidence
recommended_response
Markdown incident brief
```

Validated behavior:

```text
/healthz passed.
/readyz passed.
/brief/latest passed.
/brief/markdown passed.
Fresh high-risk MITRE event produced risk_level=high.
AI agent used scaling-agent trap_triggers even when Prometheus trap metric was 0.
AI agent correctly attributed latest high-risk attacker event instead of metric-pressure-prometheus.
```

Final validated attribution example:

```text
session_id: ai-agent-attribution-final-490080328
risk_level: high
summary mentions: ai-agent-attribution-final-490080328
current_replicas: 3.0
trap_triggers: 5.0
recent_high_event_count: 1
attacker_high_event_count: 1
elevated_posture_event_count: 2
latest_high_event: ai-agent-attribution-final-490080328
```

---

## 4. Current Document Review / Trust Policy

Some versions of this file may contain `[x]` checkmarks for phases that were not validated in this conversation. Codex must not trust checkmarks blindly.

Before starting any new phase, verify the actual repository state using:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git log --oneline -10
docker compose -f docker-compose.yml ps
```

Then verify the phase-specific service/files/tests.

Use these status categories:

```text
VERIFIED      = validated by actual command output or committed artifact.
CLAIMED       = mentioned in AGENTS.md or notes but not yet verified in this session.
PENDING       = not built yet.
DO NOT START  = intentionally deferred.
```

Conservative status as of this handoff:

```text
Database deception layer                 VERIFIED
MITRE detection layer                     VERIFIED
Hardening phases 1-9                      VERIFIED
Scaling-agent logical scaling             VERIFIED
AI Agent v1 deterministic reports          VERIFIED
KEDA/HPA structural validation             VERIFIED
Full physical KEDA scaling                 CLAIMED/VERIFY
Attacker evidence store                    CLAIMED/VERIFY
Sandbox replay engine                      CLAIMED/VERIFY
Hardening recommendation engine            CLAIMED/VERIFY
Persistent scaling state                   CLAIMED/VERIFY
Prometheus metric consistency              CLAIMED/VERIFY
Kafka idempotency/replay safety            CLAIMED/VERIFY
Operator controls                          CLAIMED/VERIFY
Grafana dashboards and alerts              PENDING
Controlled load/calibration tests          PENDING
LLM Agent v2                               PENDING
Cloud fake-company honeypot deployment     PENDING
Research validation package                PENDING
```

If a phase is marked CLAIMED/VERIFY, run its acceptance tests before modifying downstream phases.

---

## 5. Critical Safety and Scope Rules

These rules are mandatory.

### 5.1 Real production data must never be used

Do not use:

```text
real citizen data
real cardholder data
real healthcare data
real customer PII
real government records
real production credentials
```

Use only fake/synthetic/sanitized data.

### 5.2 Never replay attacker payloads against a real database

Captured attacker queries must be replayed only against:

```text
sandbox database
sanitized schema clone
disposable clone
fake dataset
isolated test environment
```

### 5.3 Do not impersonate real regulated entities

If the project is deployed publicly, it must use:

```text
fictional company
fictional brand
fake records
no real logos
no real government/bank/credit-card branding
```

### 5.4 Do not retaliate or scan attackers back

The system may collect inbound behavior only.

It must not:

```text
attack remote sources
scan attackers back
exploit remote hosts
perform credential stuffing
publish raw secrets
send payloads to third-party systems
```

### 5.5 Public internet deployment requires a security gate

Before exposing anything to the internet, confirm:

```text
No real DB connected
No real customer data
Only honeypot ports public
Grafana private
Prometheus private
Redis private
Kafka/Redpanda private
AI agent private
LLM agent private
Sandbox replay APIs private
Control APIs private
Egress restricted
Budget alerts enabled
Kill switch ready
Logs redact secrets/passwords
```

---

## 6. AI Agent Architecture Clarification

The user's proposed description of an AI agent is broadly correct in general:

```text
An AI agent can pursue goals, plan steps, use tools, interact with systems, keep memory, handle errors, and continue until a task is complete.
```

However, this project must not use an unbounded autonomous agent.

Use this safer project-specific model:

```text
Bounded security analyst agents.
```

### 6.1 Agent split

```text
MITRE agent      = deterministic detection agent.
Scaling agent    = deterministic control/scaling agent.
AI Agent v1      = deterministic evidence reporter.
LLM Agent v2     = bounded LLM-assisted analyst/report generator.
```

### 6.2 What deterministic modules decide

The following facts must be decided by deterministic code, not by an LLM:

```text
risk_level
trap_trigger_count
attacker session_id
MITRE technique
scale score
replica target
sandbox replay verdict
hardening recommendation identity
```

### 6.3 What the LLM may do

The LLM Agent v2 may:

```text
load structured evidence for one session/incident
plan report sections
ask internal tools for sandbox replay results
ask internal tools for hardening recommendations
explain attacker behavior
produce an executive summary
produce a technical timeline
produce a research-paper-friendly narrative
produce an operator checklist
flag missing evidence
```

### 6.4 What the LLM must not do

The LLM Agent v2 must not:

```text
connect to any real database
run payloads against production
scan attackers back
change cloud firewall rules automatically
decide scaling
change replica count
delete data
publish reports without review
expose services
disable safety controls
```

### 6.5 Correct LLM loop

The LLM agent should run per incident, not as an uncontrolled infinite loop:

```text
1. Receive session_id or incident_id.
2. Load evidence from evidence-store.
3. Load MITRE events.
4. Load scaling events.
5. Load sandbox replay results.
6. Load hardening recommendations.
7. Generate a structured report.
8. Validate every claim against evidence.
9. Return report to the operator.
```

Suggested endpoints:

```text
GET  /healthz
GET  /readyz
POST /llm/report/session/{session_id}
GET  /llm/report/{report_id}
POST /llm/evaluate/report/{report_id}
```

### 6.6 Is an LLM required?

For core correctness:

```text
No.
```

For the research paper and reproducible incident narratives:

```text
Yes, useful.
```

The LLM should be completed before fake-company public internet deployment so that its behavior can be tested and reproduced using controlled sessions before real-world data collection.

---

## 7. Correct Execution Roadmap From Here

Do these in order.

### Phase A — Verify current checkpoint

Goal:

```text
Prevent Codex from building on false checkmarks.
```

Commands:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git log --oneline -10
docker compose -f docker-compose.yml ps
```

Verify whether these are actually implemented and committed:

```text
evidence-store
sandbox-replay-engine
hardening recommendation engine
persistent scaling state
Prometheus consistency fix
Kafka idempotency
operator controls
Kubernetes physical scaling
```

Acceptance:

```text
A short verified status table is written to HARDENING_VALIDATION_SUMMARY.md or a new VALIDATION_CHECKPOINT.md.
```

---

### Phase B — Freeze AI Agent v1

Goal:

```text
Finalize deterministic JSON + Markdown incident reporter.
```

Required tests:

```powershell
docker compose -f docker-compose.yml up -d --build ai-agent
Start-Sleep -Seconds 10

Invoke-RestMethod http://127.0.0.1:8010/healthz | ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8010/readyz | ConvertTo-Json -Depth 8

$brief = Invoke-RestMethod http://127.0.0.1:8010/brief/latest
$brief | ConvertTo-Json -Depth 14

curl.exe http://127.0.0.1:8010/brief/markdown
```

Acceptance:

```text
Benign state → LOW.
Trap-trigger state → HIGH.
Fresh attacker event → correct attacker session_id.
Markdown report matches JSON report.
Prometheus metric 0 but scaling-agent trap count > 0 → still HIGH.
```

---

### Phase C — Verify or build attacker evidence store

Goal:

```text
One attacker session can be traced from connection to AI report.
```

Store per session:

```text
session_id
source_ip or anonymized source_ip
fingerprint
protocol
database/user attempted
query_raw
query_normalized
timestamp
trap_triggered
MITRE technique
risk_score
scale_event_id
AI_report_id
replay_id
hardening_report_id
llm_report_id
```

Acceptance:

```text
connection → query → MITRE event → scaling event → AI report
all share the same session_id or trace_id.
```

---

### Phase D — Verify or build sandbox replay engine

Goal:

```text
Replay captured attacker attempts safely against sandbox databases, never production.
```

Suggested API:

```text
GET  /healthz
GET  /readyz
POST /replay/session/{session_id}
GET  /replay/result/{replay_id}
```

Query policy:

```text
SELECT / SHOW / information_schema / pg_catalog → execute on sandbox
DROP / DELETE / UPDATE / ALTER / TRUNCATE → block or simulate by default
long-running query → timeout
unknown dangerous query → block and mark unsafe
```

Acceptance:

```text
Captured attacker behavior can be tested safely without touching any real database.
```

---

### Phase E — Verify or build hardening recommendation engine

Goal:

```text
Convert sandbox replay results into actionable database hardening recommendations.
```

Required output:

```text
issue
evidence
affected_object
severity
recommended_fix
verification_step
before_replay_result
after_replay_result
```

Acceptance:

```text
captured query → sandbox weakness → hardening fix → replay confirms fix works.
```

---

### Phase F — Build LLM Agent v2 report layer

This phase is now intentionally before public internet deployment.

Goal:

```text
Generate evidence-grounded reports from deterministic evidence.
```

Suggested service:

```text
llm-report-agent
```

Suggested files:

```text
llm_agent/
  Dockerfile
  requirements.txt
  main.py
  prompts/
    incident_report_system.md
    incident_report_user_template.md
    report_validator.md
  schemas/
    evidence_input.schema.json
    report_output.schema.json
```

Possible providers:

```text
local LLM through Ollama or compatible local server
OpenAI API if explicitly configured by user
no provider by default; system must run with a mock/deterministic fallback for tests
```

Environment variables:

```text
LLM_PROVIDER=mock|openai|ollama
LLM_MODEL=<model-name>
LLM_TEMPERATURE=0
LLM_TIMEOUT_SECONDS=30
EVIDENCE_STORE_URL=http://evidence-store:8011
SANDBOX_REPLAY_URL=http://sandbox-replay-engine:8012
AI_AGENT_URL=http://ai-agent:8010
```

API:

```text
GET  /healthz
GET  /readyz
POST /llm/report/session/{session_id}
GET  /llm/report/{report_id}
POST /llm/evaluate/report/{report_id}
```

Input evidence must include:

```text
session_id
captured queries
MITRE events
scale events
AI Agent v1 brief
sandbox replay results
hardening recommendations
metric snapshot
```

Output must include:

```text
report_id
session_id
executive_summary
technical_timeline
attacker_behavior
mitre_mapping
scaling_response
sandbox_replay_summary
hardening_recommendations
evidence_citations
unsupported_claims[]
missing_evidence[]
operator_checklist
research_summary
```

Acceptance:

```text
LLM report identifies correct attacker session.
LLM report uses only provided evidence.
LLM report explains MITRE/scaling/replay/hardening.
LLM report lists missing evidence instead of hallucinating.
LLM output is reproducible with saved input JSON and temperature 0/mock mode.
```

Required tests:

```text
Benign session → no invented attack.
Recon session → explains enumeration.
Trap session → identifies trap behavior.
Sandbox success → explains weakness.
Destructive query blocked → says blocked/simulated, not executed.
Before/after hardening → explains fix validation.
Missing evidence → reports missing evidence.
```

Research reproducibility requirements:

```text
Save evidence_input.json.
Save report_output.json.
Save prompt version.
Save model/provider name.
Use temperature 0 if supported.
Support mock mode for deterministic CI tests.
```

---

### Phase G — Verify or add persistent scaling state

Goal:

```text
Scaling-agent restart must not erase attack/scaling state.
```

Persist:

```text
current_replicas
scorer_replicas
trap_triggers
scale_up_events
scale_down_events
recent scale events
last scale-up time
scale-down timer
manual override state
safe mode state
processed event ids
```

Acceptance:

```text
Scaling-agent restart does not erase operational state.
```

---

### Phase H — Verify or fix Prometheus metric consistency

Known issue from earlier validation:

```text
scaling-agent trap_triggers = nonzero
Prometheus capstone_mitre_trap_triggers_total = 0
```

Acceptance:

```text
scaling-agent /metrics, Prometheus query, Grafana dashboard, and AI/LLM evidence agree.
```

---

### Phase I — Verify or add Kafka idempotency/replay safety

Goal:

```text
Duplicate or replayed events must not inflate trap counts or cause repeated scaling.
```

Required:

```text
event_id
processed event store
duplicate detection
DLQ validation
safe consumer restart
```

Acceptance:

```text
Replay and duplicate events do not corrupt scaling or trap counts.
```

---

### Phase J — Verify or add operator controls

Required controls:

```text
safe mode
manual replica target
rollback to baseline
max replica budget
autoscaling enable/disable
control audit log
```

Acceptance:

```text
Operator can safely stop, override, and roll back automation.
AI/LLM reports mention safe mode/manual override when active.
```

---

### Phase K — Verify Kubernetes/KEDA physical scaling

Goal:

```text
Prove autoscaling is physical, not only logical.
```

Acceptance:

```text
Real Kubernetes pods physically scale 1 → 2 or 1 → 3 based on project telemetry.
Scale-down also occurs safely after stabilization.
```

---

### Phase L — Build Grafana dashboards and alerts

Goal:

```text
Operator can observe attack → MITRE → scaling → AI/LLM report → sandbox result → hardening recommendation.
```

Dashboard panels:

```text
active sessions
query rate
MITRE events
trap triggers
scale pressure
current replicas
scale-up/down events
AI risk level
LLM report status
sandbox replay results
hardening recommendations
DLQ count
```

Alerts:

```text
trap trigger > 0
risk high/critical
DLQ increasing
AI agent down
LLM agent down
scaling-agent down
KEDA not ready
replicas at max budget
sandbox replay finds exploitable weakness
```

Acceptance:

```text
Attack-to-response pipeline is visible and alertable.
```

---

### Phase M — Controlled load and calibration tests

Goal:

```text
Measure accuracy and stability before internet exposure.
```

Workloads:

```text
benign users
reconnaissance users
trap-trigger attacker
mixed benign + attacker
query burst
many concurrent connections
```

Metrics:

```text
p50/p95/p99 latency
events per second
Kafka lag
MITRE processing latency
scaling decision latency
AI brief latency
LLM report latency
CPU/memory
false positives
false negatives
precision
recall
F1 score
```

Acceptance:

```text
The system is accurate and stable under controlled workloads.
```

---

### Phase N — Security gate before public internet deployment

This is mandatory before fake-company deployment.

Must confirm:

```text
No real database connected
No real customer data
No real government/bank/credit-card branding
Only fictional company
Only honeypot ports public
Grafana private
Prometheus private
Redis private
Kafka private
AI agent private
LLM agent private
Control APIs private
Sandbox APIs private
Egress restricted
Budget alerts enabled
Kill switch ready
Logs redact secrets/passwords
Cloud provider ToS reviewed
```

Acceptance:

```text
Public exposure is limited to controlled honeypot endpoints only.
```

---

### Phase O — Deploy fictional company honeypot to cloud

Public-facing:

```text
fake company website
fake MySQL endpoint
fake PostgreSQL endpoint
```

Private/internal:

```text
Redpanda/Kafka
Redis
Prometheus
Grafana
AI agent
LLM agent
sandbox replay engine
scaling-agent controls
```

Post-deployment tests:

```text
Public MySQL honeypot reachable.
Public PostgreSQL honeypot reachable.
Admin services not reachable publicly.
Scanner connection captured.
Query captured.
MITRE event generated.
AI report generated.
LLM report generated.
Sandbox replay result generated.
Alert fires.
Kill switch works.
Budget alarm works.
```

Acceptance:

```text
Real internet traffic is safely captured and processed end-to-end.
```

---

### Phase P — Real-world observation period

Suggested windows:

```text
24 hours safety run
3 days initial dataset
7 days main dataset
14–30 days optional extended dataset
```

Daily checks:

```text
cost
disk usage
outbound traffic
alerts
DLQ count
captured sessions
trap triggers
AI reports
LLM reports
sandbox replay findings
```

Stop immediately if:

```text
unexpected outbound traffic
cloud abuse warning
cost spike
real secret captured
service compromise
uncontrolled scaling
```

Acceptance:

```text
Real-world scanner/attacker sessions are captured safely and anonymized.
```

---

### Phase Q — Final research validation

Experiments:

```text
1. Deception realism
2. MITRE detection accuracy
3. Autoscaling effectiveness
4. Sandbox replay and hardening loop
5. AI Agent v1 report correctness
6. LLM Agent v2 report correctness/reproducibility
7. Reliability under restart/replay/failure
8. Real-world dataset summary
```

Required graphs:

```text
risk score over time
replica count over time
trap triggers over time
time to detection
time to scale
latency p95/p99
Kafka lag
false positive/false negative chart
sandbox before/after hardening success rate
AI attribution accuracy
LLM unsupported-claim count
LLM evidence-completeness score
```

Acceptance:

```text
Controlled test results + anonymized real-world evidence + reproducible AI/LLM outputs + graphs are available.
```

---

## 8. Final Completion Definition

The project is complete for research-paper purposes when all of these are true:

```text
[ ] Fake MySQL/PostgreSQL endpoints are reachable.
[ ] Real database is isolated and never touched by attackers.
[ ] Attacker/scanner queries are captured.
[ ] Sessions are correlated end-to-end.
[ ] MITRE techniques are emitted.
[ ] Trap events produce high-risk classification.
[ ] Scaling-agent scales logically under attack.
[ ] Kubernetes/KEDA scales physically under pressure.
[ ] AI Agent v1 produces correct JSON and Markdown reports.
[ ] Sandbox replay safely tests captured queries.
[ ] Hardening recommendations are generated.
[ ] Before/after sandbox replay proves fixes work.
[ ] LLM Agent v2 produces evidence-grounded reports.
[ ] LLM reports are reproducible from saved evidence JSON.
[ ] Metrics are consistent across scaling-agent, Prometheus, Grafana, AI, and LLM evidence.
[ ] Duplicate/replayed Kafka events are idempotent.
[ ] Operator safe mode/manual override/rollback works.
[ ] Controlled load and calibration tests are documented.
[ ] Public cloud honeypot passes security gate.
[ ] Real-world evidence is collected safely and anonymized.
[ ] Final graphs and validation artifacts exist for the paper.
```

---

## 9. Git Policy

Do not push partial/broken work.

For each phase:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
# run phase tests
& $git add <changed-files>
& $git commit -m "<clear phase message>"
# push only when user explicitly approves
```

Suggested commit messages:

```text
Finalize AI agent incident briefing
Add attacker evidence store
Add sandbox replay engine
Add hardening recommendation engine
Add LLM incident report agent
Persist scaling agent state
Fix Prometheus metric consistency
Add Kafka idempotency safeguards
Add operator scaling controls
Validate Kubernetes KEDA physical scaling
Add Grafana dashboards and alerts
Add controlled load and calibration tests
Prepare cloud honeypot deployment
Add research validation artifacts
```

---

## 10. Immediate Next Step For Codex

Do not start internet deployment.

Do not start real-world data collection.

First, verify the current claimed checkpoint:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git log --oneline -10
docker compose -f docker-compose.yml ps
```

Then produce a short `VALIDATION_CHECKPOINT.md` that states which of the following are actually implemented and validated in the repository:

```text
AI Agent v1
attacker evidence store
sandbox replay engine
hardening recommendation engine
persistent scaling state
Prometheus metric consistency
Kafka idempotency/replay safety
operator controls
Kubernetes/KEDA physical scaling
```

After the checkpoint, the next major build target is:

```text
LLM Agent v2 evidence-grounded report layer
```

The LLM Agent v2 must be completed and locally tested before the fictional-company cloud deployment.

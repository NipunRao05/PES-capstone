# AGENTS.md

## Project: Deception-Driven Database Threat Intelligence and Hardening Platform

This file is intended for Codex or any code-generation agent working on this repository. It describes the current project state, what has already been implemented and validated, and the future execution roadmap in the correct order.

The project root used during development is:

```powershell
F:\b\Capstone-main
```

Do not assume the repository is clean. Always start by checking:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
& $git log --oneline -8
docker compose -f docker-compose.yml ps
```

Do not push to GitHub unless explicitly instructed by the user.

---

## 1. Core Vision

The project is not just a database honeypot and not just an autoscaler.

The real goal is:

```text
Expose controlled fake MySQL/PostgreSQL endpoints
→ attract scanners/attackers
→ capture their database attack behavior
→ classify behavior with MITRE ATT&CK
→ keep honeypot infrastructure alive using autoscaling
→ generate AI incident reports
→ replay captured attempts safely in a sandbox
→ produce hardening recommendations for the protected real database
```

The protected real database may represent a sensitive-data environment such as a government citizen database, a financial institution, a credit-card processor, a healthcare database, or any organization storing high-value customer records.

However, attackers must never touch any real production database. They interact only with controlled decoy services.

Use this final project framing:

```text
A deception-driven database threat intelligence and hardening platform for sensitive-data environments.
```

Suggested research claim:

```text
The system safely exposes realistic MySQL/PostgreSQL decoy endpoints, captures attacker behavior, maps it to MITRE ATT&CK, elastically scales honeypot resources under attack pressure, and converts captured attacker attempts into evidence-based hardening recommendations using sandbox replay and AI incident reporting.
```

---

## 2. Current Architecture

Current/high-level pipeline:

```text
External scanner / attacker
        ↓
Decoy MySQL / PostgreSQL endpoint
        ↓
mysqlproxy / pgproxy
        ↓
deception-engine
        ↓
session-module
        ↓
MITRE agent
        ↓
mitre-events / mitre-sessions topics
        ↓
scaling-agent
        ↓
Prometheus / metrics-bridge / Grafana / KEDA
        ↓
AI incident brief agent / bounded evidence report agent
        ↓
sandbox replay engine
        ↓
hardening recommendation engine
```

Important Docker Compose services:

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
llm-agent
llm-agent-api
sandbox-replay-engine
sandbox-replay-api
sandbox-mysql
sandbox-postgres
json-exporter
```

Important ports used locally:

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
sandbox replay:     127.0.0.1:8012
llm-agent API:      127.0.0.1:8013
```

Important Kafka/Redpanda topics:

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

## 3. What Has Already Been Done

### 3.1 Database deception layer

Implemented and validated:

- MySQL proxy.
- PostgreSQL proxy.
- Deception engine.
- Fake/deceptive schema responses.
- Trap-table behavior.
- Decision endpoint `/decide`.
- Health/readiness endpoints:
  - `/health`
  - `/healthz`
  - `/ready`
  - `/readyz`
- Input validation for unsupported/malformed requests.
- Deterministic fake data generation across restarts.
- Rate limiting on deception-engine decision flow.

Known validation results:

```text
Direct /decide returned fake schema rows.
PostgreSQL trap-table query emitted MITRE T1213.006.
Unsupported protocol produced 400.
Missing query_normalized produced 400.
```

### 3.2 MITRE detection layer

Implemented and validated:

- MITRE rule mapping for database reconnaissance/trap behavior.
- Session profiling.
- MITRE event production to Redpanda.
- MITRE session output.
- Trap-trigger classification for database collection behavior.
- ATT&CK-style mapping such as:
  - `T1213.006`
  - `Data from Information Repositories: Databases`
  - `Collection`

### 3.3 Hardening work already completed

Completed phases:

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

Important files already created/updated:

```text
HARDENING_VALIDATION_SUMMARY.md
.env.example
```

Attack graph fix:

- `mitre_agent/attack_graph.py` was patched for NetworkX compatibility.
- It normalizes NetworkX `edges` output to `links`.

### 3.4 Scaling system

Implemented:

- `scaling-agent` in Go.
- Intent-based scaling from MITRE/session signals.
- Metric-based scaling from Prometheus.
- EWMA smoothing.
- Scale-up threshold.
- Scale-down threshold.
- Scale-up cooldown.
- Scale-down stabilization window.
- Trap-trigger scoring.
- Scale event history.
- Metrics endpoint.

Current scaling model:

```text
score >= 0.6       → scale up, bounded by max step
0.3 <= score < 0.6 → hold
score < 0.3        → scale down only after stabilization window
```

Known scaling parameters:

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
It does not automatically create more Docker containers.
Real physical autoscaling must happen through Kubernetes/KEDA.
```

### 3.5 Kubernetes/KEDA work

Implemented:

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

Validated:

```text
KEDA v2.20 installed successfully.
KEDA operator pods ran.
ScaledObject became Ready=True.
HPA was created.
HPA external metric s0-prometheus was readable.
```

Known gap:

```text
Full real app physical scaling in Kubernetes is not yet fully complete.
Images must be properly built/tagged/pushed or loaded into the cluster.
A final real KEDA scaling test is still required.
```

### 3.6 AI Agent v1

Files created:

```text
ai_agent/Dockerfile
ai_agent/main.py
ai_agent/requirements.txt
docker-compose.ai.yml
```

The AI-agent service is now defined directly in `docker-compose.yml`; the temporary
`docker-compose.ai.yml` override has been removed.

Current AI agent service:

```text
container: capstone-ai-agent
port:      127.0.0.1:8010
runtime:   Python 3.12 + FastAPI + uvicorn + requests
```

Current endpoints:

```text
GET /healthz
GET /readyz
GET /brief/latest
GET /brief/markdown
```

AI agent reads:

```text
scaling-agent /metrics
scaling-agent /scale/events
Prometheus query: capstone_scaling_scale_pressure
Prometheus query: capstone_scaling_current_replicas
Prometheus query: capstone_mitre_trap_triggers_total
Prometheus query: capstone_mitre_avg_actor_risk
```

AI agent outputs:

```text
risk_level
summary
scaling_interpretation
evidence
recommended_response
Markdown incident brief
```

Important design choice:

```text
AI Agent v1 is deterministic.
It is not currently an LLM.
It should not decide scaling.
It should explain evidence produced by deterministic modules.
```

Validated AI Agent v1 behavior:

```text
/healthz passed.
/readyz passed.
/brief/latest passed.
/brief/markdown passed.
Fresh high-risk MITRE event produced risk_level=high.
AI agent correctly used scaling-agent trap_triggers even when Prometheus trap metric stayed 0.
AI agent correctly attributed latest high-risk attacker event instead of generic metric-pressure-prometheus event.
```

Final validated attacker attribution example:

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

### 3.7 Bounded evidence report agent (AI Agent v2 local mode)

Implemented on 2026-08-21 as a bounded report generator, not an autonomous
agent. The deterministic modules remain authoritative for risk and scaling.

```text
GET  /healthz
GET  /readyz
POST /llm/report/session/{session_id}
GET  /llm/report/{report_id}
```

Safety boundaries:

```text
structured internal evidence only
no scaling decisions or control
no database drivers or database credentials
no attacker contact or scanning
no outbound internet network
no free-form prompt or tool execution
deterministic_local mode is the default and only implemented mode
```

Validated:

```text
9/9 unit/API tests passed.
Benign session remained LOW.
Trap session remained CRITICAL.
Missing evidence returned 404.
Only a matching sandbox result was included.
Repeated evidence produced a stable report ID.
Report metadata linked back to the evidence trace.
```

### 3.8 Local observability, calibration, and pre-deployment gate

Completed locally on 2026-08-21 without deployment:

```text
Grafana operator overview: 16 panels
Prometheus: 26 accepted rules
Fresh trap → scaling → AI HIGH → alert flow passed
Controlled matrix: 13/13 executed and correlated
Controlled matrix precision/recall/F1: 1.0/1.0/1.0
Local pre-deployment security gate: 17/17
Python service tests: 280 passed
All Go tests and go vet passed
```

Evidence artifacts:

```text
VALIDATION_CHECKPOINT.md
CONTROLLED_CALIBRATION_REPORT.md
PREDEPLOY_SECURITY_GATE.md
LOCAL_TEST_VALIDATION.md
```

Windows PostgreSQL conflict resolution:

```text
postgresql-x64-18 is stopped and startup is Disabled.
The installation and its data were not deleted.
Docker pgproxy owns 127.0.0.1:5432.
```

---

## 4. Critical Safety and Scope Rules

These rules are mandatory.

### 4.1 Real production data must never be used

Do not use:

```text
real citizen data
real cardholder data
real healthcare data
real customer PII
real government records
real production credentials
```

Use only fake/synthetic data.

### 4.2 Never replay attacker payloads against a real database

Captured attacker queries must be replayed only against:

```text
sandbox database
sanitized schema clone
disposable clone
fake dataset
isolated test environment
```

### 4.3 Do not impersonate real regulated entities

If the project is deployed publicly, it must use:

```text
fictional company
fictional brand
fake records
no real logos
no real government/bank/credit-card branding
```

### 4.4 Do not retaliate or scan attackers back

The system may collect inbound behavior. It must not attack, scan, exploit, or retaliate against remote sources.

### 4.5 Public internet deployment requires a security gate

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
Control APIs private
Egress restricted
Budget alerts enabled
Kill switch ready
Logs redact secrets/passwords
```

---

## 5. Execution Roadmap: Real Required Work Only

Do these in order.

---

### Phase 1 — Finish and freeze AI Agent v1

Goal:

```text
Finalize deterministic JSON + Markdown incident reporter.
```

Tasks:

```text
[x] Verify current ai_agent/main.py is the final working version.
[x] Verify /healthz.
[x] Verify /readyz.
[x] Verify /brief/latest.
[x] Verify /brief/markdown.
[x] Run baseline low-risk test.
[x] Run fresh high-risk trap event test.
[x] Run attacker attribution test.
[x] Update HARDENING_VALIDATION_SUMMARY.md.
[x] User review and manual commit.
```

Tests:

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

### Phase 2 — Build attacker evidence store

Goal:

```text
Create a clean evidence model so one attacker session can be traced from connection to AI report.
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
```

Implementation guidance:

```text
Use existing session-module/MITRE flow where possible.
Do not duplicate existing event structures unnecessarily.
Add missing fields consistently.
Preserve session_id across all modules.
Hash or redact credentials/secrets.
```

Tests:

```text
[x] Connect to MySQL honeypot → session created.
[x] Connect to PostgreSQL honeypot → session created.
[x] Send query → raw/normalized query stored.
[x] Trigger trap → MITRE event linked to same session.
[x] Scaling event generated → linked to same session.
[x] AI report generated → linked to same session.
[x] User review and manual commit.
```

Acceptance:

```text
One attacker session can be traced end-to-end:
connection → query → MITRE event → scaling event → AI report.
```

---

### Phase 3 — Build sandbox replay engine

Goal:

```text
Replay captured attacker attempts safely against sandbox databases, never production.
```

Create new service:

```text
sandbox-replay-engine
```

Suggested files:

```text
sandbox_replay/
  Dockerfile
  requirements.txt or go.mod
  main.py or cmd/server
docker-compose.sandbox.yml
```

Core API proposal:

```text
GET  /healthz
GET  /readyz
POST /replay/session/{session_id}
GET  /replay/result/{replay_id}
```

Input:

```text
session_id
protocol: mysql/postgres
captured queries
replay mode: execute/simulate
```

Output:

```text
replay_id
session_id
query_count
executed_count
simulated_count
blocked_count
timeout_count
findings[]
```

Finding fields:

```text
query
query_normalized
classification
replay_mode
would_succeed
severity
affected_object
reason
recommended_countermeasure
```

Query policy:

```text
SELECT / SHOW / information_schema / pg_catalog → execute on sandbox
DROP / DELETE / UPDATE / ALTER / TRUNCATE → block or simulate by default
long-running query → timeout
unknown dangerous query → block and mark unsafe
```

Safety requirements:

```text
No real DB connection.
Fake/sanitized schema only.
Strict timeout.
Restricted network.
Disposable/rebuildable sandbox DB.
No outbound internet from replay worker if possible.
```

Tests:

```text
[x] Captured SELECT query replays successfully.
[x] Captured schema enumeration replays successfully.
[x] DROP TABLE is blocked/simulated.
[x] DELETE is blocked/simulated.
[x] Long query is killed by timeout.
[x] Replay result links back to session_id.
[x] User review and manual commit.
```

Acceptance:

```text
Captured attacker behavior can be tested safely without touching any real database.
```

---

### Phase 4 — Build hardening recommendation engine

Goal:

```text
Convert sandbox replay results into actionable database hardening recommendations.
```

This may be part of `sandbox-replay-engine` or a separate module.

Required output fields:

```text
issue
evidence
affected_object
severity
recommended_fix
verification_step
```

Examples:

```text
Metadata enumeration succeeded
→ restrict metadata visibility / revoke excess privileges.

Sensitive-looking table readable by weak role
→ reduce table privileges / remove public grants.

Resource-heavy query succeeds
→ add timeout / limit / index / rate control.

Destructive query would be possible
→ revoke DROP/DELETE/ALTER from exposed role.
```

Tests:

```text
[x] Replay shows sandbox weakness.
[x] Recommendation generated.
[x] Apply fix in sandbox.
[x] Replay same attack again.
[x] Attack fails after fix.
[x] AI report includes before/after result.
[x] User review and manual commit.
```

Acceptance:

```text
Captured attacker query → sandbox weakness → hardening fix → replay confirms fix works.
```

---

### Phase 5 — Add persistent scaling state

Goal:

```text
Scaling-agent restart must not erase attack/scaling state.
```

Use Redis if possible, because Redis already exists in the project.

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

Tests:

```text
[x] Trigger high-risk event.
[x] Replica target becomes 3.
[x] Restart scaling-agent.
[x] Replica target restored.
[x] trap_triggers restored.
[x] recent scale events restored.
[x] scale-down timer not incorrectly reset.
[x] User review and manual commit.
```

Acceptance:

```text
Scaling-agent restart does not erase operational state.
```

---

### Phase 6 — Fix Prometheus metric consistency

Goal:

```text
Internal scaling-agent metrics and Prometheus metrics must agree.
```

Known bug:

```text
scaling-agent trap_triggers = nonzero
Prometheus capstone_mitre_trap_triggers_total = 0
```

Fix this by ensuring metrics exported by scaling-agent or metrics-bridge reflect real state.

Must align:

```text
scaling-agent /metrics
Prometheus query
Grafana dashboard
AI evidence block
```

Tests:

```text
[x] Trigger trap event.
[x] scaling-agent trap_triggers increments.
[x] Prometheus trap metric increments.
[x] AI report shows same trap count.
[x] Grafana shows same trap count.
[x] User review and manual commit.
```

Acceptance:

```text
No contradiction between scaling-agent, Prometheus, Grafana, and AI report.
```

---

### Phase 7 — Add Kafka idempotency and replay safety

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

Implementation guidance:

```text
Create deterministic event_id if upstream does not provide one:
session_id + technique_id + rule_id + normalized timestamp bucket + query hash.
Use Redis or compact store for processed event ids.
Make updates idempotent.
```

Tests:

```text
[x] Send same MITRE event once → processed.
[x] Send same event five more times → ignored as duplicate.
[x] Restart scaling-agent → no duplicate scaling.
[x] Replay topic from old offset → no inflated trap count.
[x] Invalid JSON → DLQ.
[x] Missing session_id → DLQ.
[ ] User review and manual commit.
```

Acceptance:

```text
Replay and duplicate events do not corrupt scaling or trap counts.
```

---

### Phase 8 — Add operator controls

Goal:

```text
Human operator can safely stop, override, or roll back automation.
```

Required controls:

```text
safe mode
manual replica target
rollback to baseline
max replica budget
autoscaling enable/disable
control audit log
```

Suggested endpoints:

```text
GET  /control/status
POST /control/safe-mode
POST /control/manual-target
POST /control/max-budget
POST /control/rollback
POST /control/autoscaling/enable
POST /control/autoscaling/disable
```

Tests:

```text
[x] Enable safe mode.
[x] Inject high-risk event.
[x] No auto scale-up happens.
[x] Set manual target.
[x] Manual target respected.
[x] Rollback to baseline.
[x] Disable safe mode.
[x] Autoscaling works again.
[x] AI report mentions safe mode/manual override.
```

Acceptance:

```text
Operator can safely override automation.
```

---

### Phase 9 — Real Kubernetes deployment and KEDA scaling

Goal:

```text
Prove autoscaling is physical, not only logical.
```

Tasks:

```text
[x] Build images.
[x] Tag images.
[x] Push to registry or load into cluster.
[x] Deploy namespace.
[x] Deploy services.
[x] Deploy Prometheus.
[x] Deploy KEDA.
[x] Deploy ScaledObject.
[x] Deploy HPA.
```

Tests:

```text
[x] Pods start successfully.
[x] Prometheus scrapes metrics.
[x] KEDA ScaledObject Ready=True.
[x] HPA created.
[x] External metric readable.
[x] High-risk/pressure event scales pods 1 → 2 or 1 → 3.
[x] Scale-down happens after stabilization.
```

Acceptance:

```text
Real Kubernetes pods physically scale based on project telemetry.
```

---

### Phase 10 — Build Grafana dashboards and alerts

Goal:

```text
Operator can observe attack → MITRE → scaling → AI report → sandbox result.
```

Dashboard panels must include:

```text
active sessions
query rate
MITRE events
trap triggers
scale pressure
current replicas
scale-up/down events
AI risk level
sandbox replay results
hardening recommendations
DLQ count
```

Alerts must include:

```text
trap trigger > 0
risk high/critical
DLQ increasing
AI agent down
scaling-agent down
KEDA not ready
replicas at max budget
sandbox replay finds exploitable weakness
```

Tests:

```text
[x] Trigger attack.
[x] Dashboard shows MITRE event.
[x] Dashboard shows trap trigger.
[x] Dashboard shows scale-up.
[x] Dashboard shows AI risk HIGH.
[x] Alert fires.
[x] Alert clears after recovery.
```

Acceptance:

```text
Attack-to-response pipeline is visible and alertable.
```

---

### Phase 11 — Controlled load and calibration tests

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

Metrics to collect:

```text
p50/p95/p99 latency
events per second
Kafka lag
MITRE processing latency
scaling decision latency
AI brief latency
CPU/memory
false positives
false negatives
precision
recall
F1 score
```

Tests:

```text
[x] Benign traffic stayed LOW (5/5 bounded cases).
[x] Recon traffic became MEDIUM with T1213.006 (3/3 bounded cases).
[x] Trap-trigger traffic became CRITICAL with T1213.006 (5/5 bounded cases).
[x] Scale-up happened under pressure.
[x] Scale-down behavior remains covered by the validated scaling suite and prior acceptance.
[x] AI reports were generated during the bounded run.
```

Acceptance:

```text
The system is accurate and stable under controlled workloads.
```

Local bounded acceptance passed in `CONTROLLED_CALIBRATION_REPORT.md`. The
perfect classification result applies only to the 13-case synthetic matrix and
must not be presented as general real-world accuracy.

---

### Phase 12 — Security gate before public internet deployment

Goal:

```text
Ensure public exposure cannot leak real data, expose admin services, or cause harm.
```

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
Control APIs private
Egress restricted
Budget alerts enabled
Kill switch ready
Logs redact secrets/passwords
```

Acceptance:

```text
Public exposure is limited to controlled honeypot endpoints only.
```

The local pre-deployment portion passed 17/17 checks in
`PREDEPLOY_SECURITY_GATE.md`. Cloud egress enforcement, cloud budget-alarm
delivery, public firewall validation, and provider-level kill-switch validation
remain deployment-specific gates and must be completed during Phase 13.

---

### Phase 13 — Deploy fictional company honeypot to cloud

Goal:

```text
Collect real-world scanner/attacker behavior safely.
```

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
sandbox replay engine
scaling-agent controls
```

Tests after deployment:

```text
[ ] Public MySQL honeypot reachable.
[ ] Public PostgreSQL honeypot reachable.
[ ] Admin services not reachable publicly.
[ ] Scanner connection captured.
[ ] Query captured.
[ ] MITRE event generated.
[ ] AI report generated.
[ ] Sandbox replay result generated.
[ ] Alert fires.
[ ] Kill switch works.
[ ] Budget alarm works.
```

Acceptance:

```text
Real internet traffic is safely captured and processed end-to-end.
```

---

### Phase 14 — Real-world observation period

Goal:

```text
Collect anonymized real-world evidence.
```

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

### Phase 15 — Final research validation

Goal:

```text
Produce reproducible evidence for paper/report.
```

Experiments:

```text
1. Deception realism
2. MITRE detection accuracy
3. Autoscaling effectiveness
4. Sandbox replay and hardening loop
5. AI report correctness
6. Reliability under restart/replay/failure
7. Real-world dataset summary
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
```

Acceptance:

```text
Controlled test results + anonymized real-world evidence + reproducible graphs are available.
```

---

## 6. What Not To Do Yet

Do not prioritize these before the above roadmap:

```text
multi-node Redpanda HA
multi-node Prometheus HA
multi-region deployment
full enterprise TLS mesh
real production database integration
real customer data testing
```

AI Agent v2 local deterministic mode is complete. Adding a paid or external LLM
provider remains optional and must preserve the same evidence-only boundaries;
it must never make risk or scaling decisions.

Correct AI model split:

```text
Deterministic modules decide facts:
  risk level
  trap count
  attacker session
  exploitability
  scale target

Optional LLM explains facts:
  executive summary
  timeline
  natural language report
  operator checklist
```

---

## 7. Recommended Final Git Policy

Do not push partial/broken work.

For each phase:

```powershell
$git = "C:\Program Files\Git\cmd\git.exe"
& $git status --short
# run tests
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

## 8. Final Completion Definition

The project is complete for research-paper purposes when all of these are true:

```text
[x] Fake MySQL/PostgreSQL endpoints are reachable locally.
[x] Real database backends are isolated and never directly exposed to attackers.
[x] Attacker/scanner queries are captured.
[x] Sessions are correlated end-to-end.
[x] MITRE techniques are emitted.
[x] Trap events produce high-risk classification.
[x] Scaling-agent scales logically under attack.
[x] Kubernetes/KEDA scales physically under pressure.
[x] AI Agent v1 produces correct JSON and Markdown reports.
[x] Bounded AI v2 produces evidence-cited deterministic reports.
[x] Sandbox replay safely tests captured queries.
[x] Hardening recommendations are generated.
[x] Before/after sandbox replay proves fixes work.
[x] Metrics are consistent across scaling-agent, Prometheus, Grafana, and AI evidence.
[x] Duplicate/replayed Kafka events are idempotent.
[x] Operator safe mode/manual override/rollback works.
[x] Controlled local calibration tests are documented.
[x] Local pre-deployment security gate passes.
[ ] Public cloud honeypot passes provider-specific deployment gate.
[ ] Real-world evidence is collected safely and anonymized.
[ ] Final graphs and validation artifacts exist for the paper.
```

---

## 9. Immediate Next Step For Codex

Local implementation, observability, bounded AI reporting, controlled
calibration, and the local security gate are complete. Stop for user review and
manual commit. The exact next implementation phase is Phase 13, fictional-company
cloud honeypot deployment, and it must not begin without explicit user approval
and provider selection. During that phase, enforce and validate cloud egress,
budget alarms, honeypot-only public firewall rules, and the provider kill switch
before collecting any traffic. Keep Grafana, Prometheus, Kafka/Redpanda, Redis,
AI, sandbox, evidence, and control APIs private.

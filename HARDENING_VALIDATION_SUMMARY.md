# Capstone Hardening Validation Summary

## Final Status

| Phase | Area | Status |
|---|---|---|
| 1 | Kafka dead-letter handling | PASS |
| 2 | Baseline regression validation | PASS |
| 3 | Deception-engine health/readiness | PASS |
| 4 | /decide input validation | PASS |
| 5 | /decide rate limiting | PASS |
| 6 | Kafka publish failure handling | PASS |
| 7 | Deterministic fake-data seeding | PASS |
| 8 | Security cleanup | PASS |
| 9 | AI Agent v1 incident briefing | PASS |
| 10 | Attacker evidence store | PASS |

## Key Hardening Completed

- Invalid Kafka records are routed to `dead-letter-events` instead of crashing consumers.
- Baseline MySQL/PostgreSQL deception behavior remains functional.
- Deception engine exposes `/health`, `/healthz`, `/ready`, and `/readyz`.
- `/decide` rejects malformed requests and unsupported protocols.
- `/decide` applies Redis-backed per-session rate limiting.
- Proxy publishers retry Kafka sends and drop bounded batches after retry exhaustion.
- Fake data generation is deterministic across deception-engine restarts.
- Committed weak passwords were replaced with `.env`-driven variables.
- Generated cache, scratch output, and local secret files are excluded from submission.

## Notes

- `.env` is local-only and must not be committed.
- `.env.example` is committed as the template for required local secrets.
- Docker services bind published host ports to `127.0.0.1` for local demo safety.
- `0.0.0.0` inside containers is acceptable because host publishing remains local-only.

## Scaling-Agent Validation

| Test | Expected Result | Actual Result | Status |
|---|---|---|---|
| Scaling-agent startup | Service starts and exposes metrics | Service running on 127.0.0.1:9095 | PASS |
| MITRE signal ingestion | Consume MITRE events from Kafka | Fresh MITRE event consumed | PASS |
| Scale-up decision | Critical trap signal increases target replicas | SCALE UP from 1 to 7 | PASS |
| Scale-down hysteresis | Sustained low-risk signal decreases target replicas | SCALE DOWN from 7 to 6 | PASS |
| Metrics endpoint | Expose current scaling state | current_replicas=6, scale_up_events=1, scale_down_events=1 | PASS |
| Scaling events endpoint | Show recent scaling decisions | /scale/events returned 4 scaling events | PASS |

### Scaling Notes

- In Docker Compose, the scaling-agent computes and exposes the desired replica target.
- The current deployment demonstrates observable adaptive scaling logic.
- Physical container scaling is not performed in Docker Compose.
- In Kubernetes, the exposed KEDA-compatible endpoint can be connected to KEDA/HPA for real autoscaling.

## Metric-Based Scaling Validation

| Test | Expected Result | Actual Result | Status |
|---|---|---|---|
| Prometheus query API | Scaling-agent can query Prometheus metrics | Prometheus API reachable on 127.0.0.1:9096 | PASS |
| Metrics bridge scrape | Proxy and scaling metrics exposed | metrics-bridge exported pgproxy, mysqlproxy, scaling-agent, and MITRE metrics | PASS |
| Metric collector startup | Scaling-agent starts Prometheus collector | metric-based scaling collector started | PASS |
| Metric pressure calculation | Connection-rate burst raises pressure | metric pressure reached 1.0 from pgproxy connection rate | PASS |
| Metric-based scale-up | High metric pressure increases replica target | SCALE UP from 1 to 3, then 3 to 5 | PASS |
| Metric-based scale-down | Sustained low metric pressure decreases replica target | SCALE DOWN after elapsed_seconds=133 with required_seconds=120 | PASS |
| Intent separation | Metric test should not require MITRE trap signal | trap_triggers remained 0 | PASS |

### Metric Scaling Notes

- Metric-based scaling uses Prometheus metrics from metrics-bridge.
- The validated load signal was pgproxy connection-rate pressure.
- The scaler reused the same safeguards as intent-based scaling: max-step, cooldown, scale-down threshold, and hysteresis.
- In Docker Compose, this updates the desired replica target exposed through metrics.
- Kubernetes KEDA/HPA integration is still required for physical pod autoscaling.

## Kubernetes/KEDA Physical Autoscaling Plan

| Item | Description | Status |
|---|---|---|
| Kubernetes namespace | Defines isolated capstone-deception namespace | ADDED |
| Deception-engine Deployment | Target workload for physical autoscaling | ADDED |
| Deception-engine Service | Internal service for deception-engine | ADDED |
| Scaling-agent Deployment | Exposes validated scaling pressure metrics | ADDED |
| Scaling-agent Service | Internal service for scaling-agent metrics | ADDED |
| KEDA ScaledObject | Uses Prometheus metric capstone_scaling_scale_pressure | ADDED |
| Kubernetes README | Documents apply order and validation commands | ADDED |

### Kubernetes Scaling Notes

- Docker Compose validates logical scaling decisions.
- Kubernetes/KEDA manifests define the physical pod autoscaling path.
- KEDA will scale the deception-engine Deployment using the validated capstone_scaling_scale_pressure metric.
- Physical scaling requires a Kubernetes cluster with KEDA installed and Prometheus reachable as http://prometheus:9090.
## Kubernetes/KEDA Live Validation Attempt

| Check | Result |
|---|---|
| Minikube cluster | PASS |
| KEDA installation | PASS |
| KEDA CRDs | PASS |
| KEDA pods | PASS |
| ScaledObject creation | PASS |
| HPA creation | PASS |
| External metric recognized by HPA | PASS |
| Application pod runtime | PENDING - local images not loaded into minikube |

### Live Validation Note

A one-time minikube validation confirmed that KEDA accepts the Prometheus ScaledObject and creates an HPA for the deception-engine Deployment. The HPA successfully recognized the external Prometheus metric. Application pods entered ImagePullBackOff because the local Docker images were not loaded into minikube during this validation attempt.

Validation evidence:

- KEDA pods were Running.
- ScaledObject deception-engine-prometheus-scaler was Ready=True.
- HPA keda-hpa-deception-engine-prometheus-scaler was created.
- HPA target was Deployment/deception-engine.
- HPA metric target showed 0/600m, confirming the external metric was readable but below activation/scale threshold.
## Kubernetes/KEDA Forced Physical Scaling Test

| Check | Result |
|---|---|
| Temporary dummy Deployment | PASS |
| KEDA ScaledObject | PASS |
| HPA creation | PASS |
| External Prometheus metric read by HPA | PASS |
| Physical Kubernetes replica increase | PASS |
| Cleanup of test namespace | PASS |

### Forced Scaling Evidence

A forced Prometheus query using `vector(1)` was used to verify the physical Kubernetes scaling path independently of application image availability.

Observed result:

- HPA target showed `500m/600m`.
- HPA replicas increased to `2`.
- Deployment `deception-engine` reached `2/2` ready replicas.
- Two pods were Running.
- HPA emitted `SuccessfulRescale` with `New size: 2`.

### Interpretation

This confirms that KEDA and HPA can physically scale a Kubernetes Deployment from an external Prometheus metric. The previous real capstone metric test did not trigger scaling because `capstone_scaling_scale_pressure` stayed at `0`, so real capstone-metric-driven Kubernetes scaling remains dependent on generating a non-zero pressure metric.


## AI Agent Integration Validation

| Check | Result |
|---|---|
| AI agent service files | PASS |
| Docker Compose AI override | PASS |
| Container startup | PASS |
| Health endpoint | PASS |
| Readiness endpoint | PASS |
| JSON brief endpoint | PASS |
| Markdown brief endpoint | PASS |
| Scaling-agent dependency | PASS |
| Prometheus dependency | PASS |

### AI Agent Notes

The first AI-agent integration adds a local FastAPI service that generates a review-friendly operational brief from scaling-agent and Prometheus telemetry.

Validated endpoints:

- GET /healthz
- GET /readyz
- GET /brief/latest
- GET /brief/markdown

The agent currently provides risk level, scaling interpretation, telemetry evidence, recent scaling events, and recommended response actions.

## AI Agent v1 Final Validation (2026-08-20)

| Check | Result |
|---|---|
| AI service consolidated into `docker-compose.yml` | PASS |
| Temporary `docker-compose.ai.yml` removed | PASS |
| Compose configuration validation | PASS |
| Baseline health and readiness | PASS |
| Baseline classification | PASS - LOW |
| JSON brief endpoint | PASS |
| Markdown brief endpoint | PASS |
| Synthetic high-risk MITRE trap event | PASS |
| Scaling-agent logical scale-up | PASS - 1 to 3 replicas |
| High-risk classification | PASS - HIGH |
| Attacker session attribution | PASS |
| Prometheus-zero/scaling-agent-nonzero trap fallback | PASS |
| JSON/Markdown risk and attribution consistency | PASS |

### Final Validation Evidence

Baseline telemetry produced `risk_level=low` with one desired replica and zero trap
triggers. A clearly synthetic event was then published to the local `mitre-events`
topic using session ID `phase1-ai-attribution-1787209194` and MITRE technique
`T1213.006`.

The scaling-agent consumed the event, incremented `trap_triggers` to `1`, and
raised its logical replica target from `1` to `3`. The AI agent produced
`risk_level=high`, included the exact synthetic session ID in its summary and
latest high-event evidence, and rendered the same risk and attribution in the
Markdown brief.

During this test, Prometheus still returned `0` for
`capstone_mitre_trap_triggers_total` while the scaling-agent returned `1`. The AI
agent selected the higher authoritative observed count, so the stale Prometheus
value did not suppress the high-risk result. This confirms the AI-side fallback;
the underlying cross-system metric inconsistency remains scheduled for roadmap
Phase 6.

## Attacker Evidence Store Validation (2026-08-20)

| Check | Result |
|---|---|
| Evidence-store image and service startup | PASS |
| Health endpoint | PASS |
| Redis/Redpanda/scaling readiness | PASS |
| AI readiness includes evidence store | PASS |
| SQL and credential redaction unit tests | PASS - 5 tests |
| MySQL connection and query evidence | PASS |
| PostgreSQL connection and query evidence | PASS |
| Source IP anonymization | PASS |
| Raw and normalized query correlation | PASS |
| MITRE `T1213.006` correlation | PASS |
| Trap and risk correlation | PASS |
| Scaling-event ID correlation | PASS |
| AI-report ID correlation | PASS |
| Complete five-stage trace | PASS |
| Redis evidence survives service restart | PASS |

### End-to-End Evidence

Local-only synthetic MySQL and PostgreSQL clients connected through their
respective honeypot proxies. Both sessions produced connection and query
evidence. PostgreSQL session `b8a1796d-5ea7-4eaa-b467-38a4f197ca80` queried the
synthetic `api_keys_backup` trap table and was correlated through:

```text
connection → query → MITRE T1213.006 → scaling event → AI report
```

The resulting evidence record retained the same proxy-generated `session_id`,
an HMAC-anonymized source IP, attempted protocol/database/user, redacted raw and
normalized query text, risk score `12.0`, trap status, a deterministic scaling
event ID, and an AI report ID. Its trace reported all five stages as complete.

The evidence store uses the existing persistent `redis-mitre` volume. Restarting
only the evidence-store container preserved the session, queries, MITRE
techniques, scale event, AI report link, and complete trace.

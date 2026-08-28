# Attacker Evidence Store

The evidence store correlates proxy, authoritative session, adaptive strategy,
MITRE, scaling, AI, replay, hardening, learning, proposal, and analyst-report
evidence. Records are keyed by the proxy-generated `session_id`, assigned a
stable `trace_id`, and persisted in the existing `redis-mitre` volume.

## Inputs

Kafka topics:

- `mysql-query-events`
- `pg-query-events`
- `mysql-session-events`
- `pg-session-events`
- `session-profiles`
- `mitre-events`
- `mitre-sessions`

Scaling events are read from `scaling-agent /scale/events`. AI Agent v1 links
each attacker-attributed report through `POST /evidence/report`.

The store asynchronously reads bounded authoritative state, strategy telemetry,
and decision rewards from the session-module control API. This collector is not
on the attacker-facing SQL path. Replay and hardening results link back through
the internal structured-artifact endpoint.

## API

- `GET /healthz`
- `GET /readyz`
- `GET /evidence/sessions?limit=20`
- `GET /evidence/session/{session_id}`
- `POST /evidence/report`
- `POST /evidence/artifact`

The service is locally bound to `127.0.0.1:8011`. It is an internal control and
evidence API and must not be exposed publicly.

## Evidence model

Each version-2 session record includes:

- anonymized source-IP HMAC;
- protocol, attempted database/user, and fingerprint;
- redacted raw and normalized queries;
- confirmed response outcome metadata (never database row contents);
- connection and session-profile events;
- authoritative session-state snapshots;
- MITRE technique, risk, and trap evidence;
- strategy decisions and reward vectors;
- deterministic scaling-event IDs;
- AI report IDs;
- replay results and hardening findings;
- learning analyses, proposal IDs, and analyst-report IDs when those phases
  produce them;
- a per-stage trace-completeness block with explicit missing stages.

Lists are bounded, duplicate source events are ignored, and session evidence has
a configurable 30-day default TTL. The IP hashing salt can be supplied through
`EVIDENCE_IP_HASH_SALT`; otherwise it is randomly generated once and persisted
inside Redis.

## Safety

SQL string literals, credential-like assignments, long numeric literals, and
long hexadecimal literals are redacted before storage. Structured artifacts are
size/depth/count bounded, non-finite numbers and cross-session links are rejected,
and secret/source-address keys are redacted recursively. Source IPs are never
returned or persisted in plaintext. Only synthetic honeypot data may be used,
and this service must never receive or replay production data.

Supported internal artifact types are `session_state`, `strategy_decision`,
`strategy_reward`, `replay_result`, `hardening_finding`, `learning_analysis`,
`proposal`, and `analyst_report`. Exact artifact replays are idempotent; a changed
payload with the same logical ID is retained as a bounded later version.

## Validation

```powershell
docker compose -f docker-compose.yml build evidence-store ai-agent
docker compose -f docker-compose.yml up -d evidence-store ai-agent

Invoke-RestMethod http://127.0.0.1:8011/healthz
Invoke-RestMethod http://127.0.0.1:8011/readyz
Invoke-RestMethod http://127.0.0.1:8011/evidence/sessions?limit=5
```

Offline focused validation (does not start Docker or a model):

```powershell
python -m unittest test_evidence_store.py
```

## Phase 20 live checkpoint

On 2026-08-28 the rebuilt evidence-store passed 15/15 focused tests with
networking disabled. Fresh trace `TR-a8437684e8ca48ec82886e12` linked four
confirmed MySQL response outcomes to authoritative state, MITRE/trap evidence,
one immutable strategy decision, reward versions, scaling, AI-v1 reporting,
sandbox replay, and hardening findings. `core_complete` was true. Repeated reads
across multiple collector cycles kept the decision count and `last_seen` stable.

The full-trace flag remains false until later phases produce a learning analysis,
proposal, and Analyst Agent report; those absences are reported explicitly and
are not manufactured during Phase 20 validation.

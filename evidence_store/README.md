# Attacker Evidence Store

The evidence store correlates existing proxy, session, MITRE, scaling, and AI
telemetry without changing the producer schemas. Records are keyed by the proxy
generated `session_id` and persisted in the existing `redis-mitre` volume.

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

## API

- `GET /healthz`
- `GET /readyz`
- `GET /evidence/sessions?limit=20`
- `GET /evidence/session/{session_id}`
- `POST /evidence/report`

The service is locally bound to `127.0.0.1:8011`. It is an internal control and
evidence API and must not be exposed publicly.

## Evidence model

Each session record includes:

- anonymized source-IP HMAC;
- protocol, attempted database/user, and fingerprint;
- redacted raw and normalized queries;
- connection and session-profile events;
- MITRE technique, risk, and trap evidence;
- deterministic scaling-event IDs;
- AI report IDs;
- a trace-completeness block for the five pipeline stages.

Lists are bounded, duplicate source events are ignored, and session evidence has
a configurable 30-day default TTL. The IP hashing salt can be supplied through
`EVIDENCE_IP_HASH_SALT`; otherwise it is randomly generated once and persisted
inside Redis.

## Safety

SQL string literals, credential-like assignments, long numeric literals, and
long hexadecimal literals are redacted before storage. Source IPs are never
returned or persisted in evidence records in plaintext. Only synthetic honeypot
data may be used, and this service must never receive or replay production data.

## Validation

```powershell
docker compose -f docker-compose.yml build evidence-store ai-agent
docker compose -f docker-compose.yml up -d evidence-store ai-agent

Invoke-RestMethod http://127.0.0.1:8011/healthz
Invoke-RestMethod http://127.0.0.1:8011/readyz
Invoke-RestMethod http://127.0.0.1:8011/evidence/sessions?limit=5
```


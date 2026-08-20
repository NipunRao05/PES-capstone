# Sandbox Replay Engine

The sandbox replay engine replays queries that were already captured by the
attacker evidence store. It does not accept arbitrary SQL and it never connects
to a protected or production database.

## API

The local API is published only on `127.0.0.1:8012` through a small Nginx
gateway:

```text
GET  /healthz
GET  /readyz
POST /replay/session/{session_id}
GET  /replay/result/{replay_id}
POST /hardening/report/{replay_id}
POST /hardening/verify/{hardening_report_id}
GET  /hardening/report/{hardening_report_id}
GET  /hardening/latest
```

Start an execution replay:

```powershell
$body = @{ mode = "execute" } | ConvertTo-Json
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8012/replay/session/<session_id> `
  -ContentType application/json `
  -Body $body
```

Use `mode=simulate` to classify captured queries without executing allowed
reads. Replay results are stored in Redis for seven days and remain linked to
the original `session_id`.

## Hardening workflow

Recommendations are generated deterministically from a stored execution replay.
They contain `issue`, `evidence`, `affected_object`, `severity`,
`recommended_fix`, and `verification_step` fields.

```powershell
$report = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8012/hardening/report/<replay_id> `
  -ContentType application/json `
  -Body '{}'

$verified = Invoke-RestMethod `
  -Method Post `
  -Uri ("http://127.0.0.1:8012/hardening/verify/" + $report.hardening_report_id) `
  -ContentType application/json `
  -Body '{}'
```

Verification applies only built-in, allowlisted fixes to the disposable
sandbox. For a sensitive-table exposure, the engine revokes `SELECT` from the
sandbox replay role, replays the same captured session, and records both replay
summaries. Caller-supplied SQL and unknown request fields are rejected. Metadata
visibility recommendations are marked for manual follow-up rather than applying
an engine-specific change automatically.

Hardening reports are stored in Redis for seven days. `GET /hardening/latest`
provides the most recently generated or verified report to the deterministic AI
incident brief.

## Safety model

```text
loopback API gateway
        |
control-internal network
        |
sandbox-replay-engine (no default network, read-only root filesystem)
        |
sandbox-internal network
        |
disposable PostgreSQL and MySQL databases with synthetic data
```

- The worker can fetch only captured evidence and has no default/outbound
  Docker network.
- Sandbox databases have no published host ports and use disposable `tmpfs`
  data directories.
- Database credentials come from the local `.env`; no secrets are committed.
  The PostgreSQL replay and administrative roles use different credentials.
- Administrative credentials are valid only for the disposable sandbox
  databases and are used solely by the fixed `revoke_select` action. The API
  cannot execute caller-provided fixes or SQL.
- The replay role has read-only grants. PostgreSQL also enforces a read-only
  transaction and statement timeout; MySQL starts a read-only transaction.
- The worker runs as unprivileged user `65532:65532`, with all Linux
  capabilities dropped, no-new-privileges, a read-only root filesystem, and a
  process limit.
- Each replay is limited to 100 captured queries, four concurrent jobs, and a
  750 ms per-query timeout by default.

## Query policy

| Query class | Execute mode | Simulate mode |
|---|---|---|
| PostgreSQL `SELECT` | Execute in sandbox | Simulate |
| MySQL `SELECT`, `SHOW`, `DESCRIBE`, `DESC` | Execute in sandbox | Simulate |
| Schema enumeration reads | Execute in sandbox | Simulate |
| Resource-intensive reads such as `pg_sleep` | Execute with timeout | Simulate |
| `DROP`, `DELETE`, `UPDATE`, `ALTER`, `TRUNCATE`, `INSERT` | Block | Block |
| Multiple statements, CTEs, external/file functions, unknown SQL | Block | Block |

The policy is deliberately deny-by-default. Application policy and database
permissions are independent safeguards: a write remains rejected by the
read-only database role if the application policy is bypassed.

## Local validation

```powershell
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose.yml up -d --build `
  sandbox-postgres sandbox-mysql sandbox-replay-engine sandbox-replay-api

Invoke-RestMethod http://127.0.0.1:8012/healthz
Invoke-RestMethod http://127.0.0.1:8012/readyz | ConvertTo-Json -Depth 8

docker run --rm --network none `
  --mount type=bind,source="${PWD}\sandbox_replay",target=/app,readonly `
  -w /app capstone-main-sandbox-replay-engine `
  python -m unittest -v test_policy.py test_hardening.py
```

Only synthetic schemas and records in `sandbox_replay/init` are used by the
disposable databases.

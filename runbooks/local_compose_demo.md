# Local Compose demo runbook

This stack is designed to run from the repository root with the top-level `docker-compose.yml`.

## 1. Preflight without Docker

```bash
python scripts/offline_smoke.py
```

Expected result: all checks print `[OK]`.

## 2. Generate Go checksums on a machine with network access

The sandbox used for patching cannot reach `proxy.golang.org`, so the Go modules still need normal checksum generation locally:

```bash
(cd mysqlproxy && go mod tidy)
(cd pgproxy && go mod tidy)
(cd scaling_agent && go mod tidy)
```

Commit the resulting `go.sum` changes before trying offline builds.


## Optional: replay existing Redpanda messages after restarting analytics

By default the analytics consumers start at the latest offset for a clean live demo. To replay existing topic data during debugging, set this before starting Compose:

```bash
export CONSUMER_AUTO_OFFSET_RESET=earliest
```

Then restart `session-module` and `mitre-agent`. Do not use `earliest` during a timed demo unless you intentionally want old events replayed.

## 3. Start the unified stack

```bash
docker compose up --build
```

Useful URLs:

- Grafana: <http://localhost:3000> — admin / capstone
- Prometheus: <http://localhost:9096>
- Metrics bridge: <http://localhost:9100/metrics>
- Session module metrics: <http://localhost:8000/metrics>
- Deception engine readiness: <http://localhost:8001/readyz>
- MITRE agent readiness: <http://localhost:8002/readyz>
- Scaling agent JSON: <http://localhost:9095/metrics>

## 4. Exercise the proxies

**Port conflict note:** the default stack binds PostgreSQL proxy to `127.0.0.1:5432`, MySQL proxy to `127.0.0.1:3306`, session metrics to `127.0.0.1:8000`, and MITRE readiness to `127.0.0.1:8002`. Stop local PostgreSQL/MySQL first, or start Compose with `PGPROXY_HOST_PORT=15432 MYSQLPROXY_HOST_PORT=13306 docker compose up --build`. You can also override `SESSION_MODULE_HOST_PORT` and `MITRE_AGENT_HOST_PORT` if those health ports conflict.

PostgreSQL through the proxy:

```bash
psql -h 127.0.0.1 -p 5432 -U postgres -d testdb
```

Password: `password`

Example probes:

```sql
select version();
select * from pg_tables limit 5;
select * from api_keys_backup limit 5;
```

MySQL through the proxy:

```bash
mysql -h 127.0.0.1 -P 3306 -u proxyuser -ppassword testdb
```

Example probes:

```sql
show databases;
show tables;
select @@hostname;
select * from api_keys_backup limit 5;
```

## 5. Verify events

```bash
docker compose exec -T redpanda rpk topic list

docker compose exec -T redpanda rpk topic consume mysql-query-events --num 5 --offset start
docker compose exec -T redpanda rpk topic consume pg-query-events --num 5 --offset start
docker compose exec -T redpanda rpk topic consume session-profiles --num 10 --offset start
docker compose exec -T redpanda rpk topic consume mitre-events --num 10 --offset start
docker compose exec -T redpanda rpk topic consume mitre-sessions --num 10 --offset start
```

For a readable demo summary on Windows PowerShell:

```powershell
.\scripts\demo_runtime_probe.ps1 -FailedAuthCount 3 -SessionWaitSeconds 45 -ConsumeNum 25
```

For a pass/fail milestone check, add `-AssertMilestones`:

```powershell
.\scripts\demo_runtime_probe.ps1 -FailedAuthCount 3 -SessionWaitSeconds 45 -ConsumeNum 75 -AssertMilestones
```

The brute-force milestone is a MITRE event or session containing `T1110.001`. The enumeration milestone is a `mitre-events` record containing `T1213.006` after `SHOW DATABASES` / `SHOW TABLES`.

## 6. Expected evaluator-facing story

The dashboard should show this flow:

```text
proxy query/session events → session profile → MITRE session → actor metrics → scaling pressure
```

Deception engine is deployed but still not wired into proxy response generation. Do not present it as active packet-level deception until the proxy-side encoders are implemented.

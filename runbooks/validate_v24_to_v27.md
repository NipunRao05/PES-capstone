# Validate patches v24 through v27

This checklist assumes you are running from the repository root on Windows PowerShell.

## v24 validation — fixed runtime findings

Goal: prove the runtime issues observed after v23 are fixed.

1. Rebuild the affected services:

```powershell
docker compose up -d --build mysqlproxy mitre-agent
```

2. Generate MySQL enumeration traffic:

```powershell
mysql -h 127.0.0.1 -P 3306 -u proxyuser -ppassword testdb -e "SELECT @@version_comment LIMIT 1; SHOW DATABASES; SHOW TABLES; SELECT DATABASE();"
```

If using an alternate host port:

```powershell
mysql -h 127.0.0.1 -P 13306 -u proxyuser -ppassword testdb -e "SELECT @@version_comment LIMIT 1; SHOW DATABASES; SHOW TABLES; SELECT DATABASE();"
```

3. Verify cleaned MySQL query telemetry:

```powershell
docker compose exec -T redpanda rpk topic consume mysql-query-events --num 10 --offset start | python scripts/summarize_rpk_json.py
```

Expected: query text should look like `show databases` / `show tables`, not `\u0000\u0001SHOW DATABASES`.

4. Verify enriched MITRE metadata:

```powershell
docker compose exec -T redpanda rpk topic consume mitre-events --num 20 --offset start | python scripts/summarize_rpk_json.py
```

Expected milestone: `T1213.006` for schema enumeration.

## v25 validation — actor-window brute-force alert

Goal: prove separate failed-login sessions aggregate into one actor-level `T1110.001` alert.

1. Rebuild MITRE agent:

```powershell
docker compose up -d --build mitre-agent
```

2. Trigger a burst of failed MySQL logins:

```powershell
1..3 | ForEach-Object {
  mysql -h 127.0.0.1 -P 3306 -u proxyuser -pwrongpass testdb -e "SELECT 1;" 2>$null
}
```

Alternate port:

```powershell
1..3 | ForEach-Object {
  mysql -h 127.0.0.1 -P 13306 -u proxyuser -pwrongpass testdb -e "SELECT 1;" 2>$null
}
```

3. Wait for session profiles to close:

```powershell
Start-Sleep -Seconds 45
```

4. Verify brute-force milestone:

```powershell
docker compose exec -T redpanda rpk topic consume mitre-events --num 50 --offset start | python scripts/assert_rpk_milestone.py --technique T1110.001 --print-matches
```

Expected: `[OK] technique T1110.001`.

## v26 validation — host health ports and demo probe

Goal: prove the packaged Compose file exposes the same ports you manually tested.

1. Rebuild session and MITRE services:

```powershell
docker compose up -d --build session-module mitre-agent
```

2. Verify host health endpoints:

```powershell
curl.exe http://127.0.0.1:8000/metrics
curl.exe http://127.0.0.1:8002/readyz
```

Expected: session metrics text and MITRE JSON readiness with all consumers true.

3. Run the demo probe:

```powershell
.\scripts\demo_runtime_probe.ps1 -FailedAuthCount 3 -SessionWaitSeconds 45 -ConsumeNum 50
```

Expected: readable summaries for `session-profiles`, `mitre-events`, and `mitre-sessions`.

## v27 validation — milestone assertions

Goal: fail fast if the expected ATT&CK milestones do not appear.

1. Rebuild MITRE only if v27 changed Python code in `mitre_agent`; otherwise scripts do not require rebuild:

```powershell
docker compose up -d --build mitre-agent
```

2. Run the probe with milestone assertions:

```powershell
.\scripts\demo_runtime_probe.ps1 -FailedAuthCount 3 -SessionWaitSeconds 45 -ConsumeNum 75 -AssertMilestones
```

Expected:

```text
[OK] technique T1110.001
[OK] technique T1213.006
```

3. If assertions fail on reused volumes, increase the consumed message count or clear volumes for a fresh demo:

```powershell
.\scripts\demo_runtime_probe.ps1 -FailedAuthCount 3 -SessionWaitSeconds 45 -ConsumeNum 200 -ConsumeOffset start -AssertMilestones
```

For a fully fresh run:

```powershell
docker compose down -v
docker compose up -d --build
.\scripts\demo_runtime_probe.ps1 -FailedAuthCount 3 -SessionWaitSeconds 45 -ConsumeNum 75 -AssertMilestones
```

## Always run the offline suite before runtime validation

```powershell
python scripts/offline_smoke.py
cd session_module; python -m pytest -q; cd ..
cd mitre_agent; python -m pytest -q; cd ..
cd deception_engine; python -m pytest -q; cd ..
cd observability\metrics_bridge; python -m pytest -q; cd ..\..
cd scaling_agent; go test ./internal/scorer ./tests; cd ..
cd mysqlproxy; go test ./internal/interceptor ./internal/session; cd ..
```

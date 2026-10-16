# Run and check the local honeypot

Verified on this Windows checkout on **2026-10-16**. The stack is currently
running. PostgreSQL/MySQL login, physical SQL/state, virtual-principal persistence,
monitoring queries and log delivery passed the checks in VERIFICATION_RESULTS.md.
This runbook is for the deterministic local configuration, not cloud deployment.

## 1. Open PowerShell in the repository

Start Docker Desktop and wait until its engine is running. Then:

~~~powershell
Set-Location F:\b\Capstone-main
$py = 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $py --version
docker version
~~~

This is the Python executable used for verification. If it is unavailable on a
future installation, set $py to your installed Python executable instead. Do not
use the Windows Store python alias. Config tools only need the small requirement
below; application dependencies are built inside Docker images.

~~~powershell
# Only if config-check reports that its YAML dependency is missing:
& $py -m pip install --target .runtime/tooling -r scripts/config-requirements.txt
~~~

## 2. Check configuration

~~~powershell
& $py scripts/honeypot.py config-check
& $py scripts/honeypot.py config-status
~~~

Expect CONFIGURATION VALID and deterministic_rule_based. Future AI, MITRE,
learning, steering and intervention features remain disabled. The full feature
and dependency reference is CONFIGURATION.md.

Keep your existing .env. Its database passwords were aligned with the existing
local accounts during this verification, with your approval. No data volumes were
deleted and the principal HMAC was preserved. Do not copy .env.example over it.
Do not change a password in .env alone: an initialized database retains its old
account password. Grafana also retains its initialized admin account. Keep local
credentials private and do not commit .env or .runtime.

## 3. Build and start

~~~powershell
& $py scripts/honeypot.py compose config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Fix configuration before continuing.' }
& $py scripts/honeypot.py compose up -d --build
if ($LASTEXITCODE -ne 0) { throw 'Startup failed; inspect the reported error.' }
& $py scripts/honeypot.py compose ps
~~~

Use this launcher instead of direct docker compose up. It generates the matching
Compose/Prometheus/Grafana files and removes obsolete containers from this same
project, preserving named volumes. Re-run up after changing canonical YAML; a
restart does not apply a changed environment or feature selection.

The redpanda-init container exiting successfully is normal. Long-running services
should be Up; sandbox databases should become healthy. Allow roughly 30 seconds
for initial readiness and the first Prometheus scrape before the next step. A
first build may take longer if Docker needs to download dependencies.

## 4. Run the repeatable health check

~~~powershell
& $py scripts/verify_runtime.py
if ($LASTEXITCODE -ne 0) { throw 'One or more runtime checks failed.' }
~~~

This makes read-only requests, checks configured service readiness, backend TCP
health, all Prometheus targets, primary dashboard queries, authenticated Grafana
datasources and actual Loki log delivery. It writes a sanitized result to
.runtime/runtime-verification.json. It does not create database traffic.

NOTE No samples can be normal for counters with no matching events, failures
that have never occurred, or histograms without observations. A FAIL is different:
read its check name and use the troubleshooting section below. Backend TCP health
alone does not prove database authentication; the next checks exercise real logins.

## 5. Open the interfaces

| Interface | Address / use |
| --- | --- |
| Grafana | http://127.0.0.1:3000/login — sign in as admin using GRAFANA_ADMIN_PASSWORD from .env |
| Primary dashboard | http://127.0.0.1:3000/d/honeypot-operations — open after signing in |
| Prometheus targets | http://127.0.0.1:9096/targets — all enabled targets should be UP |
| Evidence readiness | http://127.0.0.1:8011/readyz |
| Replay readiness | http://127.0.0.1:8012/readyz |
| PostgreSQL proxy | 127.0.0.1:5432, database testdb, seeded user postgres |
| MySQL proxy | 127.0.0.1:3306, database testdb, seeded admin root or app user proxyuser |

Proxy ports above are defaults; respect PGPROXY_HOST_PORT / MYSQLPROXY_HOST_PORT
if you change them. Use the matching private .env password. These are controlled
local decoys. Grafana anonymous access can return 403 for provisioned dashboards;
use the tested authenticated admin login.

## 6. Run your own bounded functional checks

Physical passthrough and authoritative-state check:

~~~powershell
& $py scripts/verify_state.py
~~~

Expect status PASS. This creates temporary physical tables, checks CRUD,
transactions, schema discovery, policy rejection of physical role creation and
asynchronous state projection, then drops its test tables. It writes
.runtime/state-verification.txt. If interrupted mid-run, inspect test objects
with the phase2_ prefix before repeating; never delete a database volume to clean
up a test. Run only against this local test stack.

Virtual-principal checks use the existing replay image for native DB clients:

~~~powershell
# Use a NEW name each run: disabled principals retain tombstones intentionally.
$name = 'fake_check_' + (Get-Date -Format 'yyyyMMddHHmmss')
& $py tests/principals/run_native_smoke.py create --name $name
if ($LASTEXITCODE -ne 0) { throw 'Principal creation failed; stop this sequence.' }
& $py tests/principals/run_native_smoke.py return --name $name
if ($LASTEXITCODE -ne 0) { throw 'Return-session checks failed; stop this sequence.' }
& $py tests/principals/run_native_smoke.py reconnect --name $name
if ($LASTEXITCODE -ne 0) { throw 'Persistence check failed; stop this sequence.' }
& $py tests/principals/run_native_smoke.py disable --name $name
~~~

Each successful stage prints ok: true for both protocols. This verifies seeded
authentication, no physical synthetic accounts, incorrect-password rejection,
rollback, committed-state reconnect, disconnect rollback and disabled-account
rejection. It deliberately creates synthetic evidence and registry entries;
it is not a read-only check. Leave the disable stage until last. The test driver
uses reserved source addresses and stops if they are already in use.

Refresh Grafana after a scrape interval. Created/reused principals, return-session
links, verified query outcomes and session distributions should reflect traffic.
Existing historical metrics are not expected to start at zero.

## 7. Stop or resume without losing data

~~~powershell
& $py scripts/honeypot.py compose stop
& $py scripts/honeypot.py compose up -d
~~~

Do not use down -v or docker volume rm. The current stack was left running for
your checks; nothing was staged, committed or pushed.

## Troubleshooting

- Docker permission/connection error: run these commands from your normal local
  PowerShell with Docker Desktop running. Agent sandbox permissions are separate.
- Missing Python/YAML: use the executable and local install command in step 1.
- CONFIGURATION INVALID: fix the named setting; do not bypass canonical flags.
- Database authentication failure: .env and initialized account credentials differ.
  Stop and align the account password or restore the correct .env value. Do not
  reset volumes. Password recovery is maintenance, not part of routine startup.
- Prometheus nested read-only mount error: use the updated launcher and run up -d
  again. The corrected generator mounts its two files directly under
  /etc/prometheus, without layering them inside a read-only directory mount.
- Grafana 403: sign in at /login. A 401 after entering the expected password can
  mean the existing Grafana volume still has a different initialized password.
- Initial health failure: inspect logs, allow initialization/scraping to finish,
  then rerun verify_runtime.py. Do not hide persistent failures with repeated restarts.

~~~powershell
& $py scripts/honeypot.py compose logs --tail 80 prometheus grafana
& $py scripts/honeypot.py compose logs --tail 80 deception-engine session-module evidence-store
~~~

Keep operational output private; third-party infrastructure logs and historical
evidence need separate review before sharing. Passing these checks establishes
the covered local behavior, not a guarantee against every future input or change.

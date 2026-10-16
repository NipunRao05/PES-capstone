# Local verification — 2026-10-16

Branch: feature/config-observability; baseline HEAD: 2ab1e04. Current work remains
uncommitted. The user explicitly authorized testing, startup and fixes, superseding
the earlier no-testing restriction. The user also approved aligning existing local
database passwords with .env. See RUN_LOCAL.md for the executable runbook.

## Results

| Check | Observed result |
| --- | --- |
| Canonical config-check | PASS with the current private .env |
| Docker Compose config --quiet | PASS |
| Compose build | All eight application images built successfully |
| Stack startup | PASS after Prometheus mount fix; 21 long-running containers Up at final inspection |
| PostgreSQL Go suite | go test ./... PASS |
| MySQL Go suite | go test ./... PASS |
| Scaling Go suite | go test ./... PASS |
| Metrics bridge unit tests | 5 PASS |
| Canonical configuration regressions | 12 PASS |
| Deception engine unit tests | 95 PASS |
| Evidence Store unit tests | 18 PASS |
| Authoritative/behavior state unit tests | 21 PASS |
| Session processing regression suite | 188 PASS |
| Native PostgreSQL and MySQL | Creation, wrong-password rejection, transaction rollback, reconnect persistence, disconnect rollback, traps and disable PASS |
| Physical synthetic database accounts | Zero for both protocols |
| Deception service restart | Committed synthetic state survived and both protocols reauthenticated |
| Physical SQL/state integration | PASS: PostgreSQL 16 verified outcomes, MySQL 13; expected rejected/error outcomes counted |
| Service readiness | Deception, session, evidence and replay all ready |
| Prometheus | All 9 enabled targets UP |
| Primary dashboard | Provisioned; all 53 PromQL expressions execute successfully |
| Grafana datasources | Authenticated Prometheus and Loki health checks OK |
| Loki | Ready; project logs present |
| Active application metric labels | 209 observed series had no forbidden session/principal/user/IP/query/cluster identifier labels |
| Loki indexed labels | Sampled project streams had no forbidden high-cardinality identifier labels |

Python unit/regression total: **339 passing tests**. Go suites are reported by
package rather than inventing a test-case count. Tests were run against existing
container dependencies where appropriate. Unit tests do not count as live flow
verification; native and physical SQL checks above exercised real local services.

## Failures found and resolved

1. Prometheus could not start: generated files were mounted beneath an existing
   read-only directory mount. The generator now mounts configuration and alerts
   directly under /etc/prometheus, retaining the Prometheus data volume. Added a
   regression assertion against overlapping mount destinations. Monitoring content
   hashes trigger recreation when generated files change; unchanged files keep
   their existing bind-mount inode. Both behaviors have regression coverage.
2. Current .env passwords differed from initialized PostgreSQL/MySQL accounts.
   With user approval, PostgreSQL's existing admin and three existing MySQL
   accounts were aligned to .env. MySQL recovery ran with networking disabled and
   preserved authentication plugins and data. No database volume was deleted;
   .env and the principal HMAC were not changed.
3. The historical state test expected physical role creation through the proxy.
   Current policy intentionally rejects those account statements. Updated the
   test to verify denied creation/SET ROLE, zero physical role creation and the
   correct failed-query count. No runtime account policy was weakened.
4. Native smoke tooling now reuses canonical dotenv parsing and shell precedence.
   Added verify_state.py to run the older PowerShell integration script with the
   generated Compose file and private environment, without printing credentials.

The initial stale state-test run failed; the corrected current-policy run passed.
The first native login attempts failed before password alignment; subsequent
seeded and virtual logins passed. These failures are not omitted from the record.

## Observed evidence and interpretation

New accepted principal creation/authentication events and session links appeared
in the evidence metrics. Both backend and deception authorities had verified
query outcomes for both protocols. First-reuse histogram received two samples.
Persisted aggregate totals included earlier history (6 created, 4 reused, 33
return sessions at one snapshot); these are observations, not controlled research
results or guaranteed fixed values. Re-engagement at that snapshot was 4/6.

No-sample dashboard notes were limited to event classes that had not occurred,
such as failed Kafka publishing and unverified query evidence. Zero samples do
not imply an unhealthy target. Recent Loki inspection found no occurrence of the
generated native-test password or principal HMAC. Naive substring matches against
other configured credentials coincided with ordinary infrastructure terminology;
that scan is not proof of complete historical secret sanitization.

Test principal fake_check_20261016 was disabled after verification on both
protocols. Its tombstones, correlations and synthetic evidence remain intentionally.
Temporary physical tables from the state checks were dropped. Existing user data
and prior evidence were preserved. The full stack is left running.

## Reproduce

Use the interpreter selection in RUN_LOCAL.md, then:

~~~powershell
& $py scripts/honeypot.py config-check
& $py -m unittest discover -s scripts -p test_configuration.py
& $py -m unittest discover -s observability/metrics_bridge -p test_metrics_bridge.py
docker exec -e LOG_LEVEL=ERROR capstone-main-deception-engine-1 python -m unittest discover -p 'test_*.py'
docker exec capstone-evidence-store python -m unittest discover -p 'test_*.py'
docker exec capstone-main-session-module-1 python -m unittest test_authoritative_state test_behavior_state
docker exec -e LOG_LEVEL=ERROR capstone-main-session-module-1 python -m pytest test_session_module.py -q --tb=short
& $py scripts/verify_runtime.py
& $py scripts/verify_state.py
Push-Location pgproxy; go test ./...; Pop-Location
Push-Location mysqlproxy; go test ./...; Pop-Location
Push-Location scaling_agent; go test ./...; Pop-Location
~~~

Native protocol stages and cleanup are documented in RUN_LOCAL.md. Sanitized live
reports are in ignored .runtime/runtime-verification.json and
.runtime/state-verification.txt; these are local evidence, not portable fixtures.

## Limits

Verified the selected default deterministic deployment. Disabled-feature
combinations have offline generation/regression coverage, not a live deployment
matrix. No load/soak campaign, exhaustive adversarial protocol testing, physical
Kubernetes scaling, full sandbox replay job or future adaptive feature activation
was performed. Grafana provisioning and query/datasource APIs were checked; no
browser screenshot/visual layout acceptance was performed. These results establish
specific observed behavior and do not promise absence of all future defects.

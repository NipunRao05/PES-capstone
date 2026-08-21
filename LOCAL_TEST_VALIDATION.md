# Local Regression Validation

Date: 2026-08-21  
Workspace: `F:\b\Capstone-main`  
Deployment performed: No

| Validation | Result |
|---|---|
| Repository offline smoke | PASS (Python compile, JSON/YAML, session, MITRE, deception, RPK helpers) |
| MySQL proxy | PASS: `go test -count=1 ./...`; `go vet ./...` |
| PostgreSQL proxy | PASS: `go test -count=1 ./...`; `go vet ./...` |
| Scaling agent | PASS: `go test -count=1 ./...`; `go vet ./...` |
| AI Agent v1 | PASS: 3 tests |
| Deception engine | PASS: 20 tests |
| Evidence store | PASS: 8 tests |
| Bounded AI v2 | PASS: 9 tests |
| MITRE agent | PASS: 32 tests |
| Sandbox replay/hardening | PASS: 15 tests |
| Session module | PASS: 188 tests |
| Metrics bridge | PASS: 5 tests |
| Python service total | PASS: 280 tests |
| Prometheus configuration | PASS: 26 rules accepted by `promtool` |
| Local security gate | PASS: 17/17 |

The deception test fixtures were updated to the current `/decide` endpoint
signature and current liveness contract. No deception application behavior was
changed for that regression repair.

All expected long-running Compose services are up. `redpanda-init` is exited
with code 0 by design. The native Windows PostgreSQL service remains stopped and
disabled; Docker `pgproxy` is running on `127.0.0.1:5432`.

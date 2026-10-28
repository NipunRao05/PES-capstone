# Permanent baseline test and evidence ledger

Imported/reviewed 2026-10-26 during Phase A at `feature/config-observability`, HEAD
`0e0dd66`. **No functional tests were run in Phase A.** Existing evidence is
retained to avoid repeated campaigns; it does not establish today's runtime health.

## Interpretation and invalidation rules

- `CONFIRMED_EXISTING`: an existing record was located and its stated result is
  preserved, not rerun. Documentary evidence is identified as such below.
- `PASS_CURRENT_CHANGE`: a check actually passed against this session's change.
- `STALE_AFTER_CHANGE`: relevant code/config/dependency changes invalidate coverage;
  record the change and run the smallest needed replacement check.
- `NOT_RUN`: no execution evidence for the named scope.
- `MANUAL_REQUIRED`: verification or reconciliation still requires a later step;
  this label does not itself authorize execution.

The October report was written against `2ab1e04` plus then-uncommitted changes.
Those implementation/report files now appear in `0e0dd66`. There is no preserved
per-test source hash proving exact equivalence to every tested byte. Do not label
all evidence stale just because a session ended or the work was committed; equally,
do not treat the report as a test of later modified code. Phase A changes only
documentation, so it invalidates no functional coverage by itself.

For H-* entries below, date is **2026-10-16**, environment is the **local Windows /
Docker Desktop selected deterministic default deployment**, unless stated otherwise.
Commands are the reproducible commands recorded in the cited documents, not a
recovered terminal transcript. Where no exact historical command was retained,
that is stated explicitly rather than invented.

`$py` in documented commands is
`C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`.
Commands run from `F:\b\Capstone-main` unless a module cwd is specified. These
paths describe the original environment, not a new portability requirement.

## Historical unit/regression evidence

Source for every row: [VERIFICATION_RESULTS.md](VERIFICATION_RESULTS.md), Results
and Reproduce sections; interpreter/environment details in [RUN_LOCAL.md](RUN_LOCAL.md).
Raw individual test logs are not retained in those documents.

| Test ID / area | Command | Result | Code areas covered | Conditions/environment | Invalidated by | Current validity |
| --- | --- | --- | --- | --- | --- | --- |
| H-PY-CONFIG / configuration | `& $py -m unittest discover -s scripts -p test_configuration.py` | 12 PASS | Canonical config validation/rendering, mount/output regressions | Host Python with YAML dependency; offline fixtures | Loader, canonical config semantics, Compose rendering, fixture/dependency changes | CONFIRMED_EXISTING |
| H-PY-BRIDGE / metrics bridge | `& $py -m unittest discover -s observability/metrics_bridge -p test_metrics_bridge.py` | 5 PASS | Bridge aggregate metric/label formatting | Host unit fixtures | Bridge producers, names/labels or fixture assumptions | CONFIRMED_EXISTING |
| H-PY-DECEPTION / engine | `docker exec -e LOG_LEVEL=ERROR capstone-main-deception-engine-1 python -m unittest discover -p 'test_*.py'` | 95 PASS | Engine helper, schema/realism, CRUD, registry/policy/principal tests included by discovery | Existing image dependencies; unit mocks are not outage/live-path coverage | Engine modules, schemas, registry, principal/state semantics or dependency versions | CONFIRMED_EXISTING |
| H-PY-EVIDENCE / evidence | `docker exec capstone-evidence-store python -m unittest discover -p 'test_*.py'` | 18 PASS | Evidence repository/ingest unit cases | Existing container dependencies; not proof of durable delivery under failure | Evidence ingest, dedup, sanitization, retention, storage or consumer changes | CONFIRMED_EXISTING |
| H-PY-STATE / state projection | `docker exec capstone-main-session-module-1 python -m unittest test_authoritative_state test_behavior_state` | 21 PASS | Authoritative/behavior projection and rollback snapshots | Unit event fixtures | Outcome schema, state/behavior projection or transaction interpretation changes | CONFIRMED_EXISTING |
| H-PY-SESSION / session regression | `docker exec -e LOG_LEVEL=ERROR capstone-main-session-module-1 python -m pytest test_session_module.py -q --tb=short` | 188 PASS | Session processing cases in the named suite | Existing container dependencies | Session processing/config/storage/consumer semantics or dependencies | CONFIRMED_EXISTING |
| H-GO-PG / PostgreSQL | `go test ./...` (cwd `pgproxy`) | All packages PASS; no invented case count | PostgreSQL module suite | Host Go; module dependencies | PG proxy/session/auth/protocol/interceptor/publisher code or Go dependency changes | CONFIRMED_EXISTING |
| H-GO-MY / MySQL | `go test ./...` (cwd `mysqlproxy`) | All packages PASS; no invented case count | MySQL module suite | Host Go; module dependencies | MySQL proxy/session/auth/protocol/interceptor/publisher code or dependencies | CONFIRMED_EXISTING |
| H-GO-SCALE / scaling | `go test ./...` (cwd `scaling_agent`) | All packages PASS; no invented case count | Existing scaling module suite | Host Go; does not verify physical KEDA replicas | Scaling code/config/dependencies | CONFIRMED_EXISTING |

H-PY-CONFIG + H-PY-BRIDGE + H-PY-DECEPTION + H-PY-EVIDENCE + H-PY-STATE +
H-PY-SESSION = **339 Python tests reported passing**. This is an aggregate of
those six rows, not a seventh execution. Historical adaptive test source is not
authorization to enable adaptive runtime.

## Historical configuration and live-flow evidence

| Test ID / area | Command | Result | Evidence/source | Code areas covered | Conditions/environment | Invalidated by | Current validity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H-CONFIG / preflight | `& $py scripts/honeypot.py config-check` | PASS | VERIFICATION_RESULTS.md Results | Enabled configuration/secrets constraints | Private local environment at test time; secret values not retained here | Canonical config, env validity, loader/required files | CONFIRMED_EXISTING |
| H-COMPOSE / render validation | `& $py scripts/honeypot.py compose config --quiet` | PASS | VERIFICATION_RESULTS.md Results; RUN_LOCAL.md step 3 | Generated deployment structure | Docker Compose; validated private environment | Compose/renderer/dependency/tool-version changes | CONFIRMED_EXISTING |
| H-START / build/start | `& $py scripts/honeypot.py compose up -d --build` | Eight app images built; 21 long-running containers Up after mount fix | VERIFICATION_RESULTS.md Results and resolved failures | Default deployment startup | Existing volumes/accounts; password alignment and mount correction already completed | Images, dependencies, mounts, config, volumes or target host | CONFIRMED_EXISTING |
| H-NATIVE / PG and MySQL principal lifecycle | `& $py tests/principals/run_native_smoke.py create --name fake_check_20261016`; then same command with `return`, `reconnect`, `disable` in place of `create` | Reported PASS: wrong-password rejection, rollback, committed reconnect, disconnect rollback, traps and disable; zero physical synthetic users | VERIFICATION_RESULTS.md; RUN_LOCAL.md step 6; existing `tests/principals/` driver | Seeded/virtual auth, registry, permissions, principal-scoped state and cleanup | Native clients in replay image, private credentials aligned; test principal remains disabled with tombstone. Listed stages are documented reproductions, not a complete chronological transcript | Auth/principal/state/engine/protocol changes, HMAC/schema/seed/account/volume changes | CONFIRMED_EXISTING |
| H-RESTART / Deception Engine persistence | Exact historical restart command not retained in report; native stages above document surrounding checks | Reported PASS: committed virtual state survived Deception Engine restart and both protocols reauthenticated | VERIFICATION_RESULTS.md Results | Registry-backed principal continuity | Engine restart only; no evidence here for full-stack or Redis crash recovery | Principal persistence, Redis configuration, HMAC/schema/generator changes | CONFIRMED_EXISTING |
| H-STATE / physical SQL and projection | `& $py scripts/verify_state.py` | Documentation reports PASS: PG 16 and MySQL 13 verified outcomes including expected failures. Retained artifact instead contains SQL syntax failure; unresolved conflict | VERIFICATION_RESULTS.md Results/Failures; `.runtime/state-verification.txt` inspected 2026-10-26 | Physical CRUD/DDL/transactions, projection, intentional physical-account rejection | PowerShell integration wrapper, selected local stack. Existing script can mutate temporary tables; not executed now | Proxy/engine/state/event/schema policy, wrapper or platform changes; evidence reconciliation also required | MANUAL_REQUIRED |

Do not reuse `fake_check_20261016` for a new execution: disabled names have retained
tombstones. Use a fresh name only in an authorized later run. Native tests create
synthetic evidence; state integration creates temporary physical objects. They are
not read-only health checks.

H-STATE preserves the historical PASS claim without endorsing the conflicting
artifact as PASS. The retained text contains `ERROR: syntax error at end of input`
at `tests/state/validate_authoritative_state.ps1:77`. Its location/mtime does not
prove whether it predates or supersedes the reported corrected pass. No new
functional failure was produced in Phase A. A later relevant session should locate
the matching pass evidence or run the smallest needed state check with authorization.

## Historical observability and readiness evidence

All H-OBS rows below use the documented command
`& $py scripts/verify_runtime.py`, dated **2026-10-16**. Source:
[VERIFICATION_RESULTS.md](VERIFICATION_RESULTS.md) plus retained
`.runtime/runtime-verification.json`, timestamp `2026-10-16T09:46:07.864575+00:00`.
That artifact was read in Phase A, not regenerated. It reports `ok: true`.
Environment: default selected local stack, authenticated Grafana where needed.

| Test ID / area | Result | Code areas covered | Conditions / limits | Invalidated by | Current validity |
| --- | --- | --- | --- | --- | --- |
| H-OBS-READY / readiness | Deception, Session, Evidence, Replay ready | Readiness endpoints | Historical endpoint snapshot only | Runtime/config/dependency/endpoint changes or elapsed runtime state | CONFIRMED_EXISTING |
| H-OBS-BACKEND / connectivity | PG and MySQL reachable | Backend TCP health | Explicitly not password verification | Backend/config/network changes | CONFIRMED_EXISTING |
| H-OBS-PROM / scraping | All 9 selected targets UP | Generated Prometheus target set | Only enabled default services | Scrape/config/producer/deployment changes | CONFIRMED_EXISTING |
| H-OBS-DASH / dashboard | Primary dashboard provisioned; 53 expressions executed successfully | Dashboard generation and PromQL | Not visual acceptance or proof every series has samples | Dashboard, metrics, Prometheus config/data or feature selection | CONFIRMED_EXISTING |
| H-OBS-GRAF-P / datasource | Authenticated Prometheus health OK | Grafana Prometheus provisioning | Historical credentials/datasource state | Grafana credentials/provisioning/backend changes | CONFIRMED_EXISTING |
| H-OBS-GRAF-L / datasource | Authenticated Loki health OK | Grafana Loki provisioning | Historical credentials/datasource state | Grafana/Loki provisioning/backend changes | CONFIRMED_EXISTING |
| H-OBS-LOKI / logs | Loki ready; project logs present | Loki/Promtail delivery | Artifact sampled `json-exporter` stream; not every application/error class | Log routing, labels, collectors or retention changes | CONFIRMED_EXISTING |

Artifact warnings: no samples for Kafka publish failures and unverified query
evidence. These were not marked failed; absent samples are not complete coverage.

| Test ID / area | Command | Date / result | Evidence/source | Code areas covered | Conditions/environment | Invalidated by | Current validity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H-LABELS / metric and log cardinality | Exact inspection command not retained | 2026-10-16: 209 observed application metric series had no forbidden ID labels; sampled Loki streams likewise | VERIFICATION_RESULTS.md Results | Active metric/Loki label surfaces | Sample of then-active streams, not dormant code or exhaustive secret inspection | Producer label/formatter/Promtail changes | CONFIRMED_EXISTING |
| H-SECRET-SAMPLE / operational logs | Exact inspection command not retained | 2026-10-16: generated test password/HMAC not found in recent Loki inspection | VERIFICATION_RESULTS.md interpretation | Sampled log sanitization | Other credential substring matches were ambiguous; not proof of complete sanitization | Logging/redaction/third-party log changes | CONFIRMED_EXISTING |

## Phase A checks actually performed — 2026-10-26

These are read-only observations and documentation checks, not functional tests.
Source search/read commands are an inspection inventory, not passing test cases.

| Test ID / area | Command | Result | Evidence/source | Code areas covered | Conditions/environment | Invalidated by | Current validity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-GIT / repository identity | `& 'C:\Program Files\Git\cmd\git.exe' status --short`; `& 'C:\Program Files\Git\cmd\git.exe' branch --show-current`; `& 'C:\Program Files\Git\cmd\git.exe' log --oneline -10`; `& 'C:\Program Files\Git\cmd\git.exe' show --stat --oneline HEAD` | PASS: branch `feature/config-observability`, HEAD `0e0dd66`; initial modification only `cmds.txt` | Phase A tool output | Repository provenance only | Local checkout; no Git mutation | Subsequent repository changes | PASS_CURRENT_CHANGE |
| A-COMPOSE-GUARD / status attempt | `docker compose -f docker-compose.yml ps` | Command FAIL (exit 1): required `HONEYPOT_CONFIGURED` unset; expected guard, no service-health result | Phase A tool output; CONFIGURATION.md launcher rules | Root source-template guard only | No bypass, startup or restart attempted | Launcher/template changes | NOT_RUN |
| A-RECORDS / evidence import | `Get-Content .runtime/runtime-verification.json`; `Get-Content .runtime/state-verification.txt` plus documentation reads | Runtime report PASS at historical timestamp; state report conflicts with documented PASS | Existing named files, preserved unchanged | Evidence provenance, not running services | Artifacts exist locally and are ignored by Git | Overwritten/missing artifacts or newer authoritative evidence | PASS_CURRENT_CHANGE |
| A-DOC / requested documents | Exact PowerShell check below | PASS: three nonempty documents, required handoff lines, four audit categories and local Markdown links resolve | Phase A tool output; final document files | Documentation only | Local PowerShell, no runtime imports/service requests | Edits to these documents or linked local paths | PASS_CURRENT_CHANGE |
| A-DIFF / whitespace | `& 'C:\Program Files\Git\cmd\git.exe' diff --no-index --check -- /dev/null STATIC_BASELINE_PROGRESS.md`; same with `VERIFIED_TESTS.md`; same with `BASELINE_CONTRACT.md` | PASS for whitespace: no whitespace diagnostics. Each command exits 1 because no-index compares a new file against an empty file; Git also warns of future LF-to-CRLF conversion | Phase A tool output | New documents, explicitly including untracked files | No staging; `cmds.txt` excluded | Document edits | PASS_CURRENT_CHANGE |

Exact A-DOC command (run from repository root):

```powershell
& {
  $docs = @('STATIC_BASELINE_PROGRESS.md', 'VERIFIED_TESTS.md', 'BASELINE_CONTRACT.md')
  foreach ($doc in $docs) {
    $body = Get-Content -LiteralPath $doc -Raw
    if ([string]::IsNullOrWhiteSpace($body)) { throw "Empty document: $doc" }
    foreach ($match in [regex]::Matches($body, '\]\(([^)]+\.md)\)')) {
      if (-not (Test-Path -LiteralPath $match.Groups[1].Value)) { throw "Broken link in $doc" }
    }
  }
  $progress = Get-Content -LiteralPath $docs[0] -Raw
  foreach ($required in @('READ THIS FILE FIRST ON THE NEXT CODEX SESSION.', 'DO NOT START MORE THAN ONE PHASE PER SESSION.', 'MUST_FIX_BEFORE_CLOUD', 'SHOULD_FIX', 'ALREADY_SUFFICIENT', 'DEFER')) {
    if (-not $progress.Contains($required)) { throw "Missing handoff item: $required" }
  }
  'PASS: three documents, handoff requirements, audit categories and local Markdown links'
}
```

No test scripts were added. No unittest, pytest, Go test/vet, native-client flow,
integration, outage, restart, build, load/soak or browser check ran this session.
Initial file searches included nonexistent guessed module filenames and shell
wildcard arguments rejected by `rg`; subsequent inventory resolved the paths.
Those search misses are not functional failures or verification evidence.

## Explicit coverage still missing

| Test ID / area | Command | Date / result | Evidence/source | Code areas covered | Conditions/environment | Invalidated by | Current validity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| N-MY-TX / ordinary synthetic transactions | No new focused command selected/executed | 2026-10-26: NOT RUN | A-M1 source audit in STATIC_BASELINE_PROGRESS.md | Ordinary MySQL managed-table commit/rollback integration | Separate from virtual-principal lifecycle | Future implementation changes require targeted evidence | NOT_RUN |
| N-PROTOCOL / prepared and grammar consistency | No campaign selected/executed | 2026-10-26: NOT RUN | A-M2/A-M5 source audit; existing suite scope | Managed prepared paths, filtered COUNT, wider unsupported SQL | Existing Go suite is not comprehensive native coverage | Protocol/grammar changes | NOT_RUN |
| N-FAILURE / outage and delivery safety | No outage commands executed | 2026-10-26: NOT RUN | A-M3/A-M6 source audit | Engine/Redis/broker/evidence failure behavior | No chaos or data-destructive checks authorized here | Failure-policy/consumer changes | NOT_RUN |
| N-FULL-RESTART / durable recovery | No full-stack/crash test executed | 2026-10-26: NOT RUN | Only engine restart is documented in H-RESTART | DB/registry/evidence/projection recovery | Stable HMAC/volumes and storage policy required | Persistence/config changes | NOT_RUN |
| N-LINUX / portability | No Linux rehearsal command executed | 2026-10-26: NOT RUN | A-S4 source audit | Linux tooling and deployment prerequisites | Phase F; no Azure/public deployment | Deployment/tooling changes | MANUAL_REQUIRED |
| N-RC / final release candidate | Commands to be selected from evidence ledger after explicit approval | 2026-10-26: NOT RUN | User's Phase G gate | Final cross-component regression | Broad tests reserved for explicit release-candidate authorization | Any subsequently modified covered area | NOT_RUN |
| N-OTHER / optional matrices, replay, load/soak and visual UI | Not selected/executed | 2026-10-26: NOT RUN | VERIFICATION_RESULTS.md Limits | Full optional-feature matrix, replay job, physical KEDA, performance, browser layout | Out of Phase A scope; adaptive/KEDA work deferred | Later changes/explicit scope | NOT_RUN |

Next session: **Phase B only**, if requested. Consult the progress audit and
invalidation columns before selecting any test. Do not run the commands above
merely to refresh their dates.

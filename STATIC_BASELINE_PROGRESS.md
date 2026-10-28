# Static baseline progress

READ THIS FILE FIRST ON THE NEXT CODEX SESSION.
DO NOT START MORE THAN ONE PHASE PER SESSION.

## Current objective and phase

Finish a stable deterministic, stateful PostgreSQL/MySQL local honeypot baseline
before later Linux/cloud preparation. No public deployment or final dataset work.

2026-10-26: **Phase B is IN_PROGRESS.** The ordinary MySQL transaction gap and a
confirmed principal overlay-expiry defect were corrected with focused failing-
then-passing tests. The remaining state areas were audited and tested selectively;
the unresolved Phase B items below prevent marking B complete. **Do not start
Phase C.** No project service was started/rebuilt, no network exposure changed,
and no Git mutation was performed. Isolated test containers used cached images,
read-only source mounts and no network. The project stack was stopped at inspection.

Phase A remains VERIFIED for its documentation/static checks only. Historical
Phase A inspection/change details below are preserved; the active Phase B record
is the section headed "Phase B implementation and remaining work".

Inspected repository: `F:\b\Capstone-main`, branch `feature/config-observability`,
HEAD `0e0dd66` (`feat(config): add deterministic config gating and observability`).
Initial working tree: only user-owned `cmds.txt` modified; preserved. The older
October handoff's `2ab1e04`/uncommitted description is historical. The current HEAD
contains the configuration/observability implementation and verification docs.

| Phase | Status | Boundary |
| --- | --- | --- |
| A — contract and gap audit | VERIFIED | Documentation/static review only; see evidence limits below. |
| B — state machines and invariants | IN_PROGRESS | Two focused corrections pass; ordinary expiry and connection-reset invariants remain open. |
| C — world/data abstraction and validator | NOT_STARTED | No final dataset generation. |
| D — protocol and unsupported SQL | NOT_STARTED | No comprehensive SUPPORTED_SQL.md authored yet. |
| E — failure safety | NOT_STARTED | No outage campaign or fallback policy changes. |
| F — local release / Linux portability | NOT_STARTED | No deployment or public bindings. |
| G — release-candidate validation | NOT_STARTED | Explicit user approval required before broad validation. |
| Dynamic/adaptive/AI/Kubernetes/cloud work | DEFERRED | Outside the static baseline phases. |

## What was inspected

- Current AGENTS.md checkpoint, attached Phase A–G brief, CONFIGURATION.md,
  RUN_LOCAL.md, VERIFICATION_RESULTS.md, current branch/status/log and HEAD summary.
- `config/{features,deception}.yaml`, relevant `scripts/configuration.py` gating,
  Compose loopback bindings, database/Redis named volumes and durability settings.
- Both proxies' `internal/protocol/{handler,principal,principal_auth}.go` paths:
  simple/prepared routing, virtual auth/query dispatch, failures and transaction
  finalization; publisher buffer/drop/retry paths.
- Deception Engine `api.py`, `mutation_store.py`, `exposure.py`,
  `principal_registry.py`, `principal_runtime.py`, `schema_loader.py`, relevant
  `generator.py` and strategy registry validation code.
- Session Module authoritative outcome projection and consumer wiring; Evidence
  Store ingest/retention/consumer behavior; existing state/principal test sources
  and `scripts/verify_state.py` as needed to establish coverage limits.
- Retained `.runtime/runtime-verification.json` and `.runtime/state-verification.txt`.

The three requested progress/contract files did not previously exist. No `.env`
values were printed or changed. This was a targeted source audit, not an exhaustive
protocol/security review or a recreation of the historical adaptive roadmap.

## Concise gap audit

Only the five requested audit areas are used below. Findings are source-backed;
they were not reproduced with new functional tests. Priorities describe work
needed before eventual cloud research, not permission to execute it now.

### MUST_FIX_BEFORE_CLOUD

| ID / area | Finding and evidence | Minimal acceptance / later phase |
| --- | --- | --- |
| A-M1 — state correctness | RESOLVED for bounded text transactions by Phase B focused checks. The original audit was incomplete: MySQL omitted `transaction_state` as well as finalization. The initial test confirmed both failures. | `transaction.go` now coordinates session overlays with successful native boundaries; see B-MY-RED/B-MY-FOCUSED and the contract for exact limits. No live DB/release-candidate claim. |
| A-M2 — protocol correctness | Ordinary PostgreSQL extended queries and MySQL prepared queries bypass `/decide`; simple/text queries can expose synthetic objects that the backend cannot see. Virtual prepared commands are deliberately rejected. `pgproxy/internal/protocol/handler.go` and `mysqlproxy/internal/protocol/handler.go`. | Phase D: explicitly support or natively reject managed prepared access before backend forwarding; bounded client checks, including PostgreSQL Sync recovery. No mandate to build full prepared synthesis. |
| A-M3 — failure handling | Ordinary decision failure falls through to backend or returns missing-table errors for recognized traps. `MutationStore` suppresses ordinary Redis write failures and returns default reads; `ExposureTracker` resets to depth 1 on failures. Already observed data can disappear or acknowledged mutations can be lost. | Phase E: distinguish unmanaged backend queries from established synthetic state; temporary/native failure without false success or authority changes. Do not blindly change global fail-open policy. |
| A-M4 — world/data abstraction | `SchemaLoader._load_all` uses permissive safe_load, overwrites duplicate schema identities and logs/continues on load errors. It lacks cross-world validation of columns, types, rows, FK targets, depths, traps and strategy asset references; unknown generator types fall back to a word. Registry metadata validation already exists but is not a strict world validator. | Phase C: reuse existing files, add strict validation before accepting a replacement world, with focused invalid-fixture tests. No dataset creation. |
| A-M5 — protocol correctness | `_validate_managed_sql` accepts `COUNT(*)` with a supported ID predicate, but `_handle_count` returns whole-table base count plus delta without evaluating that predicate. | Phase D: correctly compute this bounded case or return a native unsupported error. Do not describe filtered COUNT as working. |
| A-M6 — failure handling | Evidence consumer enables Kafka auto-commit and catches per-record ingest errors without retrying that record. Proxy publishers explicitly drop after retry/buffer exhaustion. The documented pipeline cannot promise complete research evidence; evidence Redis has no explicit AOF policy. `evidence_store/main.py::EvidenceConsumer`, both `publisher.go` files, Compose. | Phase E: prevent silent acknowledgment of failed ingestion and define/observe bounded loss, retention and recovery. Phase F: document persistence/export policy. This does not require exactly-once architecture or a new service. |

### SHOULD_FIX

| ID / area | Finding | Later bounded action |
| --- | --- | --- |
| A-S1 — state correctness | October documentation says physical SQL/state integration passed, but retained `.runtime/state-verification.txt` is a syntax-error failure. No matching retained PASS transcript was found in that named artifact. | Reconcile during the relevant state verification session; preserve both observations. Ledger H-STATE is MANUAL_REQUIRED, not a current pass or proof of a current runtime defect. |
| A-S2 — state correctness | Ordinary overlays/exposure expire after four hours; session projection is bounded/in-memory. Continued sockets may outlive state keys; persistence claims need scope. | Phase B: define expiry/connection lifecycle invariants using existing stores, including exposure continuity and open transaction cleanup. Do not build a new state service. |
| A-S3 — world/data abstraction | Database-to-schema mapping and HR employees/departments coherence contain explicit names. Semantic trap/depth metadata already exists. | Phase C: generalize only assumptions blocking replacement world configuration; retain useful existing generator behavior. |
| A-S4 — portability/deployment readiness | Launcher derives repository root from its own path, but `verify_state.py` still requires PowerShell and the primary runbook contains machine-specific Windows interpreter/root examples. No Linux rehearsal evidence. | Phase F: provide a usable Linux prerequisite/check path and a lightweight predeployment checklist, retaining Windows support. Rehearsal remains unverified until performed. |

### ALREADY_SUFFICIENT

“Sufficient” means retain and reuse for the bounded baseline, not certify every
failure case or declare cloud readiness.

- **State correctness:** physical SQL authority remains in PostgreSQL/MySQL;
  Session Module projects verified outcomes. Persistent reserved principals already
  have native auth, scoped state, disable semantics, revision checks and historical
  native lifecycle evidence. No authentication redesign/new database is needed.
- **World/data abstraction:** existing YAML schemas, trap/depth metadata,
  deterministic seed/time anchor, registry and policy modules are a usable base;
  a replacement architecture is unnecessary.
- **Protocol correctness:** simple/text synthetic result/error encoding and bounded
  managed SQL guards exist. Historical Go/native checks cover specific cases.
- **Portability/deployment readiness:** canonical feature gating, offline config
  validation, generated Compose, private bindings and named volumes already exist.
  Historical nine-target, 53-expression and datasource/log evidence supports
  retaining observability without redesign.

### DEFER

- **State correctness / protocol correctness:** full database emulation, arbitrary
  SQL coverage and a durable adaptive world ledger.
- **World/data abstraction:** final realistic dataset, new strategies for feature
  count, generative assets and fictional-company website.
- **Failure handling:** broad chaos, load/soak and full optional-feature matrices;
  release-candidate regression belongs to explicitly approved Phase G.
- **Portability/deployment readiness:** Azure/public exposure, Terraform,
  Kubernetes/KEDA and all adaptive/MITRE/LLM/learning/steering/intervention work.

## Changes, decisions and evidence

Exactly three files were created in this session:

1. `STATIC_BASELINE_PROGRESS.md` — Phase A handoff, prioritized audit and stop boundary.
2. `VERIFIED_TESTS.md` — imported October records, exact documented commands,
   evidence validity/invalidation rules, discrepancies and Phase A check ledger.
3. `BASELINE_CONTRACT.md` — authority, query categories, persistence, failures and limits.

No source/configuration, runtime, secrets, volumes, AGENTS.md or user `cmds.txt`
changes. No staging/commit/push/branch operations. Historical pass totals are
preserved without claiming that a narrative pass is a fresh execution or that
all original test-time source bytes are identifiable.

The direct root Compose status attempt was rejected by the documented
`HONEYPOT_CONFIGURED` guard before Docker status could be obtained. It is not a
service failure. No runtime health inspection/restart was substituted. A-DOC
records document checks; no pytest, unittest, Go suite, native client, integration,
rebuild, load/soak or UI verification was run in Phase A.

## Phase B implementation and remaining work — 2026-10-26

Direct user authorization to execute B superseded the attached older Grafana-only
planning prompt. No observability plan or implementation was added in this pass.
The initial B working tree contained `cmds.txt` and the three untracked Phase A
documents. They were preserved and the documents updated in place. Branch/HEAD
remain `feature/config-observability` / `0e0dd66`.

### Corrections and focused evidence

1. **Ordinary MySQL synthetic transactions:** the smallest command-loop test failed
   because transaction context was absent and ROLLBACK left a synthetic insert
   visible. Added the request context, per-connection dirty-overlay tracking and a
   bounded call to the existing `/transaction/{commit|rollback}` endpoint before
   acknowledging successful backend boundaries. Native SQL and its OK/status
   packets remain backend-owned. Synthetic OK/EOF flags now reflect transaction
   and autocommit state, including synthetic writes with autocommit disabled.
   Native errors do not finalize overlays; failed engine finalization terminates
   processing without forwarding the backend success. The existing virtual loop
   and PostgreSQL proxy code remain unchanged.
2. **Principal transaction expiry:** an isolated memory-store probe and a failing
   regression proved that a missing working overlay with a live binding could be
   committed as an empty world, erasing prior committed state. The existing binding
   now records expected working keys, refreshes their TTLs with the binding and
   rejects/invalidate-binds missing state before promotion. Reauthentication
   restores committed state. Both PostgreSQL and MySQL normal transaction/auth
   behavior are covered by focused preservation tests. No verifier/HMAC change.
3. **Remaining invariant coverage:** new tests exercise MySQL Run lifecycle for
   login success, wrong password, unknown user, disconnect during authentication,
   normal quit, abrupt disconnect and command idle timeout; engine CRUD
   commit/rollback/isolation/cleanup for both protocols; exposure after rollback
   and principal return; expired/disabled principal rejection; and PostgreSQL
   virtual aborted-transaction behavior. Existing selected projection and proxy
   tests were reused. Exact commands/results are in VERIFIED_TESTS.md.

### Unresolved Phase B items — do not declare B complete

| ID | Source-backed remaining issue | Required next bounded action |
| --- | --- | --- |
| B-OPEN1 / ordinary expiry and exposure | Ordinary `MutationStore` keys and transaction snapshots expire independently; `_capture_transaction_table` refreshes the snapshot only when first capturing a table. `ExposureTracker.get_depth` defaults to 1 on missing keys. There is no ordinary-session guard preventing a live connection from observing reset/lost state after expiry. The principal fix does not fix this path. | Prove ordinary snapshot/overlay/exposure expiry with a controllable-clock fixture; define and implement coherent lifetime or explicit session-expired failure using existing state handling. Do not silently extend the persistence contract or alter global outage fallback. |
| B-OPEN2 / MySQL reset and identity transitions | `COM_INIT_DB` updates session database even after a backend error. `COM_CHANGE_USER` updates identity without resetting the existing synthetic session; `COM_RESET_CONNECTION` uses generic forwarding without synthetic cleanup. Source audit only; not covered by the passing initial-auth/quit lifecycle test. | Focused failing wire tests for rejected database change and accepted reset/reauthentication, then minimal state/cleanup corrections that retain backend authority. |
| B-OPEN3 / bounded connection lifetime | PostgreSQL's configured `IdleTimeout` is not used by its ordinary blocking receive loop. Its virtual SCRAM exchange has a 15-second deadline, but that is not a command idle timeout. The MySQL idle test does not verify PostgreSQL timeout behavior. | Prove the PostgreSQL idle-close/cleanup behavior with a bounded socket fixture; resolve the unused timeout before claiming all timeout transitions covered. |

H-STATE's historical PASS/artifact conflict remains MANUAL_REQUIRED. This session
used focused socket/memory-store tests instead of rerunning that physical
integration campaign. No current physical database or full-stack restart evidence
was created. Backend implicit commits on errors, savepoints, multi-statement and
prepared transaction semantics remain outside the bounded text-transaction claim;
Phase D must make unsupported behavior explicit.

The new CRUD fixture also demonstrated that `_fake_insert_row` generates values
instead of preserving literal INSERT VALUES. The test was corrected to verify
the actual generated row's transaction lifetime; the SQL semantic gap is retained
for Phase D (alongside A-M5), not hidden as a supported INSERT claim. A separate
initial fixture assertion compared volatile `updated_at` across legitimate
queries; it was corrected to compare the record immediately before failed expiry
commit. Both initial failures are recorded in the ledger.

### Files changed in Phase B

- `mysqlproxy/internal/protocol/handler.go`
- `mysqlproxy/internal/protocol/transaction.go` (new, helper in existing module)
- `mysqlproxy/internal/protocol/transaction_test.go` (new)
- `mysqlproxy/internal/protocol/lifecycle_test.go` (new)
- `deception_engine/principal_runtime.py`
- `deception_engine/test_phase_b_invariants.py` (new)
- `STATIC_BASELINE_PROGRESS.md`
- `VERIFIED_TESTS.md`
- `BASELINE_CONTRACT.md`

No new service, physical database changes, source deployment, credential changes,
volume changes, Grafana changes, Phase C work or broad historical test rerun.

## Exact next task — ONE phase only

Continue **Phase B**, starting with B-OPEN1 ordinary state/exposure expiry and
then B-OPEN2/B-OPEN3 lifecycle gaps. Read the three handoff files, prove the next
gap with the smallest focused test and retain native/virtual authority boundaries.
Phase C is **not yet the next executable phase** because B remains incomplete.
Do not start C or any later phase automatically.

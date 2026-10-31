# Evidence durability and export — Hardening Pass 2, 2026-10-31

Implemented and locally validated for the bounded contract in
[RESEARCH_DATASET_CONTRACT.md](RESEARCH_DATASET_CONTRACT.md). This is not Azure
deployment approval, a disk-loss/failover test, a seven-day soak, or an attacker
effectiveness dataset. Existing evidence, volumes, secrets and prior Pass 1 work
were preserved. Branch remains feature/config-observability; starting HEAD was
0fd44e6ca10525b75b5ef5fb4331f2efe6aa4a6d. All work remains unstaged/uncommitted.

## Durability migration and observed impact

Evidence Store uses redis-mitre DB0 on the existing `capstone-main_redismitre`
named volume. It originally had appendonly=no; redis-deception already used AOF.
Before recreating the Evidence Redis container, appendfsync was set to everysec and
appendonly enabled **on the populated running instance** using CONFIG SET. Redis
completed its initial AOF rewrite: aof_enabled=1, rewrite_in_progress=0,
last_bgrewrite_status=ok and last_write_status=ok. The retained dump.rdb and the
appendonlydir base RDB/incremental AOF/manifest were inspected on the existing volume.
Only after that completed did the canonical launcher recreate the container with
the matching persistent command. No volume deletion, flush, credential reset or
data import into the live store was used.

Canonical settings are AOF yes, appendfsync everysec, existing RDB snapshots retained,
maxmemory=2147483648 and maxmemory-policy=noeviction. Everysec trades approximately
one second of acknowledged writes on an OS/power failure for lower write overhead;
it is not a zero-loss guarantee. RDB/AOF on one local disk is not an independent
backup. AOF rewrite/COW/temporary disk space and host resource limits still require
deployment review. There is no claim of disaster recovery or Redis Cluster support.

`scripts/validate_research_durability.py` generated a private prefix, wrote 132
decisions + 132 applications + 1 outcome, plus 132 immutable journal events. Admission
took 0.282362s and Redis used_memory increased 1,187,688 bytes. It then restarted
**only capstone-main-redis-mitre-1**. Restart, readiness and after-check took 2.014923s.
All 265 trace records, journal events and index snapshot/epoch/sequence survived.
Original replay remained unchanged; pagination was 128+4; a new write succeeded
after restart. SHA256 checks of all 328 pre-existing immutable trace strings were
unchanged. The injected journal capacity rejection counter also survived. The harness
removed exactly its 280 private keys, with prefix checks. No principal/world keys
were touched. Its temporary state contains hashes/engineering fixtures, not credentials.

This is real process/container restart validation, not simulated Redis or disk loss.
Current retained session projections and older trace records were also readable in
the full export afterward. A pre-AOF throughput comparison was not performed; the
reported times are small operational measurements with AOF enabled, not benchmarks.

## Export layout and consistency

`scripts/export_research_evidence.py` creates a new directory and refuses to overwrite
an earlier export. Files are UTF-8 JSON/JSONL, with versioned export metadata:

| File | Contents |
|---|---|
| export-manifest.json | Export UUID/time, experiment/deployment/run/Git/config/world/registry/profile identity, filters, boundaries, counts, origin totals, collection diagnostics, file byte counts/SHA256, before/after store health and outbox summary |
| export-manifest.sha256 | SHA256 of the manifest bytes |
| traces.jsonl | Indexed decisions, applications and outcomes, retaining record ID, admission sequence, index context and reference status |
| events.jsonl | Immutable sanitized query/session/profile/principal/linkage journal envelopes |
| sessions.jsonl | Full retained sanitized session projections, including bounded legacy lists and available metadata |
| journal-session-summaries.jsonl | Session counts reconstructed from the selected journal boundary, explicitly NOT_VERIFIED |
| deployments.json | Referenced nonsecret launch manifests, including image inventory supplement |

Record IDs, independent decision/application IDs and optional/null fields are retained
verbatim. No outcome is synthesized; missing != zero. No raw Kafka topic dump or raw
Redis credential/world/principal state is exported. Events are already sanitized by
Evidence Store; redaction does not remove all research sensitivity.

Trace export captures one epoch/global maximum admission sequence and pages each
kind at 128 entries, excluding later admissions. Journal export independently captures
its epoch/maximum and pages at 128. This is **not an atomic cut across producers,
broker, receiver, outcome evaluator and outbox**. Records can expire or disappear
between pages; stale/missing counts and before/after status remain visible. New
outcomes after the trace boundary are excluded. Repeating the same boundary does
not reconstruct expired content. No TTL is refreshed by export.

Legacy projections have no immutable historical snapshot index. Their separate API
reads at most eight session projections/page and 131072 index positions/export, with
the original maximum position count. Rank pages read mutable projection state;
concurrent updates can duplicate/omit/reorder entries. Export deduplicates session IDs,
reports duplicates, expiry/missing entries and truncation, and retains the exact
MUTABLE_RANK_PAGES consistency label. This advisory legacy path does not replace or
weaken the immutable journal boundary. Old capped lists cannot reconstruct discarded
history and are never advertised as complete. Pre-journal events are not backfilled.

The exporter uses a temporary SQLite identity/session catalog for streaming joins;
it removes that one temporary file on successful completion. A failed/incomplete
directory is not overwritten and is not acknowledged. File checksums are streamed.
Re-read validation checks manifest/file hashes, byte counts, record counts, duplicate
trace identities, manifest identity and relationship diagnostics. Missing relationships
are reported rather than invented. The validator does not replace the live Redis
store; re-read validation fulfills the non-destructive restore/export check. Full
disaster restore and automated live replay/import remain outside this pass.

## Daily operator workflow

Run from the repository using the canonical configured environment, keeping outputs
in ignored/private storage. Example PowerShell (use the local Python executable):

```powershell
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
python -B scripts/export_research_evidence.py --output ".runtime/exports/$stamp-research"
python -B scripts/export_research_evidence.py --validate ".runtime/exports/$stamp-research"
```

The default is research_external only. Use `--traffic-origin operator_validation`
for engineering checks, `unknown` for historical review, or `all` for a clearly
classified complete retained-source export. `--manifest-id` selects an exact launch.
Do not accidentally pool the latter three modes into external research analysis.

After successful export/re-read validation, the CLI acknowledges the export to the
local Evidence service using a derived operator key in an HTTP header. The key is
derived privately by canonical configuration, never written to the manifest, argv or
export. Wrong/missing authorization is rejected. The receipt tracks a validated
export operation; it does not certify collection completeness or independent backup.

Run daily, then copy the entire immutable directory to restricted independent
storage using the deployment's approved backup process. Verify checksums at the
destination. Review source lag, index/journal remaining capacity, terminal/expired
outbox entries and Redis persistence before and after collection. Daily export does
not free live capacity or change retention. Existing exports are not automatically
deleted. No scheduled automation, cloud storage account or outbound upload was
created in this pass. Backup access controls/encryption and retained archive deletion
remain operator/deployment responsibilities.

For an incident, preserve relevant operational logs before Loki's 72h expiry into
a separate restricted incident directory. For example, create a new timestamped
directory and capture a bounded service log window (never print environment values):

```powershell
New-Item -ItemType Directory -Path ".runtime/incidents/$stamp"
docker logs --since 24h --timestamps capstone-evidence-store 2>&1 |
  Out-File -Encoding utf8 -NoClobber ".runtime/incidents/$stamp/evidence.log"
```

Review/redact incident material before sharing; it is not covered by the research
export sanitizer or research file manifest. Copy it to restricted independent
storage under the incident process. No automatic incident uploader was added.

Azure deployment must monitor disk free, inode free, Redis persistence health,
Redpanda disk use, Loki disk use and Prometheus disk use. Host/node collectors are
not installed in this pass; implementing their resource/alert controls is deferred.

## Provenance and traffic validation

Canonical up generates `.runtime/deployment-manifest.json` and an archived manifest
under `.runtime/manifests/`. The archive is registered by Evidence Store from a read-
only bind. Stable deployment/run IDs and unique launch IDs make restarts explicit.
Secret fields are constant placeholders; numeric settings such as output-token
limits remain nonsecret digest inputs. Tests verify secret rotation does not change
the configuration digest, while a nonsecret port change does.

Both proxies assign origin at their listener boundary: ordinary connection ->
research_external; private 15432/13306 connection -> operator_validation; old/unmarked
-> unknown. Listener context overwrites inherited origin/manifest fields. SQL,
application_name and login names cannot override it. Internal HTTP/Kafka callers
are trusted producers; isolating these administrative paths remains deployment work.

Controlled PostgreSQL and MySQL queries on private listeners passed live checks for
query-event/decision/application execution/start/IDs, equal operator origin and
manifest reference, daemon outbox acknowledgement, and absence of private metadata
in SQL output. Two real closed fixture sessions produced persisted outcomes with
the same origin/manifest and preserved null features:

| Protocol | Session | Application | Outcome |
|---|---|---|---|
| PostgreSQL | d92a23ff-caad-4de6-a561-932d8b86d2bb | d5bee8b7-eed2-4133-86be-f503a65ea86b | 62f855df-c742-5289-b100-713132363dba |
| MySQL | 34e6448e-5c14-4948-b45f-2b38302f8810 | 65fcead4-7961-4a66-84b2-faf6bb91a9dc | 4904d458-823b-5aa0-9f19-c6a6f074cdb9 |

All are engineering fixtures, not attacker observations. Earlier fixture origins
remain unknown. The isolated measurement/restart namespaces were removed.

Final all-origin export `00679f72-e211-4c5a-b825-2f859cd0dd21`, under ignored
`.runtime/exports/hardening2-final-all`, re-read successfully: 163 decisions, 163
applications, 4 outcomes, 45 journal events, 7 journal session summaries and 129
session projections. Zero unresolved trace/deployment references, stale trace members,
missing journal records or missing projections were diagnosed at that bounded read.
437 exported rows retained legacy unknown-manifest classification; counts include
different record types and are not unique-attacker counts. The separate default
external export was empty, correctly excluding operator/unknown fixtures. These
results do not close the historical coverage gap. Repeated export reads did not
change source traces or TTLs.

Export review found 52 credential-bearing configuration fields replaced by constant
placeholders and no occurrence of the four long derived operational secrets. A naive
substring scan initially matched short local placeholder passwords against the public
`mysql_native_password` command flag; contextual inspection confirmed no credential
value in that flag. No operational secrets were printed during this review.

## Runtime metrics and retention verification

Evidence and engine `/metrics` expose the research gauges listed in the dataset
contract with fixed labels. `/evidence/research/status` and `/research/delivery-status`
expose bounded counts/diagnostics without payloads. Observed final outbox: 0 entries,
0 pending, 0 terminal, oldest age 0, capacity 32768, full/terminal/expiry totals 0.
The API route is registered before the script's blocking uvicorn entry point.

Effective retention.ms was 1209600000 on all five Evidence source topics:
pg-query-events, mysql-query-events, pg-session-events, mysql-session-events and
session-profiles. Evidence consumer group was Stable, one member, total lag 0.
Existing topic partitions and records were preserved. There is no byte-level broker
capacity guarantee: retention.bytes remains -1; disk exhaustion, sustained consumer
failure beyond retention and unusually large traffic still threaten collection.
Export/journal are required rather than treating broker retention as independent
backup. Loki remains retention_enabled=true/72h; Prometheus remains operational7d.

The initializer had previously supplied a shell script as a Compose string, which
split it into arguments and executed only `echo`. It now passes exactly one script
argument to `/bin/sh -c`, allowing the existing idempotent topic setup and new
retention command to execute. The installed rpk uses `-X admin.hosts=...`, not the
older `--api-urls` flag. No broker data volume was recreated.

The installed Evidence kafka-python 2.3.0 requires
OffsetAndMetadata(offset, metadata, leader_epoch); runtime validation reproduced the
two-argument failure and it was repaired with leader_epoch=-1. Consumer admission/
failure commit ordering now has focused tests and the live group caught up. The
trace harness was also corrected to paginate beyond the first 128 retained entries
and tolerate normal event-after-trace arrival before declaring failure.

## Exact focused validation commands

Host Python below is
`C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`.
No dependencies were installed or upgraded. PYTHONPATH includes ignored existing
`.runtime/pass2-tooling`, `.runtime/tooling`, `shared`, and the module under test.

```text
python -B -m pytest -q --tb=short -p no:cacheprovider --basetemp .runtime/pytest-hardening2-final-contract evidence_store scripts/test_configuration.py scripts/test_research_export.py
  96 passed, 4.24s

python -B -m pytest -q --tb=short -p no:cacheprovider deception_engine/test_trace_outbox.py deception_engine/test_live_trace.py deception_engine/test_query_correlation.py deception_engine/test_decision_trace.py deception_engine/test_action_provenance.py deception_engine/test_strategy_registry.py deception_engine/test_strategy_version_integrity.py deception_engine/test_strategy_commitment_preconditions.py deception_engine/test_world_commitments.py deception_engine/test_principal_registry.py deception_engine/test_world_commitment_lifecycle.py deception_engine/test_hr_world_freeze.py deception_engine/test_query_idempotency.py
  145 passed, 31.90s

docker exec capstone-main-session-module-1 python -B -m pytest -q --tb=short -p no:cacheprovider test_session_module.py test_authoritative_state.py test_behavior_state.py
  210 passed, 7.79s

go test ./internal/protocol ./internal/connection ./internal/interceptor ./internal/publisher -count=1 -timeout 90s
  pgproxy: 4 packages PASS (2.746s, 1.474s, 1.496s, 1.529s)
  mysqlproxy: 3 packages PASS (2.633s, 1.546s, 1.522s); connection has no test files

python -B scripts/honeypot.py config-check
python -B scripts/honeypot.py compose config --quiet
python -B scripts/validate_query_trace_runtime.py --protocol postgres
python -B scripts/validate_query_trace_runtime.py --protocol mysql
python -B scripts/validate_research_durability.py
Get-Content -Raw scripts/measure_research_evidence.py | docker exec -i capstone-evidence-store python -B -
python -B scripts/export_research_evidence.py --output .runtime/exports/hardening2-final-all --traffic-origin all
python -B scripts/export_research_evidence.py --output .runtime/exports/hardening2-final-external
python -B scripts/export_research_evidence.py --validate .runtime/exports/hardening2-final-all
python -B scripts/verify_runtime.py
```

The final verifier returned exit0, all13 checks PASS, nine Prometheus targets and53
dashboard expressions. Missing-traffic notes are not failures. Report is
`.runtime/runtime-verification.json`. Initial missing local sklearn prevented the
larger host session-suite collection; the existing session container supplied those
already-installed dependencies and the complete focused session selection passed.
An initial mistyped test filename and unsupported diagnostic rpk flag ran no relevant
tests/check and were corrected; none of these were treated as success. Initial unit
failures drove journal-double support, stable missing artifact-source timestamps and
a retry limit that actually fits retention; assertions were not weakened.

## Remaining deployment work

Production egress/resource/restart/logging/secret/release reproducibility and backup
access/destination review remain. This pass does not certify seven-day worst-case
memory, disk, packet loss, failover or public-network isolation. Existing unsupported
trace protocols and historical gaps remain explicit. AOF, finite capacities, daily
validated export and trusted producer metadata now provide the bounded local
prerequisites; they do not replace those deployment controls.

Exactly one next recommendation: **Deployment Runtime Hardening: egress isolation,
resource limits, restart/recovery, logging, secrets and release reproducibility**.
That next pass was not started.

## Final checks and change inventory

Final generated manifest ID:
`60e8732a6d8c9dc825019d7f5923e4c51e6fccd29a0c6ec7a9e27560d4754886`.
Configuration digest:
`f197a6c8531b62549bb3e8275e461d6ecbb76fe9d686808b0d190fd1b0fa5378`.
Sixteen running engine/Evidence/session Python source hashes matched the workspace
and manifest; image inventory contains 23 services/one-shot entries. A final repeat
of live PG/MySQL origin/correlation checks passed and was recorded in ignored
`.runtime/research-final-pg.json` and `.runtime/research-final-mysql.json`.
Final operator export `3afd5a61-b605-4a2f-8ed0-8d6dec1675f3` re-read valid with
13 decisions, 13 applications, 2 outcomes, 49 journal events, 9 journal session
summaries and 9 session projections, with zero unresolved trace relationships.
A deliberately modified COPY of the real all-origin export failed checksum
validation; original export and live store were unchanged. The marked
`.runtime/exports/hardening2-tampered` directory is an invalid test artifact, not a
backup. A repeat private sizing check admitted 1001 records of each trace kind,
then removed its 3418 exact keys; the repeated measured memory delta was
10,035,576 bytes/1000 queries, elapsed 8.510572s. The conservative first measurement
remains the documented workload model. Final verifier remains all13 PASS/exit0.

A final elevated test attempt encountered the existing Windows pytest Temp-root
permission error (95 passed, one setup error). The final command above used a new,
explicit workspace basetemp and passed all96; no product behavior or assertion
changed. Prometheus runtime retention flag was `1w` (seven days). The initial flag
lookup used the proxy health port and got404; corrected lookup used9096.

Production changes this pass: config/deception.yaml; scripts/configuration.py,
honeypot.py, new deployment_manifest.py and export_research_evidence.py;
shared/research_metadata.py; engine models/live_trace/decision_trace/principal_runtime/
trace_outbox/api and new research_metrics; both proxies' main/manager/principal
context/handler/principal-query publication paths plus research_context.go; session
models/engine/consumer/authoritative_state; Evidence main/strategy_traces/trace_index/
strategy_outcomes/outcome_aggregation/indexed_aggregation and new research_journal,
deployment_registry/research_metrics; observability/capstone_alert_rules.yml.
Prior Pass1 source edits remain in the same working tree and are not new Pass2 work.

Tests: new evidence_store/test_research_evidence.py and test-only journal_model.py;
extended existing Evidence Redis doubles; scripts/test_research_export.py and
configuration tests; both proxies' research_context_test.go; session mapping test;
updated outbox contract double key-count handling. Manual bounded tools: new
scripts/validate_research_durability.py and measure_research_evidence.py; corrected
validate_query_trace_runtime.py pagination/arrival handling and moved both controlled
query/containment harnesses to private validation listeners. Documentation: this
file, RESEARCH_DATASET_CONTRACT.md and additive AGENTS.md handoff. Final diff check
passes. Existing .env and feature defaults remain unchanged; no Git mutation.


## Broker storage assumptions and empty exports

A read-only Kafka consumer (group_id=None, no commits, at most64 retained values/
topic) measured actual stored value sizes without printing payloads:

| Source | n | Median bytes | Largest measured bytes |
|---|---:|---:|---:|
| PG query | 64 | 861.5 | 1218 |
| MySQL query | 64 | 814.5 | 883 |
| PG session | 64 | 298 | 569 |
| MySQL session | 64 | 296 | 566 |
| Session profile | 51 | 803 | 1731 |

For14days at10queries/minute, a deliberately conservative observed-size scenario
with one raw and one dedup query value/query, three session/principal events per ten
queries and one profile per ten queries gives approximately
201600*(2*1218 + 0.3*569 + 0.1*1731), about0.56GB of value payload. This is a planning
scenario, not a maximum-message bound or a validated broker throughput rate. Kafka
headers, indexes, metadata, active segments, other topics, filesystem allocation,
replication and rewrite/recovery space are additional. Current local broker data
occupied754360KiB with18 retained topic partitions/replication1. Configured segment
size is128MiB; allowing one working segment/partition adds about2.25GiB for this
local partition inventory. A fresh initializer can create48partitions across12topics,
so that allowance becomes6GiB before recovery reserve. Deployment disk planning
must use the actual partition inventory and reserve headroom; it cannot extrapolate
only from the tiny current fixture payload. Host VHD filesystem free space is not
an Azure disk reservation or proof of physical-host free capacity.

The exporter now includes a generated deployment manifest even when the selected
external population is empty, labeling it export_context_manifest_id. It does not
assign that identity to old records. The exact exporter source SHA256 is also in
export-manifest.json, independently of the runtime launch source map. A real empty
external export0ded3a58-7410-443d-a53e-a5c578744017 under ignored
`.runtime/exports/hardening2-external-context` re-read valid, retained one deployment
manifest and the exporter digest, and contained zero selected evidence records.
The final focused selection remained96PASS,4.24s. The export-context-only script
refinement does not change running service source; the16 verified runtime source
hashes and current launch identity remain valid. Configuration status explicitly
shows all six optional_future features disabled.

If an installation has never activated its trace index, the existing409 INDEX_NOT_ACTIVE
contract is preserved: export fails explicitly rather than inventing an empty
historical index. Verify the deployment using the controlled private-listener query
harness before its first daily research export. No Redis CLI or historical relabeling
is needed. Daily exports and incident-log preservation are separate restricted
artifacts; neither frees live retained capacity.

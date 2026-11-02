# Deployment Runtime Hardening — Pass 3

Completed 2026-11-02 for the bounded local contract. Runtime engineering checks were
performed on 2026-10-31 and rechecked on continuation. This is not authorization for
public exposure, an Azure deployment, a seven-day soak or a crash/disk-loss guarantee.
Release mechanics and dependency exceptions are in RELEASE_REPRODUCIBILITY.md.

## Repository and scope

Original start: feature/config-observability, HEAD
0fd44e6ca10525b75b5ef5fb4331f2efe6aa4a6d, with Pass 1/2 changes preserved.
On continuation the user had committed that work and the interrupted implementation
as b0b16baf918298032d742363cd81c4890093e68d (R2); the checkout was clean. No agent
branch, stage, commit, push, reset, actual .env edit, credential reset, volume deletion,
Terraform, Azure or public binding was performed. Documentation completion remains
uncommitted. Deterministic selection, HR v1, strategy approvals and optional-feature
defaults are preserved. Engineering fixtures are not attacker research observations.

## Network and host boundary

The previous single default bridge, individually published management services,
unbounded container resources, collector/socket dependency and mixed log driver
configuration were replaced by canonical policy in config/runtime.yaml and
scripts/runtime_hardening.py. Unknown enabled services fail configuration validation.

| Network | CIDR | Members | Egress |
| --- | --- | --- | --- |
| edge | 172.28.10.0/24 | PG/MySQL proxies, operator gateway | Namespace firewall permits reviewed internal TCP only |
| application | 172.28.20.0/24 | proxies, engine, session, Evidence, scaling, broker/init, bridge, Prometheus, gateway | internal isolated bridge |
| state | 172.28.30.0/24 | proxies, engine, main DBs, deception Redis, containment init | internal isolated bridge |
| control | 172.28.35.0/24 | Evidence, evidence Redis, scaling, replay, JSON exporter, gateway | internal isolated bridge |
| observability | 172.28.40.0/24 | Prometheus, Grafana, Loki, collector, JSON exporter, gateway | internal isolated bridge |
| sandbox | 172.28.50.0/24 | replay and sandbox DBs | internal isolated bridge |

All internal bridges use gateway_mode_ipv4=isolated, which removes the host bridge
address. There is no default network. Docker resolves internal aliases; explicit
127.0.0.1 forwarding DNS prevents external resolution. Build/pull/package resolution
requires operator network access before steady state; application startup requires
no internet API, package registry, external DNS, cloud control plane or IMDS access.
No Docker socket, host networking, privileged service or host PID namespace remains.

Only the two proxies and gateway have an edge attachment. shared/runtime_guard.sh
sets IPv4/IPv6 OUTPUT DROP before workload startup, permits established traffic and
loopback, rejects link-local/IMDS and default gateway, then allows reviewed internal
TCP networks/ports. Proxies permit application/state TCP 5432,3306,8001,8003,9092;
they cannot reach Redis 6379. Gateway permits its fixed HTTP targets only; it is not
an arbitrary forwarding proxy. Its edge CIDR allowance is needed when embedded DNS
selects a proxy's edge address; the explicit host-gateway rejection precedes it.

Firewall initialization alone has NET_ADMIN/SETUID/SETGID/SETPCAP. PID 1 then runs
as UID/GID 65532 with effective/permitted/bounding/ambient capabilities zero and
NoNewPrivs=1. A workload cannot restore NET_ADMIN or change these rules. Application
root filesystems are read-only with bounded 64-MiB noexec/nosuid tmpfs. Official
state images retain entrypoint capabilities they need; no unsupported UID override
was imposed on retained database volumes.

Real checks: reviewed internal dependencies work; public IP, IMDS, host gateway
ports 22/2375 and external DNS fail; firewall alteration fails; replay cannot reach
the main PostgreSQL IP. Full 44-check matrix and actual mounts/caps/networks/limits:
.runtime/pass3-isolation.json. This is container/bridge containment, not a kernel
escape guarantee. Future Linux Engine >=28, host firewall/NSG, actual management
addresses and cloud metadata boundary require private-host validation. Docker's
[port publication documentation](https://docs.docker.com/engine/network/port-publishing/)
describes isolated bridges and the pre-28 localhost publication caveat.

## Published ports

All current publications are 127.0.0.1 only. Future public candidates are solely
the ordinary PG5432/MySQL3306 decoy listeners, under separate authorization.
PG15432/MySQL13306 remain private operator-validation listeners.

Gateway preserves local operator workflows: 8000 session control, 8003 session API,
8001 engine, 8011 Evidence, 9090 PG health, 9091 MySQL health, 9095 scaling control,
9100 bridge, 9096 Prometheus, 3000 Grafana, 3100 Loki, 8012 replay. These management
publications are for loopback access/SSH tunneling only. Redis, backend DBs, broker
9092/admin9644, sandbox DBs, collector and JSON exporter have no host publication.

## Resources and admission

Every enabled service has explicit memory, CPU and PID bounds. The measurement
appendix below records point samples, not peaks or calibrated capacity. Init jobs
have bounds but restart=no; all 21 long-running services use unless-stopped.

Redis deception: allocator512MiB, container1536MiB, noeviction, AOF/always.
Evidence Redis: allocator2048MiB, container4608MiB, noeviction, AOF/everysec.
The latter preserves Pass 2 and reserves at least twice allocator plus256MiB for
RSS/COW/rewrite headroom. Full admission fails/backpressures instead of evicting
live evidence; allocator limits are not hard disk quotas. Rewrite pressure at full
capacity remains unverified. The approximately one-second everysec crash window
remains; safe stop/start is not a sudden-power-loss test.

Redpanda retains smp1, memory512M, reserve0 and overprovisioned mode inside1536MiB/
1.5CPU/128PIDs. All five source topics retain14days. retention.bytes=-1 is an
explicit exception: time retention is not an absolute byte ceiling. The Pass 2
10queries/min baseline model is approximately0.56GB payload/14days before overhead;
18 existing partitions add approximately2.25GiB working-segment allowance. Do not
silently shorten evidence retention or impose destructive byte retention to hide
disk pressure. Reserve measured headroom, monitor disk/inodes, stop collection and
export before exhaustion. Higher60/600 rates are overload scenarios, not guarantees.

PG max_connections64, shared_buffers128MB, work_mem2MB, maintenance64MB,
statement5s, lock1s, idle-in-transaction30s. The runtime role's existing2s statement
limit remains stricter. MySQL max_connections48, buffer pool128MiB, tmp/heap8MiB,
packet1MiB, connect5s, network reads/writes10s, idle300s, query2s, thread cache8.
Both proxies share a128-connection bound across ordinary/private listeners,15s
authentication/startup and per-message write deadlines,5min idle deadlines and
bounded input allocations. PG validates frontend message length before pgproto3
allocation; MySQL checks client packet size before allocation. Existing backend
packet handling and HR semantic generation remain unchanged.

Sum of all reviewed memory maxima including init jobs:16128MiB. Deployment preflight
requires that total plus2048MiB host reserve,18176MiB. The local Docker host has
approximately15.56GiB and ran the bounded smoke successfully, but would deliberately
fail strict deployment sizing. Plan at least24GiB actual usable host memory and
validate on the private host; no cloud SKU has been selected or provisioned.

## Disk and logging

All container drivers are explicitly json-file, max-size10m/max-file3 (about30MiB
each plus rotation/metadata overhead). Loki retains72h with16MiB/s ingestion and
32MiB burst controls; it is operational logging, not a seven-day evidence archive.
Prometheus retains7days with a2GB TSDB size bound. Neither time retention nor rate
limits alone constitute a filesystem quota. DB/WAL/binlog, broker segments, Redis
AOF/rewrite, Loki compaction, images/build cache and exports require disk/inode
monitoring and measured headroom. No database data is automatically purged here.

Daily research exports should use a new restricted directory, validate checksums,
copy to an independent destination and retain seven daily exports plus a final one.
No scheduler, upload destination, automatic deletion or backup-restore guarantee was
introduced. Preserve incident logs separately with restricted access before72h
expiry. Metrics bridge now exports filesystem size/free and inode counts from the
container backing filesystem; strict deployment puts Docker's backing root on the
reviewed data disk. This does not inventory arbitrary host mounts.

Promtail3.2.1 is retained as the explicitly permitted smallest collector exception.
It is [EOL since2026-03-02](https://grafana.com/docs/loki/latest/send-data/promtail/).
It tails read-only Docker JSON files, not the Docker API; its positions have a named
volume. HONEYPOT_DOCKER_LOG_ROOT must point at the actual Docker data-root/containers
directory. This read-only directory also exposes Docker metadata/config files:
the collector is a trusted host reader and can potentially read environment secrets.
It has no socket/control API and no external network route. Read-only files do not
make a Docker socket safe. Migration to a supported collector needs separately
validated parsing/position continuity before deployment; no unsupported claim of
equivalence or secret-inaccessible collector is made.

Actual Loki checks found five recent lines each for PG/MySQL proxies, engine,
session, Evidence, both Redis instances, broker and both main DBs, all with bounded
level labels. Application JSON and anchored native formats normalize levels;
unknown remains explicit. Labels are project/service/environment/level/stream,
not SQL, username, source IP, session/principal/QID. Filename label is removed.
Shared Python and Go logging redact operational PASSWORD/SECRET/KEY/SALT values
and SQL payloads. Tests exercise operator, runtime and pseudonym secrets. This is
structured operational logging, not a claim to detect arbitrary secret strings
from every third-party message. Before-migration logs were preserved locally in a
bounded restricted validation folder; none are shipped in the source archive.

## Startup, persistent disk and secrets

Strict deployment uses HONEYPOT_DEPLOYMENT_MODE=true and an explicit
HONEYPOT_SECRET_FILE=/opt/honeypot-data/secrets.env. No fallback to developer .env
is permitted. The secret file must be a regular non-symlink, owner/root-owned0600.
deployment/secrets.env.example contains placeholders only; actual secret files are
Git-excluded and excluded from image contexts and release archives.

Independent strong operator secrets: POSTGRES_PASSWORD, MYSQL_ROOT_PASSWORD,
MYSQL_PASSWORD, GRAFANA_ADMIN_PASSWORD, PG_RUNTIME_PASSWORD, MYSQL_RUNTIME_PASSWORD.
Weak/default/placeholder, short, low-diversity or reused values are rejected in
deployment mode. RESEARCH_OPERATOR_KEY is a domain-separated derived export-ACK
credential from PG_RUNTIME_PASSWORD, not an attacker login or stable research key.
Decoy PG/MySQL visible login values must be explicit and separate; deliberately weak
decoys may be allowed. Stable DECEPTIVE_PRINCIPAL_HMAC_SECRET (base64 >=32 random
bytes) and EVIDENCE_IP_HASH_SALT must be independent and preserved across restarts.
No key is automatically rotated. Fingerprints in the disk marker detect accidental
change; Evidence's persisted pseudonym salt rejects a mismatching configured value.

Future Linux installation contract (templates are preparation, not installed here):

1. Mount the intended persistent disk at /opt/honeypot-data. Do not accept an ordinary
   directory as the disk. Set an explicit HONEYPOT_DATA_VOLUME_ID and private secrets.
2. On a genuinely new mounted disk only, explicitly initialize the marker using
   scripts/deployment_guard.py --initialize-marker. It refuses existing marker or
   Docker data. Existing volumes require a reviewed migration, not reinitialization.
3. Keep source at /opt/honeypot and .runtime on the mounted data disk (an explicit
   reviewed link is acceptable). Preserve research-identity.json and stable keys.
4. Install deployment/docker-data-guard.conf verbatim as
   /etc/systemd/system/docker.service.d/honeypot-data-guard.conf. Configure Docker's
   data-root using deployment/daemon.json.example. The Docker daemon itself must
   refuse absent-disk startup, before any container restart policy runs.
5. Review/install deployment/honeypot.service and its strict environment/log root.
   Build/pull reviewed images before this no-build startup. Use canonical launcher.

Preflight requires Linux, actual mount, correct private project/version/volume marker,
stable-key continuity,20GiB free, .runtime below the mount, correct Docker data-root,
Engine>=28, installed exact daemon drop-in and reviewed memory reserve. It runs
before Compose up/restart. Missing/wrong disk or changed keys fail closed; it never
creates a fresh Docker root or resets credentials to recover. Direct administrator
Docker commands can bypass launcher policy and are outside the supported runbook.

Unit negatives and a real temporary Linux tmpfs check passed for valid mount/marker,
changed keys, low free space,0644 secret and unmounted-directory rejection. This is
not an actual Ubuntu daemon reboot/unmount test; install and test the systemd/daemon
contract on the future private host before public operation. No Azure disk or host
daemon configuration was changed here.

## Recovery and runtime results

Full local Compose stop/start with retained volumes passed. Hashes of14 principals
(12 with retained world state),465 retained evidence strings and256 journal entries
were unchanged. Index epoch survived, sequence was monotonic and both AOF states
were healthy. The same before-state check passed again on2026-11-02 after resumption.
No FLUSH, volume deletion, fresh DB initialization or credential regeneration.

Gateway uses embedded DNS resolver valid=2s and a variable upstream for fixed targets.
Replay backend was moved to unused172.28.35.240, then recreated onto172.28.35.5;
gateway start time stayed unchanged and /readyz returned200. This specifically
exercises an IP change, not just a recreation that reused the old address.

Bounded pressure:4 workers,24 successful private queries,16 managed applications
and8 native constants,0.886178482s. Outbox pending/terminal/full/expiry counters0;
no OOM and health remained stable. No full-capacity or adversarial sustained-load
claim. SELECT1 intentionally has no strategy application; initial test expectation
of24 applications was corrected after inspecting native routing, not production.

Both live PG/MySQL request-start/QID/decision/application/origin/manifest linkage
checks passed, indexed traces and outbox ACKs observed, no private SQL metadata.
Six live containment/HR checks passed, including actual grants and virtual-principal
commit/reconnect. All-origin export validated249 decisions/249 applications/4 outcomes/
315 journal events/31 summaries/153 projections; operator export96/96/2/286/31/31;
external export empty. No unresolved references; collection completeness remains
NOT_VERIFIED. These are engineering fixtures only. Export IDs and source snapshots
are in ignored validation artifacts, not a release or scientific dataset.

Runtime verifier:13/13 PASS,9 targets,53 dashboard expressions before interruption.
Continuation initially caught Loki's startup503 after the host restart; final result
is recorded in the continuation addendum below. Missing-traffic notes are not checks
failing. Dependencies have native health checks; app readiness and proxy/gateway
health are explicit. Grafana/Prometheus/Loki/collector/scaling/JSON exporter are also
covered by endpoint/scrape verification; not all have Docker health commands.

## Tests and commands

Use bundled Python with -B; PYTHONPATH includes .runtime/pass2-tooling,
.runtime/tooling, shared, scripts and the selected module. Tests use fresh workspace
--basetemp and -p no:cacheprovider. No dependencies/test tools were installed in
production containers. Disposable tests use read-only mounts and network=none.

Final focused selections (overlap exists; do not sum as unique tests):

| Selection | Result |
| --- | --- |
| Configuration/runtime/logging/export + Evidence research/world/store |54PASS,4.10s |
| Evidence trace/index/endpoint/outcome/aggregation/correlation + archive/config |64PASS,2.70s |
| Engine HR/live trace/outbox/correlation/world/registry |65PASS,20.67s |
| Session/session-state/behavior/experiment/strategy telemetry |225PASS,8.35s |
| Final archive identity/tamper/runtime policy/export digest |12PASS,1.28s |
| Continuation query-idempotency/principal-registry/decision-trace |44PASS,3.25s |
| Continuation configuration/runtime/logging/export |28PASS,3.68s |
| PG cmd/connection/protocol/interceptor/publisher |5packages PASS |
| MySQL same selection |5packages PASS |
| Scaling cmd/agent |PASS,1.083s |
| go mod verify |all3 modules PASS |

New focused tests cover pre-allocation wire bounds, connection caps/deadlines,
secret logging, deployment permissions/mount/key continuity, reviewed networks/
resource/port/log contracts and archive exclusion/checksum tampering without Git.
Initial Go cache access denial required approved escalation. Initial session helper
omitted py.py/shared mount; fixed the test harness and reran225PASS. No assertion or
production safety deadline was weakened. Initial migration gateway duplicate ports,
nonroot nginx stderr and multi-network DNS selection were reproduced and repaired.
Fresh build of all10 custom images succeeded, then final cached builds/start passed.
All5 runtime Python images passed pip check, had no application tests and no pytest.

Operational commands (canonical; expanded Compose output can contain secrets):

```text
python -B scripts/honeypot.py config-check
python -B scripts/honeypot.py compose config --quiet
python -B scripts/honeypot.py compose up -d --build
python -B scripts/verify_runtime.py
python -B scripts/validate_runtime_isolation.py
python -B scripts/validate_resource_smoke.py
python -B scripts/verify_recovery.py --capture .runtime/before.json
python -B scripts/honeypot.py compose stop
python -B scripts/honeypot.py compose up -d --no-build
python -B scripts/verify_recovery.py --check .runtime/before.json
python -B scripts/validate_release_runtime.py
```

The last script intentionally recreates only the stateless replay backend and moves
its control-network IP after verifying an unused fixture address. Run only during a
bounded maintenance window. No state volumes are removed. Other validators produce
private operator fixtures; keep them excluded from research and release bundles.

Local artifacts: pass3-before.json, pass3-disk-before.txt, pass3-fresh-build.log,
pass3-isolation.json, pass3-pressure.json, pass3-release-runtime.json,
pass3-linux-guard.json, pass3-pre-reboot-state.result.json and final verifier logs
under .runtime. They are local evidence, not permanent repository history.

## Remaining deployment gates

Private Linux host daemon/mount/reboot enforcement and real cloud/host boundary
validation; independent backup destination/restore; current image CVE inventory and
unsupported-component review; full allocator/COW/disk headroom and sustained-rate
validation; clean final source release. EOL collector is an explicit temporary
exception, not a production-security approval. Arbitrary corruption, kernel escape,
disk disaster/failover and unsupported query protocols remain outside this pass.
Do not repeat resolved backend-admin/HR/evidence-contract blockers from Pass1/2.

Exactly one next recommendation: **Azure Terraform + Private Cloud Validation
Preparation**. No next-pass implementation or deployment was started.

## Measured resources and applied limits

Continuation result2026-11-02: all13 runtime checks PASS after Loki's initial
startup503 settled; all44 isolation checks PASS; all10 required log streams had
level labels (proxies3 lines each, others5 in the bounded query). Configuration
validation and28 focused configuration/runtime/logging/export tests PASS3.68s.
No source or runtime behavior changes were required on continuation. Some running
image IDs were not inspectable in the Docker image catalog; sizes are explicitly
unavailable, not inferred. Runtime image IDs and container measurements remain
observable. Safe-recovery hash checks passed again against the original baseline.
All55 production Python source files across engine/session/Evidence/bridge/replay
matched workspace SHA256 on continuation; see pass3-resume-source-hashes.json.

## Implementation and handoff files

Implementation resides in preserved user commit b0b16ba. Main Pass3 groups:
config/runtime.yaml and image-lock.yaml; scripts/runtime_hardening.py,
deployment_guard.py,build_deployment_archive.py,verify_recovery.py and bounded runtime
validators; configuration.py/honeypot.py/deployment_manifest.py; deployment templates;
operator_gateway; shared/runtime_guard.sh/safe_logging.py; proxy connection/protocol
bounds and Go logging; per-context Dockerfiles/.dockerignore/requirements locks;
collector parsing and bridge filesystem gauges; Evidence pseudonym continuity.
Focused test files accompany these contracts. No new principal/world/strategy
algorithm is introduced by Pass3. Earlier Pass1/2 source in the same commit remains
preserved and should not be attributed to new behavior in this continuation.

Continuation changes only these four documentation files: this report,
RELEASE_REPRODUCIBILITY.md, AGENTS.md and the additive evidence-durability note.
Generated measurements/archives are ignored. Final configuration check/status,
Compose config --quiet and git diff --check pass. No stage/commit/push was performed.

Point samples from the original inventory and continuation, not maximum RSS/CPU/PID guarantees. N/A denotes an exited init job or newly introduced gateway. All memory limits below are MiB.

| Service | Before memory | After memory | After CPU / PIDs | Memory limit | CPU limit | PID limit |
| --- | --- | --- | --- | --- | --- | --- |
| pgproxy | 9.156MiB | 14.57MiB | 0.18% / 10 | 256 | 1.0 | 128 |
| mysqlproxy | 8.695MiB | 13.02MiB | 2.07% / 13 | 256 | 1.0 | 128 |
| deception-engine | 51.54MiB | 67.7MiB | 0.17% / 3 | 384 | 1.0 | 100 |
| session-module | 97.55MiB | 106.1MiB | 1.09% / 16 | 512 | 1.0 | 128 |
| evidence-store | 50.2MiB | 64.29MiB | 0.48% / 9 | 768 | 1.0 | 128 |
| scaling-agent | 12.48MiB | 13.51MiB | 0.23% / 13 | 128 | 0.5 | 128 |
| metrics-bridge | 25.06MiB | 41.48MiB | 0.01% / 1 | 128 | 0.25 | 64 |
| redis-deception | 5.602MiB | 9.684MiB | 0.46% / 6 | 1536 | 1.0 | 64 |
| redis-mitre | 9.898MiB | 9.754MiB | 0.39% / 6 | 4608 | 1.0 | 64 |
| postgres | 19.77MiB | 36.38MiB | 0.00% / 6 | 768 | 1.0 | 128 |
| mysql | 354.5MiB | 352.6MiB | 0.53% / 38 | 1024 | 1.0 | 256 |
| redpanda | 308.8MiB | 311.5MiB | 0.94% / 3 | 1536 | 1.5 | 128 |
| redpanda-init | N/A | N/A | N/A / N/A | 256 | 0.5 | 64 |
| backend-containment-init | N/A | N/A | N/A / N/A | 256 | 0.5 | 64 |
| sandbox-replay-engine | 48MiB | 61.66MiB | 0.12% / 6 | 384 | 0.5 | 100 |
| sandbox-postgres | 103.8MiB | 84.14MiB | 0.00% / 6 | 512 | 0.5 | 100 |
| sandbox-mysql | 606.1MiB | 605.2MiB | 0.61% / 40 | 1024 | 0.75 | 256 |
| operator-gateway | N/A | 6.336MiB | 3.13% / 2 | 64 | 0.5 | 64 |
| prometheus | 98.41MiB | 81.15MiB | 0.01% / 14 | 512 | 1.0 | 128 |
| grafana | 98MiB | 95.72MiB | 0.04% / 21 | 384 | 0.5 | 128 |
| loki | 87.88MiB | 52.91MiB | 0.55% / 32 | 512 | 1.0 | 128 |
| promtail | 48.4MiB | 31.97MiB | 1.04% / 14 | 256 | 0.5 | 128 |
| json-exporter | 14.67MiB | 12.17MiB | 0.00% / 9 | 64 | 0.25 | 64 |

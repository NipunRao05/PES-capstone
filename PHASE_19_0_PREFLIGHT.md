# Phase 19.0 Hardware, Storage, and Runtime Preflight

Validation date: 2026-08-27

Repository: `F:\b\Capstone-main`

Branch / HEAD: `main` / `1c938e47b52ef133c6f4f26fc4449673f41ff2dc`

Status: **VERIFIED**

This phase establishes resource and storage feasibility only. It makes no model-quality, research-effectiveness, or final-model-selection claim.

## Worktree boundary

The preflight began with user-owned instruction-file changes already present:

```text
 D AGENTS_UPDATED.md
?? UPDATED_AGENTS.md
```

Those changes were preserved. No Git commit or push was performed.

## Measured host resources

| Resource | Current measurement |
|---|---:|
| CPU | Intel Core i7-7700 @ 3.60 GHz |
| Physical cores | 4 |
| Logical processors | 8 |
| Installed RAM | 31.89 GiB |
| Free RAM | 16.36 GiB |
| Used RAM | 15.53 GiB |
| GPU | Intel HD Graphics 630; no useful discrete inference GPU |
| C: free | 6.29 GiB |
| H: free | 893.77 GiB |

The smaller D:, E:, and F: volumes are unsuitable for model storage. Free RAM and disk values are point-in-time measurements and must be rechecked before the Phase 19.1 pull/benchmark.

## Docker resource state

```text
Docker CPUs                 8 logical CPUs
Docker memory ceiling       15.56 GiB (16,709,709,824 bytes)
Running-container memory    approximately 2.102 GiB
Approximate Docker headroom approximately 13.46 GiB
Docker root                 /var/lib/docker (overlayfs)
```

Per-container memory snapshot:

| Container | Memory |
|---|---:|
| capstone-ai-agent | 40.89 MiB |
| capstone-evidence-store | 51.79 MiB |
| capstone-llm-agent | 37.63 MiB |
| capstone-llm-agent-api | 1.824 MiB |
| capstone-main-deception-engine-1 | 49.67 MiB |
| capstone-main-grafana-1 | 90.55 MiB |
| capstone-main-json-exporter-1 | 14.71 MiB |
| capstone-main-loki-1 | 81.79 MiB |
| capstone-main-metrics-bridge-1 | 24.85 MiB |
| capstone-main-mitre-agent-1 | 51.25 MiB |
| capstone-main-mysql-1 | 379.6 MiB |
| capstone-main-mysqlproxy-1 | 6.445 MiB |
| capstone-main-pgproxy-1 | 6.285 MiB |
| capstone-main-postgres-1 | 32.13 MiB |
| capstone-main-prometheus-1 | 94.62 MiB |
| capstone-main-promtail-1 | 42.87 MiB |
| capstone-main-redis-deception-1 | 8.527 MiB |
| capstone-main-redis-mitre-1 | 5.164 MiB |
| capstone-main-redpanda-1 | 295.1 MiB |
| capstone-main-sandbox-mysql-1 | 578.9 MiB |
| capstone-main-sandbox-postgres-1 | 86.93 MiB |
| capstone-main-scaling-agent-1 | 14.36 MiB |
| capstone-main-session-module-1 | 102.4 MiB |
| capstone-sandbox-replay-api | 2.367 MiB |
| capstone-sandbox-replay-engine | 51.57 MiB |

The optional `capstone-local-llm` container remained stopped. Its preserved Phase 18 profile is 4 GiB memory, 4 logical CPUs, read-only root filesystem, all Linux capabilities dropped, internal-only networking, no host ports, and a read-only model mount. Rendered Compose configuration has no service dependency on `local-llm`.

## Model-storage finding

The existing named model volume resolves to:

```text
capstone-main_local_llm_models
→ /var/lib/docker/volumes/capstone-main_local_llm_models/_data
→ C:\Users\ISFCR\AppData\Local\Docker\wsl\disk\docker_data.vhdx
```

Therefore the existing volume is backed by `C:`, which had only 6.29 GiB free. It is not safe to pull `ornith-1.5:9b` into that volume.

A network-isolated, read-only inspection measured the existing model data at 941 MiB and found exactly one manifest:

```text
qwen2.5:1.5b-instruct-q4_K_M
```

No Ornith model was present or pulled. The Qwen Phase 18/19 baseline volume remains unchanged.

Phase 19.1 storage precondition:

```text
use an explicit Docker Desktop-supported bind mount backed by H:
preserve the current Qwen named volume
verify the H: path and free space immediately before the pull
do not relocate Docker Desktop or mutate the existing volume blindly
```

## Selected Phase 19.1 resource profile

Measured headroom supports the updated handoff's conservative starting profile:

```text
CPU cap              4 logical CPUs
memory cap           9 GiB
parallel inference   1
queue depth          2
context              4096 tokens
maximum output       512 tokens initially
keep-alive           5 minutes, configurable
hard client timeout  300 seconds for the bounded benchmark
automatic retries    0 beyond the existing bounded workflow
```

The memory cap may increase to 10 GiB only if Phase 19.1 measurements prove it necessary and host/Docker reserve remains safe. No Docker or WSL limit was changed during this preflight.

## Live readiness and regression evidence

The following endpoints returned HTTP 200:

```text
deception-engine /readyz
session-module /readyz
mitre-agent /readyz
mysqlproxy /ready
pgproxy /ready
scaling-agent /healthz
ai-agent /readyz
evidence-store /readyz
sandbox-replay /readyz
Prometheus /-/ready
Grafana /api/health
Redpanda /v1/status/ready
```

Additional checks:

```text
redis-deception PING                         PONG
redis-mitre PING                             PONG
MySQL mysqladmin ping                        alive
PostgreSQL pg_isready                        accepting connections
Redpanda cluster health                      healthy; no down nodes or leaderless partitions
docker compose config --quiet                PASS
Phase 18 local-LLM focused tests             9/9 PASS
Phase 19 generator focused tests             15/15 PASS
Phase 17 candidate-validation compatibility  12/12 PASS
```

The default Windows Store `python.exe` alias was inaccessible. The tests were rerun with the bundled workspace Python. The local-LLM suite requires its own directory as the working directory because it imports `client` as a local module; rerunning it there passed 9/9.

## Acceptance result

```text
[x] current host RAM recorded
[x] current Docker memory/CPU ceiling recorded
[x] per-container memory recorded
[x] model-storage backing drive verified
[x] no low-space model pull to C:
[x] core honeypot services remain healthy
[x] bounded local-AI resource profile selected from measured headroom
[x] no Docker/WSL limit increased
```

Phase 19.0 is **VERIFIED**. Phase 19.1 may begin only after its model storage is explicitly bound to the high-headroom H: drive and rechecked. This is a storage precondition, not a `BLOCKED_RESOURCE` result for Phase 19.0.

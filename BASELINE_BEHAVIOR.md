# Deterministic Baseline Behavior

Checkpoint date: 2026-08-24

Baseline run: `baseline-1787551496-5f7480`

Result: **PASS (40/40 assertions)**

This is a bounded local regression capture through the real MySQL and PostgreSQL proxies. It did not rebuild images, run a load test, change application code, or deploy anything.

## Captured behavior

| Behavior | Protocol output | Latency | Evidence result | Verification |
|---|---|---:|---|---|
| Benign MySQL session | Marker column returned value `1` | 306.89 ms | Session `24fc5914-2634-4b00-8353-37b5bf44ae02`; risk `0.0/low`; trap `false`; no MITRE technique; connection/query/MITRE/scaling trace present | PASS |
| Benign PostgreSQL session | `database_name=testdb`, `user_name=postgres`, marker value `1` | 283.21 ms | Session `815b1751-756c-410a-bdcb-d94f0e5f8bec`; risk `0.0/low`; trap `false`; no MITRE technique; connection/query/MITRE/scaling trace present | PASS |
| Catalog enumeration | `information_schema`, `mysql`, `performance_schema`, `hr_production`, `finance_production`, `crm_production` | 280.88 ms | Session `50aa88c5-b55e-4fbe-a7a5-38414325032b`; risk `6.0/medium`; trap `false`; MITRE `T1213.006`; two scaling records | PASS |
| Trap-table interaction | Columns `id, service, token, notes, created_at`; synthetic row used `slack`, `HONEYPOT_PK_LIVE_FAKE_*`, and `old prod key` | 383.29 ms | Session `8d99d23f-a5c4-4e60-9fe2-c358049ac56a`; risk `12.0/critical`; trap `true`; MITRE `T1213.006`; two scaling records | PASS |
| MITRE mapping | Catalog and trap sessions mapped to Data from Information Repositories: Databases | Asynchronous | Technique `T1213.006`; benign sessions remained unmapped/low | PASS |
| Scaling decision | Trap raw/smoothed score `0.7/0.7`; logical target `6 -> 7`; reason recorded bounded scale-up | Asynchronous | Scaling event `247fd5856919fae5da6ee112ac05f2aacd1cc59fa67c76d716d7bbf5eddbfc50` linked to the trap session | PASS |
| AI Agent v1 brief | HIGH summary attributed the fresh trap session | Asynchronous | Report `2f5087b0-126d-4a38-80f9-8e7fbf85243d`; trap counters `22/22`; metric consistency `true`; evidence link stored; control mode `automatic` | PASS |

Valid synthetic API-key prefixes are `HONEYPOT_SK_LIVE_FAKE_`, `HONEYPOT_PK_LIVE_FAKE_`, `DECOY_API_KEY_`, and `DECOY_TOKEN_`; the harness rejects tokens outside this allowlist.

The latency values include Docker client startup overhead and are baseline observations, not throughput measurements. The regression ceiling is intentionally conservative at 10 seconds; comparative latency experiments belong to later research phases.

## Current deterministic rules

Scaling configuration captured from the live service:

| Rule | Baseline value |
|---|---:|
| Replica range | 1-10 |
| Maximum scale-up step | 2 |
| Scale-up threshold | 0.6 |
| Scale-down threshold | 0.3 |
| Scale-up cooldown | 30 seconds |
| Scale-down window | 120 seconds |
| EWMA alpha | 0.3 |
| Z-score threshold | 2.5 |
| Feature weights | attacker confidence 0.4; failed-auth ratio 0.1; query entropy 0.2; session depth 0.3 |
| Operator state | automatic; safe mode off; autoscaling on; budget 10 |

Rule-asset provenance for this capture:

| Asset | SHA-256 |
|---|---|
| `deception_engine/api.py` | `0acec3df42666000157e9639aff2e7f61a390f3c782e31847a0a71512af0a800` |
| `deception_engine/exposure.py` | `b850355cbde9356d006063e9547c4d719f1d60a2b546e3b7f910859484b5df6c` |
| `deception_engine/generator.py` | `52150ffd19c80ff8faebe1427a754ac00e058258a276b78b410d8876af268763` |
| `deception_engine/mutation_store.py` | `da2f74466f3e19103edfe7cf4c2e4f040b0fb3089f1e5e649fb65f1a5c4b0f5c` |
| `deception_engine/schemas/crm.yaml` | `f3c719133b5fcce99886c4ebf228758d2b7e22315fceaf35afacdd48801eeb43` |
| `deception_engine/schemas/finance.yaml` | `e2517c6ef383cbac69e1f69f9c39b1458b9e35373a489f3bd06cd1f2d90572b6` |
| `deception_engine/schemas/hr.yaml` | `cc256096e769dfb64c48862b9b272c702058b87b1dd7bf02d8991d2f244033b8` |
| `mitre_agent/rules/detection_rules.yaml` | `2db4ad273afced6e11478e0a3862d6c204fad4794735352b007f543c1f93de34` |
| `mitre_agent/rules/deception_profiles.yaml` | `14c9f227e2a23b1ce71499464b9a1e59b332e9e8b48047f2143686c4675b0447` |
| `mitre_agent/rules/hmm_config.yaml` | `80b2833e7c2a99ec7440abc5a5f4ff4c18fffe9f2b659903b379fe45da13126a` |
| `scaling_agent/internal/scaler/scaler.go` | `21a07a5ebdd418d640684e32935b9c0ae5b5493ef70d4c48e4dbb95f93e2e2b7` |
| `scaling_agent/internal/scorer/scorer.go` | `1abf74672e570f3816cb912744625d3116d042d67b38a9fe2d6d276aca785e1f` |

Hashes are provenance, not pass/fail assertions. Later refactors may change implementation while preserving this observable contract.

## Reproduction

Run from the repository root with the verified Compose stack running:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\baseline\capture_baseline.ps1
```

Expected result: JSON with `status=PASS`, `40` passed assertions, and `0` failed assertions. Dynamic run/session/report/event IDs, synthetic row values, timestamps, replica starting state, and measured latency may change. The semantic response, risk, MITRE, trap, bounded scaling, and AI contracts must remain stable.





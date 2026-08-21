# Local Pre-Deployment Security Gate

Date: 2026-08-21  
Result: **PASS_LOCAL_PREDEPLOY (17/17)**  
Deployment performed: **No**  
Public exposure enabled: **No**

## Verified locally

- Every published Compose port is bound to `127.0.0.1`; no service is publicly
  exposed.
- The MySQL and PostgreSQL backend containers publish no host ports. Attack
  traffic reaches only the decoy proxies.
- The native Windows PostgreSQL 18 service is stopped and disabled, while its
  installation and data remain intact. Docker `pgproxy` owns
  `127.0.0.1:5432`.
- `.env` is not tracked by Git.
- The control and sandbox networks use Docker `internal=true`.
- The bounded report engine has only the internal control network and contains
  no paid-API or database client dependency.
- Evidence store, AI Agent v1, bounded AI v2, and sandbox replay run non-root
  with read-only root filesystems, all Linux capabilities dropped, and
  `no-new-privileges`.
- Stored source addresses use HMAC-SHA256 pseudonyms.
- No configured PostgreSQL/MySQL secret value was found in the most recent 500
  Compose log lines per service.
- Deception, evidence, AI v1, AI v2, and sandbox readiness checks passed.
- The operator safe-mode kill switch enabled successfully and the original
  automatic state was restored.
- Max-budget, DLQ, AI v1 down, and AI v2 down alerts are loaded.

Reproduce with:

```powershell
& .\scripts\predeploy_security_gate.ps1
```

## Deployment-only checks intentionally pending

These cannot be truthfully validated without selecting and configuring a cloud
environment. They are the deployment gate, not unfinished local application
work:

- enforce and test cloud egress policy;
- configure and test cloud budget-alarm delivery;
- validate the public firewall exposes only honeypot ports;
- validate the provider-level kill-switch runbook.

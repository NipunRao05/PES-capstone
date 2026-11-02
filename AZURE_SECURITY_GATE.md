# Azure security gate

2026-11-02. Preparation is locally validated; **Azure deployment, reboot, external
port behavior and independent restore remain NOT VERIFIED**. This gate never
authorizes publication by itself. Public exposure needs a later explicit decision.
No terraform apply or enable_public_honeypot=true occurred in this pass.

## Required proof on the intended private VM

| Gate | Required observation | Current Azure status |
| --- | --- | --- |
| Backend containment and HR v1 | Actual restricted grants, both protocols, HR/virtual-principal harness | NOT VERIFIED |
| Evidence durability | Retained records/index/journal and AOF after actual VM reboot | NOT VERIFIED |
| Traffic origin | Both private listener requests retain operator_validation through indexed trace/event | NOT VERIFIED |
| Deployment provenance | Same deployment/run/manifest/image/world/registry identity, fixed experiment v1 | NOT VERIFIED |
| Data mount | Actual LUN0 UUID mount, marker/disk/key continuity; absent-disk start refusal | NOT VERIFIED |
| Secrets | Explicit private0600 values, strong/separate operators, stable keys, no state/custom_data secrets | NOT VERIFIED |
| Resource limits | Correct SKU/real RAM reserve and all reviewed container limits | NOT VERIFIED |
| Docker/image storage | Docker and containerd roots on persistent disk | NOT VERIFIED |
| Runtime egress | Required peers work; metadata/host/public/DNS denied | NOT VERIFIED |
| Host firewall | iptables backend/DOCKER-USER installed, provisioning exception removed | NOT VERIFIED |
| Reboot recovery | Changed boot ID, mounted disk before daemons, offline guard before auto-restart, retained data | NOT VERIFIED |
| Backup/export | Off-VM validated export and both Redis populations independently loaded; stable keys retained | NOT VERIFIED |
| SSH | Effective NSG/admin CIDR plus reachable only from actual administrator network | NOT VERIFIED |
| Database ingress | Effective NSG disabled,5432/3306 unreachable from both networks | NOT VERIFIED |
| Management/operator ports | Loopback bindings and all fixed external probes unreachable | NOT VERIFIED |
| Budget | Actual regional quote/credit/quota review, approved amount, alerts/monitoring | NOT VERIFIED |
| Release/dependencies | Clean release, trusted checksum, source/image identity; EOL/CVE disposition | NOT VERIFIED |

Earlier local PASS results are useful regression evidence, not substitutes for these
host-specific observations. Do not fill a future receipt with PASS based on mocks.

## Machine-checkable artifact bundle

scripts/verify_azure_private_deployment.py creates private-report.json plus hashed
successful validator outputs. It checks disk/secrets/roots/resources,manifest,
observability,isolation,Redis/broker and,with --exercise,both protocols/HR/export.
Without exercise or a supplied pre-reboot baseline it returns NOT_READY. It never
reboots a VM itself. --baseline verifies retained state, not that a real reboot
occurred: record before/after boot IDs and service ordering separately.

scripts/verify_external_ports.py runs independently from admin and non-admin
networks, reporting fixed TCP probes. The operator must establish actual vantage
and inspect effective NIC NSG; a CLI label is not proof of network identity.

After those checks, prepare separate restricted JSON receipts for infrastructure,
budget,backup and reboot. Every receipt needs these common fields:

```json
{
  "status": "NOT_VERIFIED",
  "deployment_id": "REPLACE",
  "checked_at": "REPLACE_UTC_RFC3339"
}
```

Only after actual observation may status become PASS. Additional fields:

- infrastructure: ssh_restricted=true,public_db_enabled=false,management_private=true,
  managed_identity_absent=true. Preserve effective NSG/public-IP/VM review evidence.
- budget: reviewer,alerts_reviewed=true,estimated_seven_day_usd,approved_usd. Estimate
  must not exceed approval; include actual region/SKU/credit and quota review.
- backup: off_vm=true,export_validated=true,evidence_redis_loaded=true,
  principal_redis_loaded=true,stable_keys_preserved=true. Attach independent isolated
  Redis load/hash evidence, not merely the archive-integrity script result.
- reboot: actual_vm_reboot=true,manifest_id from the AFTER private report. Retain
  changed boot IDs, service order and absent-disk refusal evidence.

Run on the operator machine after securely downloading the private report directory
and its referenced files; all reports must be current (within24h), same deployment:

```bash
python3 -B scripts/validate_azure_gate.py --deployment-id "$DEPLOYMENT_ID" \
  --private /private/proof/private-after/private-report.json \
  --admin /private/proof/admin-ports.json --other /private/proof/other-ports.json \
  --infrastructure /private/proof/infrastructure.json \
  --budget /private/proof/budget.json --backup /private/proof/backup.json \
  --reboot /private/proof/reboot.json --output /private/proof/gate-result.json
```

The validator rejects missing/status/scope/stale/artifact checksum/port/budget/restore
or reboot-proof failures and records report hashes. It is an artifact completeness
and integrity check using explicit human attestations, not cryptographic identity
verification, independent cloud API auditing or permission to publish. Review raw
evidence, source authenticity and any remaining operator-only gates too. Do not
relabel synthetic unit-test PASS fixtures as deployment evidence.

## Explicit stop conditions

No public release if disk/marker/key/root fallback is possible, backend privileges
are excessive, public management/SSH is broad, source/identity is unknown, workloads
can reach IMDS/host control paths, restore is untested, provisioning egress remains,
credit/quota is unknown or unsupported/CVE findings lack disposition. Containers
passing readiness does not override these gates. Alerts do not terminate billing.

Data disk prevent_destroy is intentional. Never disable it to bypass missing
backup evidence. Kill switch removes DB NSG ingress without replacing VM/disk;
stop both proxies immediately to terminate established SQL sessions. Current
bootstrap is private-only and cannot publish by toggling an NSG alone.

## Preparation verification

Local Terraform fmt/validate and four mocked plan tests passed with no Azure calls:
private NSG,16GiB rejection,wide SSH rejection,floating image rejection. Focused
Python tests cover disk safety, host-rule construction, archive exclusions, gate
and TCP expectations; Bash syntax checked without executing host bootstrap.
These establish preparation quality only. Actual Student availability, regional
image version, plan/apply, cloud-init success, Linux daemon/mount enforcement,
reboot, effective NSG, external scans and independent restore are future work.

Recorded local results: Terraformfmt/validate PASS;4 mocked tests PASS;48 focused
Python tests PASS3.50s;Bash syntax PASS;source archive integrity/no-Git preparation
PASS. No Azure gate receipt was manufactured from those results.

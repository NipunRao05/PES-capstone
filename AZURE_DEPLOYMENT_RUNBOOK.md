# Azure private deployment and validation runbook

2026-11-02. Prepared commands only: **no Azure apply or public exposure authorized
or performed in this pass**. Run cloud commands only after a separately authorized
private deployment. Examples below use Bash on an operator Linux/WSL machine and
the Ubuntu VM. Use real private variables, never commit their values. Read
deployment/azure/README.md for pricing, limits and variable definitions.

## Before private apply

Preserve source/Git boundaries. Review Pass1–3 reports and current dependency/CVE
risks. Choose a32GiB x86_64 SCSI SKU; confirm subscription policy, regional availability,
family/total vCPU quotas, exact Ubuntu24.04 image version, cost and remaining credit.
No Azure CLI credential inspection was performed by this implementation pass.
Human operator examples (read-only after login):

```bash
az login
az account set --subscription "$SUBSCRIPTION_ID"
az account show --query '{subscription:id,tenant:tenantId,name:name}'
az vm list-skus --location "$REGION" --size "$SKU" --all --output json
az vm list-usage --location "$REGION" --output table
az vm image list --location "$REGION" --publisher Canonical --offer ubuntu-24_04-lts --sku server --all --output table
```

Check restrictions and capabilities (vCPUs,MemoryGB,CPUArchitectureType,DiskControllerTypes),
not just SKU name. Declare actual vm_memory_mb/vm_vcpus in private tfvars. Quota may
be unavailable on Student subscriptions; do not silently select an undersized VM.
Register Microsoft.Compute,Microsoft.Network,Microsoft.Storage only if needed and
authorized; provider auto-registration is disabled. Optional budget additionally
needs consumption permissions/API support. No service principal secret is required
when using operator az login; private SSH key stays on the operator machine.

Use a separate protected working directory/state for each subscription. Copy example
tfvars, replace every placeholder, keep enable_public_honeypot=false. Review
format_blank_data_disk=true only for the newly created blank managed disk; existing
ext4 needs no formatting permission. An existing unknown disk fails for manual review.

```bash
terraform -chdir=deployment/azure init -lockfile=readonly
terraform -chdir=deployment/azure fmt -check -recursive
terraform -chdir=deployment/azure validate
# NEXT AUTHORIZED PRIVATE DEPLOYMENT ONLY, not executed during preparation:
terraform -chdir=deployment/azure plan -var-file=/private/account-a.tfvars -out=/private/account-a.tfplan
# Review resource changes, no application secrets, SSH source and DB-disabled NSG.
terraform -chdir=deployment/azure apply /private/account-a.tfplan
terraform -chdir=deployment/azure output
```

Local state contains infrastructure details, public key, cloud-init and optional
contact addresses. Protect state/backups/plans; never commit/upload them as source.
Data disk prevent_destroy blocks accidental destroy/replacement. RG also refuses
deletion with unexpected remaining resources. It does not replace off-VM backups.

## Release transfer and installation

Start from a user-reviewed clean source commit. Build the Pass3 deterministic archive
and record adjacent release manifest/SHA256. A dirty development bundle is explicitly
NON-RELEASE and cannot substitute for the clean-release gate. Confirm the manifest's
source/image/config/world/strategy references and no secrets/state/real tfvars.

```bash
python3 -B scripts/build_deployment_archive.py --output /private/research-source.tar.gz
sha256sum /private/research-source.tar.gz
scp /private/research-source.tar.gz "$ADMIN@$PUBLIC_IP:research-source.tar.gz"
```

Transmit the expected SHA256 through an independently trusted operator channel;
copying an attacker-replaced checksum beside an archive is not authentication.
On the VM verify the expected checksum before extraction; preserve the source archive.

```bash
printf '%s  %s\n' "$EXPECTED_SHA256" research-source.tar.gz | sha256sum -c -
sudo cloud-init status --wait
sudo systemctl status honeypot-bootstrap.service --no-pager
sudo journalctl -u honeypot-bootstrap.service --no-pager -n 80
findmnt /opt/honeypot-data
# Require bootstrap success, correct LUN0 source and no preexisting source install.
sudo tar --extract --file research-source.tar.gz --directory /opt/honeypot --no-same-owner
```

Bootstrap installs only safe host dependencies/mount/configuration, no source fetch,
application login or principal-key generation. It leaves Docker/containerd masked.
If LUN attachment arrived after timeout, inspect Azure attachment and disk contents;
rerun the bootstrap job explicitly only after resolving that cause. Do not use a
different device or initialize an existing deployment to bypass failure.

Prepare actual secrets on the operator side using the existing placeholder template.
Supply independent operator/runtime passwords, explicit separate decoy login values,
base64 stable principal key and stable pseudonym key. Never put actual secrets in
tfvars/custom_data/commands/history or generate them as part of reboot recovery.
This pass does not create those values. Transfer over SSH to a private staging file,
then install using the supported data-disk path:

```bash
chmod 600 /private/secrets.env
scp /private/secrets.env "$ADMIN@$PUBLIC_IP:secrets.env.upload"
# VM:
chmod 600 secrets.env.upload
sudo install -o root -g root -m 600 secrets.env.upload /opt/honeypot-data/secrets.env
# Remove only that staging copy after verifying installation, not the stable source.
rm -- secrets.env.upload
sudo bash /opt/honeypot/deployment/azure/install_runtime.sh
```

Installer creates a nonsecret EnvironmentFile from Terraform deployment_id/run_id,
fixed experiment/version and managed-disk ID. It uses existing manifest variables,
not another provenance registry. It refuses changed existing identity. .runtime is
linked to persistent runtime storage. Stable-key marker initialization is explicit,
new-disk-only and refuses an existing Docker data-root. Existing marker/key mismatch
requires continuity review, not overwrite. Source hashes are checked on preparation.

Both Docker and containerd ExecStartPre run the new offline guard before any
unless-stopped workload can restart. It validates mount/marker/keys/permissions/
space without needing the daemon. The canonical launcher then performs full daemon,
memory/root/config preflight before Compose. Both persistent engine stores are
under the mounted data disk. No OS-disk storage fallback is accepted.

## Build/acquire images and start privately

Use a root shell with the nonsecret identity environment, while application secrets
are read only by the canonical loader (do not source secrets.env into a shell):

```bash
sudo -i
cd /opt/honeypot
set -a; . /etc/honeypot-runtime.env; set +a
export HONEYPOT_DEPLOYMENT_MODE=true
export HONEYPOT_SECRET_FILE=/opt/honeypot-data/secrets.env
export HONEYPOT_DOCKER_LOG_ROOT=/opt/honeypot-data/docker/containers
python3 -B scripts/deployment_guard.py
docker info --format '{{.DockerRootDir}}'
containerd config dump | head -20
dpkg-query -W docker-ce docker-ce-cli containerd.io docker-compose-plugin
# Provisioning mode allows trusted docker0 build traffic only. No app starts here.
trap 'python3 /usr/local/sbin/honeypot-host-firewall' EXIT
python3 /usr/local/sbin/honeypot-host-firewall --provisioning
python3 -B scripts/honeypot.py compose build --pull
python3 /usr/local/sbin/honeypot-host-firewall
trap - EXIT
python3 -B scripts/honeypot.py config-check
python3 -B scripts/honeypot.py compose config --quiet
systemctl enable --now honeypot.service
```

Record installed Docker29+/Compose/containerd versions and actual image IDs. Apt
packages/wheels are acquired during preparation, not silently upgraded during the
experiment. Reapply the steady firewall if a provisioning shell was killed. Never
start the stack while provisioning mode remains. A separate reviewed image-save/
transfer/load workflow can avoid VM builds, but no private registry is required.

Loopback remains authoritative:5432/3306 normal listeners,15432/13306 operator
validation. NSG also closes all four. Admin Grafana tunnel:

```bash
ssh -N -L 3000:127.0.0.1:3000 "$ADMIN@$PUBLIC_IP"
```

Browse localhost:3000. No public Grafana/API/metrics/Kafka/Redis rule. Host DNS/NTP/
apt/platform-agent egress is preserved; runtime-container metadata/host/public
egress is blocked by namespace and host DOCKER-USER rules. Do not use UFW as the
sole Docker firewall. Sizing/disk headroom and EOL images still need gate review.

## Private checks and actual reboot

From the same root environment, use a new restricted report directory. --exercise
creates ordinary operator-validation queries, disabled fixture principals and an
export; no external traffic or public listener is needed. No helper resets volumes.

```bash
python3 -B scripts/verify_azure_private_deployment.py --exercise --output /opt/honeypot-data/private-before
python3 -B scripts/verify_recovery.py --capture /opt/honeypot-data/before-reboot.json
cat /proc/sys/kernel/random/boot_id
# Explicit maintenance action in the separately authorized private validation:
systemctl reboot
```

Before-reboot verifier returns NOT_READY for the deliberately missing reboot proof;
other checks must pass. Reconnect; verify boot ID changed, disk/daemon/service order
and retained baseline. Use a new report after the reboot:

```bash
# Re-enter root environment as above after reconnect.
systemctl is-active honeypot-firewall.service docker.service containerd.service honeypot.service
findmnt /opt/honeypot-data
python3 -B scripts/verify_azure_private_deployment.py --exercise --baseline /opt/honeypot-data/before-reboot.json --output /opt/honeypot-data/private-after
```

Expected private checks: strict disk/secrets/resources, actual Docker/containerd
roots, manifest identity/images/world,13 runtime checks, isolation/limits, Redis
AOF/noeviction and broker, actual backend grants/HR, both origin/correlation paths,
export checksum/linkage, retained state and steady firewall. Operator exercises may
advance the index; retained original hashes and monotonic sequence must survive.
Loss/unknown data remain visible, not retrofitted. No actual reboot has been proved
by this preparation pass. For absent-disk failure testing, first stop the stack and
daemons, then follow reviewed Azure detach/boot maintenance; never unmount a live
Docker data disk. Require startup refusal and no fresh OS-root state, then reattach.

## External tests from two real networks

On independent operator machines, not the VM itself or a tunnel:

```bash
python3 scripts/verify_external_ports.py --public-ip "$PUBLIC_IP" --deployment-id "$DEPLOYMENT_ID" --vantage admin --output /private/admin-ports.json
# Run from a genuinely different, non-admin network:
python3 scripts/verify_external_ports.py --public-ip "$PUBLIC_IP" --deployment-id "$DEPLOYMENT_ID" --vantage other --output /private/other-ports.json
```

Admin SSH must open; other-network SSH, both DB ports and every listed management/
operator port must be unreachable. TCP failure alone cannot prove an effective NSG
rule: inspect effective NIC NSG and public IP/VM identity separately. The verifier
observes only fixed ports; it never changes exposure. No Internet scan was run here.

## Off-VM backup and independent restore gate

Daily new-directory exports, validate and download over SSH to encrypted operator
storage. Keep separate restricted incident logs before Loki72h expiry. No cloud
backup credentials, expensive managed backup service or automatic live-volume
transfer is introduced.

```bash
# VM root environment:
python3 -B scripts/export_research_evidence.py --output /opt/honeypot-data/exports/day01 --traffic-origin all
python3 -B scripts/verify_recovery.py --capture .runtime/azure-backup-baseline.json
python3 -B scripts/honeypot.py compose stop
python3 -B scripts/backup_azure_evidence.py --output /opt/honeypot-data/backups/redis-continuity.tar
systemctl restart honeypot.service
# Operator: SSH encrypts transport; sudo reads root-only files without a public staging copy.
umask 077
mkdir -p /private/off-vm
chmod 700 /private/off-vm
set -o noclobber
ssh -T "$ADMIN@$PUBLIC_IP" sudo cat /opt/honeypot-data/backups/redis-continuity.tar > /private/off-vm/redis-continuity.tar
ssh -T "$ADMIN@$PUBLIC_IP" sudo tar -C /opt/honeypot-data/exports -cf - day01 > /private/off-vm/export-day01.tar
tar -xf /private/off-vm/export-day01.tar -C /private/off-vm
age -r "$OPERATOR_AGE_PUBLIC_KEY" -o /private/off-vm/redis-continuity.tar.age /private/off-vm/redis-continuity.tar
python3 -B scripts/backup_azure_evidence.py --validate /private/off-vm/redis-continuity.tar
python3 -B scripts/export_research_evidence.py --validate /private/off-vm/day01
```

Do not use a world-readable staging copy. Transfer stable principal/pseudonym keys separately over an
encrypted channel and retain them encrypted off-VM. The backup script requires a
fully stopped project and covers both Redis volumes, runtime identity, key-fingerprint
marker and the captured retained-state hash baseline, not Kafka/whole VM/secrets.env.
Raw Redis includes sensitive principal verifiers and persisted key material: treat
the archive as a secret, not as a sanitized research export. It rejects path
traversal/links and validates every byte hash.
Checksum validity alone is **not Redis restore proof**.

Before public approval: on an independent, network-isolated machine, extract only
validated members into NEW scratch volumes, start the pinned Redis7 image with
network=none using the copied AOF directory, require successful AOF load/PING and
compare retained trace/index/journal/principal/world hashes to capture. Never mount
live volumes or use FLUSH/import to test. Preserve source and immutable originals;
do not use redis-check-aof --fix. Record failure rather than repairing backup input.
Demonstrate stable-key fingerprint continuity. This preparation adds capture/
integrity tooling and the gate, but has not demonstrated independent Azure restore.

## Kill switch, cost stop and account migration

Future authorized public operation only: set enable_public_honeypot=false in the
private tfvars, review plan, terraform apply to remove only DB NSG rules. It must
not replace VM/disk: NSG switch is absent from immutable custom_data. NSG changes
may leave established connections; immediate fallback:

```bash
python3 -B scripts/honeypot.py compose stop pgproxy mysqlproxy
```

Do not destroy VM/disks as a kill switch. This private bootstrap remains closed
even if NSG is toggled; public publication/host-policy changes require a separate
reviewed release. Deallocate through Azure after validated exports/backups to stop
VM compute charges; disk/IP/storage charges persist. Budget alerts are delayed
notifications, not a kill switch. Review credits daily and alerts50/75/90%.

Account A: export, encrypted off-VM continuity capture if selected, independent
validation, then retire resources deliberately. prevent_destroy intentionally
blocks blind terraform destroy; retaining a disk or removing protection requires
explicit reviewed state/lifecycle handling, never an automatic helper. Protect
state until resource retirement is verified. Do not remove the guard to make a
failed destroy look successful.

Account B: separate private state/tfvars, new az login/subscription/region/quota/
image/key/admin CIDR, new deployment_id/run_id, same deterministic experiment/version.
Expect a new public IP. Choose explicitly:

- Fresh: new blank disk, new principal/world population and separately supplied
  stable keys. Historical exports remain attributed to A; no relabeling/backfill.
- Continuity: securely transfer validated stopped principal/world/evidence backups,
  stable keys and identity history. Restore only into NEW isolated volumes, validate,
  then explicitly reconcile new disk/deployment marker and deployment/run identity.
  Never rewrite a marker or clone live Redis automatically. install_runtime rejects
  changed retained identity; continuity therefore needs a reviewed migration step.

Archive, secrets, state, raw backups and sanitized evidence are separate artifacts.
No VM GitHub credential is required. Public exposure is considered only after every
item in AZURE_SECURITY_GATE.md has current proof and a later explicit authorization.

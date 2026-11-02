# Azure private deployment preparation

Prepared2026-11-02; no Azure login, real plan, apply or public exposure performed.
One Ubuntu24.04 VM, Compose, Standard static IPv4 and separate managed data disk.
No managed identity or managed application/database/observability service.
Authoritative workflow: ../../AZURE_DEPLOYMENT_RUNBOOK.md (repository root).
Public gate: ../../AZURE_SECURITY_GATE.md. Preserve Pass1–3 contracts.

## Files and tooling

Flat Terraform: versions/providers/variables/main/network/compute/security/storage/
outputs.tf; cloud-init.yaml; bootstrap.sh,prepare_disk.py,host_firewall.py and
install_runtime.sh. Terraform>=1.14.0,<1.15.0, reviewed AzureRM=4.64.0; intentional
bounded versions, not an assertion they are newest. The signed provider lock covers
Linux/Windows amd64. Re-review upgrades explicitly; do not silently run init -upgrade.
Linux entrypoint line endings are protected by .gitattributes for Windows teammates.
Operator-side backup validation requires Python3.11+; the VM uses Ubuntu24.04 Python3.12.
Terraform local backend is intentional. State/backup/plan/tfvars contain sensitive
infrastructure details; keep encrypted/restricted outside Git. No application secret,
private SSH key or GitHub credential belongs in Terraform or cloud-init.

## Per-account variables

Copy terraform.tfvars.example to a private ignored file and replace placeholders.
Required: subscription_id,tenant_id,resource_group_name,location,name_prefix,
public_ip_name,vm_size,vm_memory_mb,vm_vcpus,admin_username,admin_source_cidr,
ssh_public_key,image_version,deployment_id,run_id. CIDR is one IPv4/24–/32; use/32
where practical. Size capability values are explicit operator declarations from
the actual SKU listing, not independent discovery. Host preflight measures real RAM.
All teammate-specific IDs/names/region/SKU/key/address inputs remain configurable.
Azure assigns the static address; public_ip output is its authority, not a literal
address transferable to another subscription.

Optional: IPv4 VNet/subnet CIDRs (default10.42.0.0/16,10.42.1.0/24; must not overlap
Docker172.28.0.0/16 or administrator networks),64GiB OS/128GiB data SSD sizing,
disk type, blank-disk formatting permission and budget notification settings.
Review image/SKU compatibility: bootstrap deliberately supports x86_64 SCSI LUN0;
NVMe-only/ARM SKUs fail rather than guess a disk. Budget contacts/dates are optional;
manual cost/credit review is mandatory. Current fixed experiment is
deterministic_baseline/version1; other experiments are rejected.

## Sizing and cost: East US retail example

Queried Microsoft unauthenticated [Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
on2026-11-02, USD Linux on-demand,168h, no Windows/CloudServices/Spot/reservation
meters. Subscription-specific Student availability/quotas/discounts NOT VERIFIED.

| SKU | vCPU / GiB | USD/hour | VM alone/168h | Decision |
| --- | --- | --- | --- | --- |
| Standard_B4ms |4/16|0.166|27.89|Reject: below18176MiB guard; burst credits also matter |
| Standard_D4as_v5 |4/16|0.172|28.90|Reject: below guard, despite non-burstable CPU |
| Standard_B8ms |8/32|0.333|55.94|Memory fits, credit-dependent CPU and higher cost |
| Standard_E4as_v5 |4/32|0.226|37.97|Initial candidate, non-burstable, subject to quota |

[Easv5 specifications](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/memory-optimized/easv5-series),
[B-series credit behavior](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/bv1-series).
Do not choose based on idle RSS. Pass3 maxima16128MiB+reserve2048MiB=18176MiB;
16GiB is deliberately rejected. Four vCPUs are a baseline candidate, not a measured
seven-day CPU-capacity guarantee. Student free B1s-class offers are insufficient.

E4as_v5 example: VM37.968; E6 StandardSSD_LRS OS64GiB4.80/month ->1.105 for168/730h;
E10 data128GiB9.60/month ->2.209; Standard IPv4 static0.005/h ->0.840.
Base~42.12. Reserve10GB outbound at0.087/GB ->0.87 (MGN tier above100GB; do not rely
on an unused free allowance), plus2.00 provisional SSD transaction allowance:
**approximately44.99 USD/seven days**, before taxes, currency conversion, retries,
additional exports/logging and unmodeled transactions. B8ms equivalent~62.97.
Disk transactions are metered separately; the2.00 allowance is not a rate guarantee.
Requery your actual region/SKU before authorizing apply. Retained disks/IP keep
billing while a VM is deallocated. VM shutdown inside Linux is not deallocation.

About45% of the [100USD Student credit](https://learn.microsoft.com/azure/education-hub/about-azure-for-students)
is not a modest portion. Do not conceal that conflict by reducing safe RAM. Prefer
an initial24–48h private validation window (roughly13USD base for48h plus traffic/
transaction contingency), then deallocate and review spend. Budget50USD defaults
to optional alerts50/75/90%; alerts do not cap spending or stop services. If the
Student API disallows budgets, configure/review Portal credit alerts and preserve
evidence of the manual decision. Never upgrade to a paid subscription implicitly.

## Azure and boot behavior

Resources: RG,VNet,subnet,NSG,NIC+association,Standard static IPv4,LinuxVM with managed
OS disk,managed data disk+LUN0 attachment; optional RG budget. Ubuntu image:
Canonical:ubuntu-24_04-lts:server:EXACT_VERSION, AMD64 Gen2. Resolve region-specific
version before apply; latest is rejected. See [Canonical's image inventory](https://ubuntu.com/azure/docs/azure-how-to/find-ubuntu-images/).

SSH only from admin_source_cidr, key auth, no root/password login. Custom deny4096
overrides default VNet inbound permission. Only future DB5432/3306 NSG rules are
conditional; enable_public_honeypot defaultsfalse. No Grafana/API/Kafka/Redis/
operator-listener ingress rules. No managed identity.

Cloud-init writes no application secrets. It launches a separate bootstrap systemd
job so Terraform can attach LUN0 after VM creation without a provisioning wait cycle.
Check both cloud-init and honeypot-bootstrap.service; cloud-init done alone does not
prove bootstrap success. Missing LUN0 times out closed; no /dev/sdX guess/OS fallback.
Defaultformat_blank_data_disk=false. Explicit new-disk approval permits formatting
only an unmounted whole disk with no partitions/signatures and an all-zero full
device scan. Existing ext4 is mounted, never reformatted; unknown/nonzero data fails.
The full zero scan may take minutes; bootstrap has a2h ceiling. UUID fstab has no
nofail; actual mount and source are verified. No stable-key marker is fabricated.

Docker/containerd remain masked until operator artifact/key installation. Both data
stores are on /opt/honeypot-data (docker and containerd subdirectories); the latter
avoids Docker29's separate image-store root silently using the OS disk. Docker's
iptables backend is explicit; bootstrap therefore requires a reviewed Engine29+
package from official Docker Ubuntu repository. Installed packages are acquired
at provisioning time, not bit-reproducibly pinned; record/test actual versions.

Host iptables-nft INPUT and DOCKER-USER rules supplement namespace guards without
flushing Docker tables or using UFW. Host SSH is CIDR restricted; Azure DHCP reply
is narrowly allowed; host DNS/NTP/apt/Docker/platform-agent outbound remains usable.
Runtime container IMDS/host/Internet egress is blocked. Only explicit provisioning
mode temporarily permits docker0 build traffic; remove before app startup. See
[Docker firewall ordering](https://docs.docker.com/engine/network/firewall-iptables/)
and [Azure platform IP requirements](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16).
This is reviewed preparation, not actual Azure firewall/reboot proof.

## Validation performed and boundaries

Terraform fmt/validate and mocked-provider tests run locally without cloud auth or
resource creation. Python tests cover disk refusal, firewall rules, archive/state
exclusion, external-port expectations and gate integrity. Shell syntax is checked
without executing bootstrap. No real Azure plan/apply, quota check, cloud-init run,
mount formatting, host firewall installation or VM backup/restore occurred here.
Unsupported image/CVE issues from Pass3 remain public-release gates.

Final local evidence: Terraform1.14.0 fmt-check/validate PASS;4 mocked tests PASS;
48 focused Python tests PASS3.50s;two Bash syntax checks PASS. Both private PG/MySQL
query harness checks PASS after using separate decoy credentials. A development
archive round-trip verified202members,two byte-identical archives,dirty-release
refusal and extracted prepare without Git. All fixtures/archives are ignored and
NON-RELEASE. No full-repository or Azure-runtime validation claim.

The public switch changes NSG rules only; it is intentionally absent from immutable
VM bootstrap input, so disabling ingress does not force VM replacement. This private
bootstrap and Compose remain closed even if someone opens the NSG. A future public
release needs separately reviewed ordinary-proxy host publication/firewall changes.
No management or operator listener should ever be opened as part of that step.

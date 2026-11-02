# Release Reproducibility — Pass 3

2026-11-02. The local build/archive contract is complete; this is not a public
release approval, a vulnerability-free claim or a bit-for-bit image guarantee.
See DEPLOYMENT_RUNTIME_HARDENING.md for isolation, secrets and persistent-disk gates.

## Inputs and immutable identity

Enabled third-party images are tag@sha256 references in config/image-lock.yaml.
Enabled Dockerfile Go/Python/Alpine/nginx bases also have digests. Custom builds have
explicit runtime-v1 local tags; tags are mutable names, so deployment manifests
capture actual service image IDs with a separate image-inventory digest after up.
Before-image IDs/sizes and resolved base observations are retained locally in
.runtime/pass3-before.json and pass3-base-digests.json. Four historical image IDs
were unavailable for inspection; no fabricated before inventory was substituted.

Python direct requirements and resolved transitive versions are pinned using each
enabled context's requirements.lock constraint. All5 images passed pip check;
pytest and application tests are excluded from runtime images. Engine FastAPI was
aligned with the already observed Evidence runtime stack. Go uses pinned go.mod/
go.sum, digest-pinned builders and CGO_ENABLED=0; go mod verify passed in all3
modules. No remote learning/adaptive package workflow was enabled.

Runtime proxy/gateway APK direct packages are version-pinned. Explicit remaining
drift: scaling builder git and scaling runtime ca-certificates/wget still resolve
from APK repositories; transitive APK and Python platform-wheel availability remain
repository dependent. Frozen versions are not an authenticated package mirror or
pip --require-hashes supply chain. Image timestamps/build metadata, host/platform
and upstream availability can change results. Record observed image IDs, retain
reviewed artifacts and rebuild/review deliberately; do not claim identical images
across arbitrary hosts from these pins alone.

Every12 build contexts, including dormant AI contexts, has a .dockerignore excluding
secrets, tests, Git history, caches, evidence and documentation. Enabled Go final
stages copy binaries; Python copies reviewed application files, schemas/strategy
definitions where needed and pinned dependency inputs. Shared source and generated
configuration are read-only runtime binds and are part of deployment identity.
The deployment source digest now includes guard scripts, locks, daemon/service
templates and .dockerignore; secret SALT/KEY/PASSWORD values are placeholders in
configuration identity. A dedicated test verifies rotation does not leak salt or
change nonsecret policy identity.

## Archive format and policy

scripts/build_deployment_archive.py creates a sorted deterministic tar.gz with
zero timestamps/owners and fixed file modes. It includes only enabled build
contexts and reviewed shared/config/deployment/observability/scripts assets.
Actual .env, secrets.env, .runtime, Git, local evidence/exports, tests, caches,
unrelated project history and symlinks are excluded or rejected. Empty canonical
config/empty.env and placeholder .env.example are intentionally included.

Default requires a clean checkout. --development explicitly permits a dirty tree
but marks DEVELOPMENT_NOT_RELEASE, never a release. Neither mode commits, stages,
pushes, uploads, starts cloud resources nor changes actual secrets. Use a new
output name; existing archives are not overwritten.

```text
python -B scripts/build_deployment_archive.py --output releases/research-source.tar.gz
python -B scripts/build_deployment_archive.py --development --output .runtime/releases/review.tar.gz
```

Three outputs: archive, .tar.gz.sha256 and .tar.gz.release.json. The archive embeds
release/source-manifest.json with Git commit, dirty/mode, exact file SHA256 map,
archive_source_digest and source_diff_digest. The external release manifest adds
UTC creation time/byte count/checksum, deployment-manifest ID, deployment-source
digest, configuration/world/strategy-registry versions/digests and observed images.
Archive-source and full-checkout source digests have different scopes and names;
they must not be treated as equal. Image observations supplement immutable launch
identity and have their own digest.

On extraction without .git, the launcher verifies the embedded file hash map and
inventory digest and uses that source identity. Changed source fails verification;
no Git history is required on the target. Checksums detect alteration relative to
the reviewed manifest; they do not authenticate an attacker-replaced manifest.
Transfer the SHA256/manifest through an independently trusted operator channel.
Secret files and persistent research identity/state are provisioned separately.
Never ship a local .runtime directory as a way to seed deployment state.

## Validation

All10 enabled custom images fresh-built successfully on2026-10-31. Subsequent final
build/start matched the completed sources. Runtime image checks found no app tests
or pytest and no broken Python requirements. Archive tests rejected dirty-release
creation, produced two byte-identical development archives, checked member exclusions,
verified all source hashes, and successfully ran prepare from extraction without
Git. A unit regression rejects changed archive source.

BuildKit reported transferred context sizes in the saved build log: engine1.86kB,
session1.29kB,Evidence1.25kB,replay879B,bridge383B,scaling1.62kB,MySQLproxy3.67kB,
PGproxy3.69kB. Containment init shares the replay context; gateway's context has only
its Dockerfile/.dockerignore and no application payload. These are BuildKit's
incremental/deduplicated transferred counts, not total source-tree byte counts or
compressed image sizes. Full per-file source bytes are attested in the191-member
archive and its hash map. Contexts do not include dormant AI/LLM service builds.

Original validation artifact:191members,363057bytes,
SHA25689cdf243760ebf0f7080716d6ec83df021d7b8e9ea5b3c00df09e6bbd56392cd,
commit0fd44e6. That artifact is historical and DEVELOPMENT_NOT_RELEASE. The user
subsequently committed interrupted work as b0b16ba. The continuation artifact and
current source identity are recorded in the addendum below; no clean production
release is implied by the historical development bundle.

## Vulnerability and support review

Docker Scout1.25.0 was available. The bounded high/critical scan of the local engine
image required Docker login and produced no CVE report. No login, scanner service,
large security platform or new credential was introduced. Automated CVE coverage
is **NOT VERIFIED**, including transitive OS/Python/Go packages. This pass uses the
request's permitted honest manual-review fallback, not a zero-CVE assertion.

Confirmed upstream support risks reviewed2026-10-31:

| Component | Finding and treatment |
| --- | --- |
| Promtail3.2.1 | [EOL2026-03-02](https://grafana.com/docs/loki/latest/send-data/promtail/); temporary known-working collector exception; no socket, isolated network, migration must be validated |
| Redpanda24.1.9 | [Support ended2025-04-30](https://support.redpanda.com/hc/en-us/articles/30366903291287-Redpanda-v24-1-X-End-of-Support-Notice); broker/data-format upgrade needs separate compatibility/recovery validation |
| MySQL8.0.46 | [8.0 reached EOL inApril2026](https://dev.mysql.com/doc/relnotes/mysql/8.0/en/); frozen HR persona/retained DB format means no opportunistic major upgrade |
| Grafana10.2/Prometheus2.48/Loki2.9 | Older pinned operational components, private only; current advisory/version assessment required before release; no unverified CVE number assigned |

Digest pinning preserves identity, not security freshness. None of these findings
was hidden by changing a tag or deleting retained data. Before public operation,
obtain an authenticated current scan or equivalent advisory inventory, disposition
findings, validate necessary upgrades and preserve HR/schema/protocol contracts.
The future private-cloud pass must treat unsupported binaries as an explicit gate,
not infer that local containment resolves dependency vulnerabilities.

## Continuation artifacts

Continuation archive at .runtime/pass3-release-continuation/development-a.tar.gz:
191members,363019bytes, SHA256
334c2c3832f15aa7ade66e5ba40d2ac2673d1af751b6e282b74ff786849fd593.
It records user commit b0b16baf918298032d742363cd81c4890093e68d, dirty=true,
DEVELOPMENT_NOT_RELEASE, archive source digest
e3d328c5f5ad64efa5f1fa45ad9b7725eced8794705e21aa59f582cdbd5799e9.
Two archives matched byte-for-byte; exclusions, source checksums, dirty-release
rejection and extracted no-Git prepare passed again. This source-only validation
artifact predates the final documentation handoff and excludes reports by design.
Its deployment manifest references the locally observed launch, not a new cloud
deployment or clean production release. See adjacent .release.json and .sha256.

Developer tooling, local fixtures and generated archives remain ignored and separate
from repository source. Four running image IDs were not inspectable in the current
Docker image catalog; unavailable sizes below do not imply a current fresh-build
or CVE inventory. The original successful fresh-build logs remain historical evidence.

## Observed runtime images

Image sizes are Docker-reported local bytes, not transferred/compressed size. Full IDs and network/port inventory are in .runtime/pass3-after.json.

| Service | Before bytes | After bytes | Image ID |
| --- | --- | --- | --- |
| backend-containment-init | unavailable/new | unavailable | sha256:50c3c92bf9dc362dbb6ca6e7082d7dba458e6a0ee6932ea33d0f92e26b47264b |
| deception-engine | 272497910 | 268272538 | sha256:cc44598dd2bc5740ab4f674fe2467a3c570c7eb7df63435c57c4dc36409fe505 |
| evidence-store | 265864131 | 265753985 | sha256:48c7cdadb242352b702a983c50fc877172e2939dda57e18701895f4367c308a0 |
| grafana | 538061026 | 538061026 | sha256:1ee0c54286b8ca09a3dd1419ff8653e7780a148a006ac088544203bb0affe550 |
| json-exporter | 41230655 | 41230655 | sha256:3a777171d39ad435cb39519e84e0a8b5c63c7e716cc06011f8140cfaabfc1baf |
| loki | 101353905 | 101353905 | sha256:b025a0220f390baaab01578aea2fe0ba677584d9f248c3fe5af15f84dd1de60d |
| metrics-bridge | unavailable/new | unavailable | sha256:90dece4a5ea5ba84c40b95fce9010b8cc85e552091a2c9a4b5dc972276d10ee2 |
| mysql | 1085747945 | 1085747945 | sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b |
| mysqlproxy | 27881970 | 46703162 | sha256:714345774c770098b7a71400b54a6056c4d0dd1bebcd0894bbbf8c45a12bf3f3 |
| operator-gateway | unavailable/new | unavailable | sha256:e0a667d079b8c8c43d3cf422af534829398ddbe3161ea39d2da5a21f5c5c7c96 |
| pgproxy | 32481095 | 49253867 | sha256:2f6ebbbd7a7ccab7d7442059d339f2bc3582cd192a35fcd1842b4bb322e2b1f5 |
| postgres | 636265108 | 636265108 | sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d |
| prometheus | 348876212 | 348876212 | sha256:b440bc0e8aa5bab44a782952c09516b6a50f9d7b2325c1ffafac7bc833298e2e |
| promtail | 266615005 | 266615005 | sha256:bf617e9d67e80247a59f717f9c1ad388d7d32dc0a1d29abd5799516d15e0a9b5 |
| redis-deception | 57300241 | 57300241 | sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499 |
| redis-mitre | 57300241 | 57300241 | sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499 |
| redpanda | 841573816 | 841573816 | sha256:85a30e0084f3d479098c327575e3eb27b729ec31f7d72cd1b2ef1098dc1e3b85 |
| redpanda-init | 841573816 | 841573816 | sha256:85a30e0084f3d479098c327575e3eb27b729ec31f7d72cd1b2ef1098dc1e3b85 |
| sandbox-mysql | 1085747945 | 1085747945 | sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b |
| sandbox-postgres | 636265108 | 636265108 | sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d |
| sandbox-replay-engine | unavailable/new | 273954441 | sha256:41dc2cd279c776ec7a2741ef8dc582dcde9a110bf105e03f8b8c722c8107e5bf |
| scaling-agent | unavailable/new | unavailable | sha256:d3432cb0adff8c25aecc1138bbaf3ad15445f7a0677864b855d6b35a9e076555 |
| session-module | 607460025 | 589096745 | sha256:9393bf0e2cc53b531e1530cbb67cf00c2a9cb9427bb3671d05975d3e50e0191a |

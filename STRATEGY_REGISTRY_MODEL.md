# Pass 5 — Strategy Registry and Commitment Preconditions

> Pass 5C — 2026-10-28: approved engine action bindings now have producer-side
> verification; see ACTION_PROVENANCE_MODEL.md for coverage and private boundaries.

> Pass 5B — 2026-10-28: historical versions, explicit active pointers, semantic
> fingerprints and adjacent lock validation are now implemented. Bounded action
> families replace coarse identity, but executable provenance remains partial.
> See STRATEGY_VERSION_INTEGRITY.md. Historical Pass 5 findings follow.

2026-10-28. **IMPLEMENTED / VERIFIED BY FOCUSED TESTS**; runtime health **NOT VERIFIED**.

The existing `deception_engine/strategies/registry.yaml` and `strategy_registry.py`
remain the strategy metadata authority. The engine loads the registry and uses it
for deterministic response annotations and asset mappings; `policy_guard.py`
consumes it for existing policy checks. Historical adaptation and experiment code
remains dormant. The registry does not replace deterministic response handlers.

Each current entry explicitly specifies integer `strategy_version: 1`, its existing
approval status, `implementation: existing_deterministic` and empty commitment
preconditions. `validation_version` retains its prior, distinct meaning. Legacy
entries missing these new fields default to version 1, that implementation and an
empty list. `D0` remains the existing approved fallback. The registry deliberately
allows only one definition per ID: that version is the active version. Duplicate
IDs are rejected, including duplicate ID/version pairs; multiple historical versions
and historical immutability across separate deployments are not implemented.

Current approved entries: D0 baseline, D1 catalog reconnaissance, D2 backup lure,
D3 credential lure, D4 sensitive-data lure, D6 synthetic mutation simulation.
D5 remains REQUIRES_REVIEW; D7 remains unmapped. The implementation reference is
coarse metadata, not an executable dispatch table or a guarantee of exact handler
provenance. Existing rules still select and execute actions; this pass adds no new
selection path. Unknown/unapproved existing resolution still falls back to D0.

The internal `eligibility(id, version, protocol, record)` returns a boolean and
reason code. Its optional structured preconditions support only `requires` with a
Pass 4 canonical Fact. Every required fact must exist and match; missing, mismatch,
invalid commitment storage, unsupported protocol, unapproved entry, unknown ID and
unknown version are distinguishable. Evaluation uses a defensive `Commitments`
snapshot and never writes the record. Production definitions contain no nonempty
preconditions; test fixtures prove the mechanism. It is not connected to SQL
response selection and does not infer ordinary-session or cross-protocol identity.

No learning, adaptive selector, reward model, experiment assignment, attack graph,
automatic promotion or candidate generation was added. Version immutability across
releases requires later artifact history or review; the current static file alone
cannot detect replacing an old definition with different content under the same
version. Current bindings are descriptive and the legal action-space guarantee is
therefore **PARTIAL**, not an independent execution enforcement boundary.

Focused tests from `deception_engine`, using the bundled Python and existing
ignored pass2-tooling on PYTHONPATH:

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_strategy_commitment_preconditions.py test_strategy_registry.py test_policy_guard.py test_world_commitments.py test_world_commitment_lifecycle.py
```

**52 PASS, 3.23s** after adding the explicit YAML fields. No live services, full
suite, protocol changes or runtime health check.

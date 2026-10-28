# Pass 5C — Producer-Side Action Identity Verification

2026-10-28. IMPLEMENTED / VERIFIED BY FOCUSED TESTS for the engine response
families below. Runtime health NOT VERIFIED.

## 1. Purpose

Registry metadata states an expected binding. Producers now separately supply an
actual action to the serializer; comparison cannot manufacture producer identity.

## 2. Producer definition

A producer is the semantic branch constructing a successful result or an error.
Shared SELECT/COUNT code chooses its existing deterministic asset family before
generation, then supplies the corresponding code-level action only on successful
completion. This uses the existing asset-selection rule, not heuristics over rows,
SQL text, table-name substrings or later response annotations. It does not copy the
registry action_binding field. Exceptions do not claim completed production.

## 3. Action identity authority

strategy_registry.py retains ACTION_BINDINGS. PRODUCER_ACTIONS derives the allowed
runtime vocabulary from it, excluding review_only and adding policy_rejection and
statement_error. No operational error receives a new strategy ID.

## 4. Producer-side contract

Each api.py production `_json_response` call explicitly passes producer_action.
The serializer constructs the unchanged JSON body and attaches an immutable
ActionProvenance(actual, expected, status) to the Python response object.
Legacy calls without an action produce NOT_VERIFIED; there is no inferred default.

## 5. Strategy expected binding

The existing selector resolves the same strategy as before. Its resolved registry
binding supplies expected; the producer parameter supplies actual. Version/digest/
lock files and their semantics are unchanged. No producer calculates a digest.

## 6. Selected versus actual

verify_action returns MATCH, MISMATCH, NOT_VERIFIED or INVALID_ACTION. Mismatch is
an explicit internal result, never a rewritten SQL response or failed transaction.
Tests assert status directly, including deliberately corrupted expected binding.
There is no persistent trace, logging system or application-result record.

## 7. Current producer/action map

| Actual producer branch | Actual identity | Expected strategy |
| --- | --- | --- |
| System-variable/banner and passthrough branches | baseline_response | D0 |
| Database enumeration, PG catalogs, information_schema, MySQL columns, SHOW TABLES | catalog_response | D1 |
| Successful SELECT/COUNT using existing backup family | backup_asset_read | D2 |
| Successful SELECT/COUNT using existing credential family | credential_asset_read | D3 |
| Successful SELECT/COUNT using existing sensitive-data family | sensitive_asset_read | D4 |
| Successful SELECT/COUNT using default family | baseline_response | D0 |
| Successful managed mutation response after existing mutation handling | managed_mutation | D6 |
| Exposure/managed-relation denial | policy_rejection | operational, not lure success |
| Bounded syntax/column error | statement_error | operational, not lure success |

D5 remains REQUIRES_REVIEW and D7 unmapped. No production version/binding correction
or lock regeneration was necessary.

## 8. Errors and rejection

Read authorization returns before successful-read provenance. Relation denial
reports policy_rejection; syntax and column errors report statement_error. Existing
error responses commonly carry D0, so their comparison can legitimately be MISMATCH;
that does not claim successful baseline or lure execution. No selected-intent trace
is invented where the current runtime never retained one.

## 9. Private metadata boundary

Provenance lives only on the Python JSONResponse object. It is absent from body,
headers and HTTP serialization. It expires at that boundary; principal_runtime's
JSON decoding and proxies do not receive it. Future tracing must capture it before
that boundary or explicitly introduce a reviewed private envelope later.

## 10. Client response preservation

Rows, columns, errors, mode, timing policy and existing strategy annotations retain
their prior construction/serialization. Tests compare body bytes with and without
provenance, including mismatch. No proxy changes or protocol test campaign required.

## 11. Compatibility

Missing legacy provenance remains NOT_VERIFIED. Direct principal auth/transaction
dictionary responses, framework HTTP errors and out-of-engine responses are outside
this engine-family contract. They must not be interpreted as verified producers.
Every approved registry family has a verified engine producer; this is not a claim
of provenance coverage for every service response or physical database operation.

## 12. Limits and next boundary

No decision trace, experiment registry, outcome linkage/scoring, learner, shadow
mode, adaptive selector, gap detector, candidate generation, attack graph or
automatic promotion. No persistent provenance event. Action-family identity proves
the instrumented branch contract, not socket delivery or physical mutation success.
Recommended Pass 6: scoped strategy decision/application trace and experiment
registry, explicitly consuming provenance before serialization and retaining UNKNOWN
for uncovered paths. Pass 6 has not started.

## 13. Tests

New test_action_provenance.py: actual D0/D1/D2/D3/D4/D6 producers in both protocols,
COUNT, missing/invalid/matching/mismatching metadata, unchanged payload, denied lure
and independently tampered expected binding. Initial new-file run had one fixture
failure (missing required deception_level), corrected without production changes.

PowerShell from deception_engine, existing bundled interpreter and dependencies:

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_action_provenance.py test_strategy_version_integrity.py test_strategy_commitment_preconditions.py test_strategy_registry.py test_policy_guard.py test_world_commitments.py test_world_commitment_lifecycle.py test_postgres_error_state.py test_principal_state.py test_principal_registry.py test_phase_b_invariants.py
```

128 PASS, 17.16s. One additional tampered-binding test then added; the same command
restricted to test_action_provenance.py: 17 PASS, 5.18s. No live health tests.

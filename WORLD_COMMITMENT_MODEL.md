# Pass 4 — Monotonic Attacker-Visible World Commitments

> Pass 5 progress — 2026-10-28: the existing strategy registry now offers a
> read-only bounded commitment-precondition check. Production preconditions are
> empty and SQL selection is unchanged. See `STRATEGY_REGISTRY_MODEL.md`.

2026-10-28. **IMPLEMENTED / VERIFIED BY FOCUSED TESTS** for the bounded integration
below. Runtime health, real Redis crash recovery and complete observation coverage
are **NOT VERIFIED**. This is a record of exposed facts and an internal contradiction
API; it does not change SQL results or authorize adaptive behavior.

## 1. Purpose

Keep a small durable record of what an authenticated synthetic principal has
already been told. Pass 1 found progressive depth and committed row overlays,
but neither identified individual observed facts. Passes 2 and 3 retain ownership
of transaction transitions and PostgreSQL error state. Their historical documents
remain unchanged; the short note in STATE_WORLD_AUDIT.md identifies this extension.

Repository: `feature/config-observability`, observed HEAD `f568312`, initial tree
clean. All Pass 4 edits remain unstaged/uncommitted. No branch, worktree, service,
volume, credential, feature configuration or dependency-install changes.

## 2. Authority

`principal_runtime.observe` owns durable observation writes under the existing
principal lock. `world_commitments.Fact` and `Commitments` own validation and pure
monotonic semantics. Native SQL engines retain physical database authority;
`persistent_mutations` retains committed synthetic row authority. The new field
does not grant accounts, privileges or physical database access.

Normal callers use `commit`, `get`, `has`, `list`, `check`, `serialize`. Reads and
serialization return copies; the model never exposes its mutable internal map.
There is no remove/replace API. A stale serialized model must never be written
over a fresh record. Runtime always reloads under the principal lock first.

## 3. Fact schema

Identity is the tuple `(namespace, subject, property)` serialized as
`relation|testdb.employees|exists`. The separator cannot appear in any component.

| Field | Bound / meaning |
| --- | --- |
| namespace | Literal `relation`; initial vocabulary only |
| subject | Two lower-case identifiers separated by a dot; each at most 63 characters |
| property / value | `exists`: JSON boolean; `kind`: literal `table` or `view` |
| first_session_id | 1–128 ASCII letters, numbers, underscore or hyphen; provenance only |
| first_committed_at | Timezone-aware ISO timestamp, at most 40 characters |
| source | Literal `synthetic_select_response` |

Example entry (illustrative, no production identity):

```json
{
  "namespace": "relation",
  "subject": "testdb.employees",
  "property": "exists",
  "value": true,
  "first_session_id": "example_session",
  "first_committed_at": "2026-10-28T12:00:00+00:00",
  "source": "synthetic_select_response"
}
```

The model rejects noncanonical forms: uppercase subjects, `1` or `"true"` in place
of a boolean, arbitrary strings, SQL and unknown properties. Extraction lowercases
the supported unquoted SQL identifiers before forming the canonical subject.
JSON keys and list snapshots are sorted deterministically. Only `exists=true`
is integrated now; `kind` is a bounded model vocabulary, not an inferred SELECT fact.
No rows, result sets, passwords, verifiers, HMAC material or SQL are stored here.

## 4. Scope

Commitments are principal-scoped. The containing principal's existing key is the
identity boundary, already protocol-specific. `testdb.employees` names the managed
relation in the current virtual database; it is not the internal YAML schema `hr`
or a claim about a physical database table. PostgreSQL and MySQL use the same
semantic fact schema, but their principal records are separate worlds. No implicit
cross-protocol linking, IP/fingerprint identity or global attacker identity.

Anonymous/ordinary session-only commitments are **DEFERRED** to keep this pass
bounded. A session ID records first provenance, not durable attacker identity.

## 5. Monotonicity

| Operation | Result | Stored value / first provenance |
| --- | --- | --- |
| New identity | `inserted` | Append first value and provenance |
| Same identity/value | `unchanged` | Preserve everything, including original timestamp/session |
| Same identity/different value | `conflict` | Preserve original; no last-writer-wins update |
| Read/check missing identity | `unobserved` from check | No write |
| Capacity/corruption/noncanonical input | Bounded validation error | No eviction or replacement |

At most 128 entries per principal; each field has fixed vocabulary or a length
bound. There is no commitment TTL, truncation or oldest-entry eviction. The trusted
receipt accepts 1–8 known table subjects. Capacity failures keep prior facts and
do not alter SQL output. Equal logical commits converge after fresh locked loads;
conflicting logical commits are reported by the model. There are no invented
change/version semantics and no automatic response repair policy.

## 6. Persistence

Optional `world_commitments` map in the existing `deceptive-principal:<key>` JSON,
saved with the existing `PrincipalRegistry.save`. Old records missing the field
load empty without migration or writes. Malformed present fields are rejected,
not silently erased. The existing persistent Redis-deception AOF/volume remains
the durability mechanism; no new DB, keyspace, service, lock or dependency.

The receipt reloads the binding and record inside the existing lock, validates
and appends to that fresh record, then saves. It never trusts a whole record
snapshot submitted by a proxy. Login, query and account commands already reload
under the same principal lock and preserve the optional field.

The existing `world_revision` remains the **row overlay revision**. Incrementing
it for a SELECT observation would cause previously valid pending transactions to
fail with 40001, changing SQL behavior. Observation inserts therefore leave it
unchanged and use the existing lock with fresh loads. No second revision counter
was added. Existing stale row-commit rejection remains intact; tests show both a
successful pending commit and a stale rejected commit preserve newly stored facts.
The finite lock lease and lack of fencing remain pre-existing limitations.

## 7. Transaction independence

Observation metadata is outside pending overlays and mutation snapshots. BEGIN,
COMMIT, ROLLBACK, PostgreSQL FAILED -> ROLLBACK/COMMIT-as-ROLLBACK, and disconnect
do not delete it. A successful read inside T can expose relation existence even
if subsequent row changes roll back. Future sessions restore committed rows and
retain these facts. Receipt processing does not change binding I/T/E, permissions,
working keys, exposure depth, TTLs or row revision.

## 8. Integration points and actual exposure boundary

1. After an existing successful `fake_table_data` or `high_value_target` result,
   principal query recognizes a small grammar: unqualified `SELECT *` or named
   identifier projections, FROM a known managed table, optional `WHERE id = N`
   and optional `LIMIT N`. It returns private `observation_candidates` containing
   `testdb.<table>`. Empty rows still reveal relation existence. Errors, DML,
   transaction commands, catalogs, aggregates, joins and other SQL have no candidates.
2. Both proxies' existing `servePrincipalQuery` writes the complete existing SQL
   response. Only after all writes return success, virtual principal `fake`
   responses with candidates call the private authenticated `/principals/observe`
   action using the existing HMAC transport and request budget.
3. The engine resolves the authenticated session's existing principal, appends
   `relation / testdb.<table> / exists = true`, and returns inserted/conflict counts.
   Duplicate exposure preserves first provenance. A late receipt may record the
   already-sent fact in a disabled tombstone, without enabling the principal.

**Boundary:** successful proxy response writes followed by a successful durable
receipt. This does not prove client application receipt, parsing or attention.
Candidate construction alone never stores facts. Failed writes never acknowledge.

**Failure window:** a crash, request failure, lost/expired binding or storage
failure after socket writes can leave an exposed fact unrecorded. The proxy logs
one bounded warning without payload/error text and retains the SQL response and
transaction state. There is no retry queue, atomic socket/Redis transaction or
atomic Evidence Store publication. A lost receipt can be recorded on later
successful re-exposure. Synchronous receipt time can delay the next command;
existing transport timeouts bound it. No SQL wire fields/rows/tags are changed.

## 9. Exposure depth relationship

ExposureTracker's depth/last_table remains the existing aggregate progressive
disclosure mechanism. The principal saves max depth and restores it on reconnect;
rollback does not lower it. It does not identify all observed facts and is not
derived from this deliberately incomplete collection. The new collection is
authority for recorded individual observations; depth remains the existing
disclosure-policy input. Neither overwrites or duplicates the other's contents.

## 10. Limitations and next boundary

PARTIAL overall observation coverage: only supported simple principal table reads
are instrumented. Ordinary sessions, catalog/enumeration facts, roles/permissions,
credentials/paths, arbitrary rows and result contradictions are not tracked.
Schema/generator versions are not pinned; this model cannot prevent an external
asset edit from contradicting a prior response. Conflicts are internal results,
not SQL blocks, substitutions or strategy decisions. Times are engine receipt
timestamps for provenance, not distributed causal ordering.

DEFERRED: contradiction repair policy, general attack graph, broader crash/true
parallel Redis/lease-expiry guarantees, atomic evidence/outbox and full replay
world reconstruction. No new strategy/experiment registry, selector, learning,
steering, intervention or AI was implemented or enabled.

Recommended Pass 5 (one focused boundary, not started): inspect and extend the
existing dormant approved strategy registry with explicit versions and read-only
commitment preconditions, keeping current deterministic selection and feature
defaults unchanged. Do not create a competing registry or activate adaptation.

## 11. Focused verification

New Python model tests: first/idempotent/conflict/independent facts; old-record and
JSON round trip; defensive snapshots; canonical validation, capacity and corruption.
New lifecycle tests: actual decision + private observe route; construction vs
receipt; both protocols; reconnect and new registry instance over serialized store;
rollback/FAILED/disconnect; active success and stale commit; principal isolation;
internal conflict with unchanged SQL fields; private auth, invalid receipts,
empty results and storage failure. The fixture uses in-memory Redis with a no-op
lock: sequence/interleaving evidence, not proof of real parallel lease behavior.

Both new Go tests use real response writers with net.Pipe and a stub private HTTP
service: no acknowledgement before reads unblock writes, none after failed writes,
one after complete writes, unchanged PostgreSQL bytes/MySQL result packet payloads
on successful and failed receipts. MySQL comparison excludes framing; the existing
writer and sequence framing are unchanged. No physical backend is supplied.

Commands actually executed, PowerShell from `deception_engine`:

```powershell
$env:PYTHONPATH='F:\b\Capstone-main\.runtime\pass2-tooling'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_world_commitments.py test_world_commitment_lifecycle.py
& 'C:\Users\ISFCR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q -p no:cacheprovider test_world_commitments.py test_world_commitment_lifecycle.py test_postgres_error_state.py test_principal_state.py test_principal_registry.py test_phase_b_invariants.py
```

Initial new-file run: **23 PASS, 2.78s**. Combined first run: **81 PASS, 13.48s**.
A final storage-failure test was then added: **82 PASS, 13.45s** in the final
combined run (24 new cases plus 58 existing cases).

From **each** `pgproxy` and `mysqlproxy`:

```powershell
go test ./internal/protocol ./internal/principal -count=1 -timeout 45s
```

Final **all four packages PASS**: PG protocol 1.726s/principal 1.104s;
MySQL protocol 1.686s/principal 1.118s. Initial new Go tests had two fixture compile
errors (MySQL session constructor and PG message Encode return arity); corrected
before these passing runs. Production compilation and existing tests pass.
`gofmt` applied; `git diff --check` passed. No full suite, service startup/rebuild,
live health check or installation. Real Redis/process restart is NOT VERIFIED.

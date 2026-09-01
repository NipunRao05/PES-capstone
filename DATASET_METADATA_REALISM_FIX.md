# Dataset and PostgreSQL Metadata Realism Fix

Status: **VERIFIED**  
Date: **2026-09-01**  
Scope: bounded correction before the next dynamic-honeypot phase

## Discovered implementation

| Responsibility | Existing source retained |
|---|---|
| Canonical deceptive row generator | `deception_engine/generator.py` |
| Deceptive schema and trap definitions | `deception_engine/schemas/*.yaml` through `SchemaLoader` |
| PostgreSQL metadata response path | `pgproxy` request routing to `deception_engine/api.py` |
| Trap and progressive exposure behavior | YAML `is_trap` / `exposure_depth`, `ExposureTracker`, and the strategy registry |
| Session mutation behavior | Redis keys owned by `deception_engine/mutation_store.py` |

Before this correction, HR employee and department fields were independently
generated per table. PostgreSQL `information_schema.tables` returned a canned
table list, while `information_schema.columns` had no corresponding deceptive
catalog response. Rows and table names came from the YAML schema, but column
metadata and query-aware catalog filtering were incomplete.

## Corrected behavior

- The existing generator now builds one deterministic HR organization per
  session and caches it in a bounded in-process LRU. Session cleanup removes its
  cached world; Redis mutation isolation is unchanged.
- Departments determine allowed roles; roles determine explicit seniority and
  salary bands; the finished hierarchy determines manager IDs and hire dates.
- Employee IDs, names, and corporate emails are unique. Department names are
  unique and continue to use the existing `company.internal` fictional domain.
- Managers exist, are more senior, normally share the employee's department,
  and form an acyclic hierarchy. Department heads report to the synthetic CEO.
- Department `head_count` is derived from assigned employees. `budget_usd` is a
  two-decimal `numeric(12,2)` value derived from department function, size, and
  bounded deterministic variation.
- Password hashes are nonfunctional synthetic values with valid bcrypt syntax,
  length, and alphabet, without obvious padding or decoy labels.
- `information_schema.tables` and `information_schema.columns` are rendered
  from the existing YAML schema at the session's current exposure depth.
- Bounded literal predicates for `table_schema`, `table_name`, and
  `column_name` support `=`, `LIKE`, and `ILIKE`; unrelated rows are excluded.
- Existing trap names, trap flags, exposure depths, registry mappings, policy
  semantics, and D0-D6 behavior were not changed.

## Verification

```text
Focused base-world and metadata tests       PASS 10/10
Complete deception-engine test suite        PASS 68/68
PostgreSQL proxy Go tests                    PASS
PostgreSQL proxy go vet                      PASS
Deception-engine readiness                   PASS (registry degraded=false)
Normal PostgreSQL proxy smoke                PASS 6/6 queries
Git diff whitespace check                    PASS
```

The PostgreSQL smoke verified:

```text
information_schema.tables at public depth 1
employees column names and data types
departments column names and data types
ILIKE table-name filtering
10 coherent public.employees rows
8 derived public.departments rows
```

## Intentional boundary

Metadata predicate handling is deliberately not a full SQL parser. It supports
the bounded reconnaissance forms above and deterministically ignores unsupported
predicate forms rather than expanding authority or changing the deception
architecture.

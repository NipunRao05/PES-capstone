# PostgreSQL Stateful CRUD Regression Fix

Status: **VERIFIED**  
Date: **2026-09-02**

## Root cause

- `pgproxy` consulted the deception engine for managed `SELECT` statements but
  not ordinary `INSERT`, `UPDATE`, or `DELETE` statements. Those mutations
  therefore reached the physical PostgreSQL backend, which correctly had no
  deceptive tables.
- Deception mutation responses contained no result columns. The proxy treated
  that valid mutation shape as unusable and fell through even when the engine
  returned `mode=fake`.
- The deception engine supported LIMIT/OFFSET but did not evaluate the bounded
  row predicate `WHERE id = <integer>`. The mutation store logged UPDATE intent
  but did not apply structured changes to materialized rows.
- PostgreSQL transaction status is owned by `pgproxy`. Backend errors changed
  the session status to `E`, but the synthetic response path did not check it.
  Redis overlays also lacked a per-transaction snapshot for rollback.

## Corrected contract

```text
pgproxy qualified/unqualified CRUD recognition
  -> normalized deceptive table name
  -> bounded id predicate and UPDATE assignment parsing
  -> per-session Redis mutation overlay
  -> exact affected-row command tag
```

- `employees` and `public.employees` resolve through the same existing table
  normalization for SELECT/INSERT/UPDATE/DELETE.
- Supported row predicates are intentionally limited to
  `WHERE [alias.]id = <positive integer>` with optional LIMIT/OFFSET for SELECT.
- Supported UPDATE assignments are simple literals or same-column numeric
  addition/subtraction, bounded to existing deceptive columns.
- UPDATE and DELETE apply only to the matching row and return exact PostgreSQL
  command tags such as `UPDATE 1` and `DELETE 1`.
- Transactional mutations capture the prior session/table Redis overlay once.
  COMMIT discards the snapshot; ROLLBACK restores it.
- The proxy notifies the deception engine only after PostgreSQL successfully
  completes COMMIT/ROLLBACK and before forwarding ReadyForQuery. Notification
  failure closes the connection rather than presenting contradictory state.
- While PostgreSQL transaction status is `E`, deceptive queries receive SQLSTATE
  `25P02`; ROLLBACK still reaches PostgreSQL and clears the state.
- Mutation state remains keyed by session ID. No physical deceptive PostgreSQL
  table, shared mutation state, or general SQL parser was introduced.

## Verification

```text
Focused deceptive CRUD tests                    PASS 5/5
Complete deception-engine suite                 PASS 73/73
Authoritative session-state tests               PASS 9/9
pgproxy tests                                   PASS
pgproxy go vet                                  PASS
Dataset/metadata/trap/strategy regressions      PASS
Live filtered SELECT                            PASS (exactly one row)
Live UPDATE + ROLLBACK                          PASS (X -> X+100 -> X)
Live COMMIT                                     PASS (same-session persistence)
Live aborted transaction                        PASS (25P02 until ROLLBACK)
Live simultaneous two-session isolation         PASS
Live qualified INSERT/DELETE + ROLLBACK         PASS
```

The metadata catalog, coherent HR generator, trap flags/exposure depths,
strategy registry, policy guard, learning components, reward model, MITRE
logic, and scaling architecture were not redesigned.

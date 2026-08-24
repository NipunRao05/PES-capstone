# Phase 2 authoritative-state validation

Run from the repository root while the local Compose stack is running:

powershell -ExecutionPolicy Bypass -File .\tests\state\validate_authoritative_state.ps1

The script creates uniquely named objects only in the isolated local decoy
PostgreSQL/MySQL services and removes them during the tested session. It proves:

- CREATE, INSERT, UPDATE, SELECT, DROP, and SELECT-after-DROP failure
- PostgreSQL transactional DDL rollback and MySQL transactional row rollback
- PostgreSQL role/permission switching and reset
- schema discovery through both proxy protocols
- confirmed backend outcomes and transaction flags reach the state projector
- unverified query intent is not accepted as an authoritative mutation
- dropped or rolled-back objects do not remain visible in projected state

Unit validation:

docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v F:\b\Capstone-main\session_module:/app -w /app capstone-main-session-module python -m pytest -q test_session_module.py test_authoritative_state.py

Authority boundaries:

- MySQL/PostgreSQL engines remain database truth.
- The projector never connects to a database and never executes SQL.
- Backend, deterministic deception, and policy outcomes are labeled separately.
- Only confirmed successful backend outcomes mutate database-object state.
- Confirmed deception outcomes may update discovery/trap state but not backend objects.
- Raw backend error text is not published; only bounded MySQL/SQLSTATE codes are retained.
- The state API is host-bound to 127.0.0.1 through Compose.
- State is bounded in memory in Phase 2; per-session collections and metadata are capped, non-finite risk is rejected, and restart persistence remains Phase 24.
- PostgreSQL extended-protocol executions remain explicitly unverified until a
  complete backend outcome can be correlated at Sync/ReadyForQuery; they cannot
  mutate projected authoritative state.

"""
mutation_store.py — Per-session in-memory mutation state.

When an attacker runs INSERT/UPDATE/DELETE, the changes are stored
in Redis for the duration of the session. Subsequent SELECT queries
reflect those mutations, making consistency probes pass.

This is what defeats honeypot detection via:
  INSERT INTO users VALUES (999, 'test@test.com');
  SELECT COUNT(*) FROM users;   ← must return original_count + 1

Redis key: mutation:{session_id}:{table_name}
Stores: {inserts: [...], updates: [...], deletes: [...], count_delta: int}
TTL: 4 hours
"""

from __future__ import annotations

import json
import logging
import time

import redis

log = logging.getLogger(__name__)

REDIS_KEY_PREFIX = "mutation:"
REDIS_TX_KEY_PREFIX = "mutation-tx:"
REDIS_TTL_SECONDS = 4 * 60 * 60


class MutationStore:
    """
    Tracks INSERT/UPDATE/DELETE operations per session per table.
    Provides adjusted row counts and mutated rows for SELECT responses.
    """

    def __init__(self, redis_client: redis.Redis):
        self._redis = redis_client

    def record_insert(
        self, session_id: str, table_name: str, row: dict,
        transaction_active: bool = False,
    ) -> None:
        """Record an INSERT operation for a session."""
        key = self._key(session_id, table_name)
        try:
            if transaction_active:
                self._capture_transaction_table(session_id, table_name)
            raw = self._redis.get(key)
            state = json.loads(raw) if raw else self._empty_state()
            state["inserts"].append(row)
            state["count_delta"] += 1
            state["last_modified"] = time.time()
            self._redis.setex(key, REDIS_TTL_SECONDS, json.dumps(state))
        except Exception as e:
            log.error("MutationStore record_insert failed: %s", e)

    def record_delete(
        self, session_id: str, table_name: str, where_clause: str,
        row_id: int | None = None, transaction_active: bool = False,
    ) -> None:
        """Record a DELETE operation. Decrements count_delta."""
        key = self._key(session_id, table_name)
        try:
            if transaction_active:
                self._capture_transaction_table(session_id, table_name)
            raw = self._redis.get(key)
            state = json.loads(raw) if raw else self._empty_state()
            already_deleted = row_id is not None and any(
                item.get("row_id") == row_id
                for item in state.get("deletes", []) if isinstance(item, dict)
            )
            if not already_deleted:
                state["deletes"].append({
                    "where": where_clause, "row_id": row_id, "ts": time.time(),
                })
                if row_id is not None:
                    state["count_delta"] -= 1
            state["last_modified"] = time.time()
            self._redis.setex(key, REDIS_TTL_SECONDS, json.dumps(state))
        except Exception as e:
            log.error("MutationStore record_delete failed: %s", e)

    def record_update(
        self, session_id: str, table_name: str, set_clause: str, where_clause: str,
        row_id: int | None = None, assignments: dict | None = None,
        transaction_active: bool = False,
    ) -> None:
        """Record an UPDATE operation."""
        key = self._key(session_id, table_name)
        try:
            if transaction_active:
                self._capture_transaction_table(session_id, table_name)
            raw = self._redis.get(key)
            state = json.loads(raw) if raw else self._empty_state()
            state["updates"].append({
                "set": set_clause,
                "where": where_clause,
                "row_id": row_id,
                "assignments": assignments or {},
                "ts": time.time(),
            })
            state["last_modified"] = time.time()
            self._redis.setex(key, REDIS_TTL_SECONDS, json.dumps(state))
        except Exception as e:
            log.error("MutationStore record_update failed: %s", e)

    def get_count_delta(self, session_id: str, table_name: str) -> int:
        """
        Return the net row count change for a table in this session.
        Used to adjust COUNT(*) responses. Corrupt or migrated Redis records must
        not break SELECT/COUNT handlers, so non-numeric values fall back to 0.
        """
        key = self._key(session_id, table_name)
        try:
            raw = self._redis.get(key)
            if raw:
                state = json.loads(raw)
                value = state.get("count_delta", 0)
                return int(value)
        except Exception as e:
            log.error("MutationStore get_count_delta failed: %s", e)
        return 0

    def get_inserted_rows(self, session_id: str, table_name: str) -> list[dict]:
        """
        Return rows inserted by this session (prepended to SELECT results).
        Ignores malformed entries instead of returning strings/lists that would
        later corrupt the fake result shape.
        """
        key = self._key(session_id, table_name)
        try:
            raw = self._redis.get(key)
            if raw:
                state = json.loads(raw)
                rows = state.get("inserts", [])
                if isinstance(rows, list):
                    return [r for r in rows if isinstance(r, dict)]
        except Exception as e:
            log.error("MutationStore get_inserted_rows failed: %s", e)
        return []

    def apply_rows(
        self, session_id: str, table_name: str, rows: list[dict]
    ) -> list[dict]:
        """Apply bounded structured UPDATE/DELETE overlays to materialized rows."""
        try:
            raw = self._redis.get(self._key(session_id, table_name))
            state = json.loads(raw) if raw else self._empty_state()
        except Exception as e:
            log.error("MutationStore apply_rows failed to load state: %s", e)
            return [dict(row) for row in rows]

        deleted_ids = {
            item.get("row_id")
            for item in state.get("deletes", []) if isinstance(item, dict)
            and item.get("row_id") is not None
        }
        updates = [
            item for item in state.get("updates", [])
            if isinstance(item, dict) and item.get("row_id") is not None
        ]
        result: list[dict] = []
        for source in rows:
            row = dict(source)
            if row.get("id") in deleted_ids:
                continue
            for update in updates:
                if row.get("id") != update.get("row_id"):
                    continue
                for column, operation in update.get("assignments", {}).items():
                    if not isinstance(operation, dict):
                        continue
                    op = operation.get("op")
                    value = operation.get("value")
                    if op == "set":
                        row[column] = value
                    elif op == "add" and isinstance(row.get(column), (int, float)):
                        row[column] = row[column] + value
                    elif op == "subtract" and isinstance(row.get(column), (int, float)):
                        row[column] = row[column] - value
            result.append(row)
        return result

    def finalize_transaction(self, session_id: str, action: str) -> None:
        """Commit or restore the session-local mutation snapshot."""
        action = str(action or "").strip().lower()
        if action not in {"commit", "rollback"}:
            raise ValueError("transaction action must be commit or rollback")
        tx_key = REDIS_TX_KEY_PREFIX + session_id
        try:
            raw = self._redis.get(tx_key)
            snapshot = json.loads(raw) if raw else {"tables": {}}
            if action == "rollback":
                for table_name, prior in snapshot.get("tables", {}).items():
                    key = self._key(session_id, table_name)
                    if prior is None:
                        self._redis.delete(key)
                    else:
                        self._redis.setex(key, REDIS_TTL_SECONDS, prior)
            self._redis.delete(tx_key)
        except Exception as e:
            log.error("MutationStore finalize_transaction failed: %s", e)
            raise

    def has_mutations(self, session_id: str, table_name: str) -> bool:
        """Returns True if any mutations exist for this session + table."""
        key = self._key(session_id, table_name)
        try:
            return self._redis.exists(key) > 0
        except Exception:
            return False

    def cleanup_session(self, session_id: str) -> None:
        """Remove all mutation state for a session."""
        try:
            pattern = REDIS_KEY_PREFIX + session_id + ":*"
            keys = list(self._redis.scan_iter(pattern, count=200))
            if keys:
                self._redis.delete(*keys)
            self._redis.delete(REDIS_TX_KEY_PREFIX + session_id)
        except Exception as e:
            log.error("MutationStore cleanup_session failed: %s", e)

    # ─── Helpers ──────────────────────────────────────────────────────────

    def _key(self, session_id: str, table_name: str) -> str:
        return f"{REDIS_KEY_PREFIX}{session_id}:{table_name}"

    def _capture_transaction_table(self, session_id: str, table_name: str) -> None:
        """Capture a table overlay once, immediately before its first tx mutation."""
        tx_key = REDIS_TX_KEY_PREFIX + session_id
        raw_tx = self._redis.get(tx_key)
        snapshot = json.loads(raw_tx) if raw_tx else {"tables": {}}
        tables = snapshot.setdefault("tables", {})
        if table_name not in tables:
            tables[table_name] = self._redis.get(self._key(session_id, table_name))
            self._redis.setex(tx_key, REDIS_TTL_SECONDS, json.dumps(snapshot))

    @staticmethod
    def _empty_state() -> dict:
        return {
            "inserts":       [],
            "updates":       [],
            "deletes":       [],
            "count_delta":   0,
            "last_modified": time.time(),
        }

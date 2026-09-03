"""
exposure.py — Progressive table exposure tracker.

Tracks the exploration depth for each active session in Redis.
Controls which tables appear in SHOW TABLES responses based on
how deeply the attacker has explored the schema so far.

Rules:
  - Every session starts at depth 1 (only depth-1 tables visible)
  - When attacker runs SELECT against any depth-1 table → depth becomes 2
  - When attacker runs SELECT against any depth-2 table → depth becomes 3
  - Depth-3 tables include trap/honeytoken tables
  - Depth never decreases

Redis key: exposure:{session_id}
TTL: 4 hours (sessions longer than this are effectively reset)
"""

from __future__ import annotations

import json
import logging
import time

import redis

log = logging.getLogger(__name__)

REDIS_KEY_PREFIX = "exposure:"
REDIS_TTL_SECONDS = 4 * 60 * 60   # 4 hours
MAX_DEPTH = 3


class ExposureTracker:
    """
    Manages per-session exploration depth.
    Determines which tables are visible via progressive disclosure.
    """

    def __init__(self, redis_client: redis.Redis):
        self._redis = redis_client

    def get_depth(self, session_id: str) -> int:
        """Return current exploration depth for a session (default: 1).

        Redis records can be manually edited, migrated, or corrupted during demos.
        Clamp to the valid exposure range so a bad depth value cannot expose all
        trap tables immediately or hide every table.
        """
        key = REDIS_KEY_PREFIX + session_id
        try:
            raw = self._redis.hget(key, "depth")
            depth = int(raw) if raw else 1
            return max(1, min(MAX_DEPTH, depth))
        except Exception as e:
            log.error("Redis get_depth failed for %s: %s", session_id, e)
            return 1

    def record_table_access(
        self, session_id: str, table_name: str, table_depth: int
    ) -> int:
        """
        Record that a session accessed a table at the given depth.
        If table_depth == current_depth, advance to next depth.
        Returns the new depth.
        """
        key = REDIS_KEY_PREFIX + session_id
        try:
            current = self.get_depth(session_id)
            new_depth = current

            if table_depth >= current and current < MAX_DEPTH:
                new_depth = min(current + 1, MAX_DEPTH)
                self._redis.hset(key, mapping={
                    "depth": new_depth,
                    "last_table": table_name,
                    "advanced_at": str(time.time()),
                })
                self._redis.expire(key, REDIS_TTL_SECONDS)
                log.info(
                    "Depth advanced: session=%s table=%s depth=%d→%d",
                    session_id[:8], table_name, current, new_depth,
                )
            else:
                # Just refresh TTL on access
                self._redis.hset(key, mapping={
                    "depth": current,
                    "last_table": table_name,
                })
                self._redis.expire(key, REDIS_TTL_SECONDS)

            return new_depth
        except Exception as e:
            log.error("Redis record_table_access failed for %s: %s", session_id, e)
            return 1

    def initialise_session(self, session_id: str) -> None:
        """Create depth=1 entry for a new session."""
        key = REDIS_KEY_PREFIX + session_id
        try:
            self._redis.hset(key, mapping={
                "depth": 1,
                "created_at": str(time.time()),
                "last_table": "",
            })
            self._redis.expire(key, REDIS_TTL_SECONDS)
        except Exception as e:
            log.error("Redis initialise_session failed for %s: %s", session_id, e)

    def cleanup_session(self, session_id: str) -> None:
        """Remove depth tracking for a closed session."""
        key = REDIS_KEY_PREFIX + session_id
        try:
            self._redis.delete(key)
        except Exception as e:
            log.error("Redis cleanup_session failed for %s: %s", session_id, e)

    def active_session_count(self, limit: int = 10_000) -> int:
        """Return a bounded count of live exposure sessions.

        World reloads use this to avoid changing established schema facts in
        the middle of a connection. Redis remains the shared authority across
        scaled deception-engine replicas.
        """
        count = 0
        try:
            for _key in self._redis.scan_iter(match=REDIS_KEY_PREFIX + "*", count=100):
                count += 1
                if count >= limit:
                    break
        except Exception as e:
            log.error("Redis active-session scan failed: %s", e)
            return -1
        return count

    def get_session_info(self, session_id: str) -> dict:
        """Return full depth info for a session (for debugging)."""
        key = REDIS_KEY_PREFIX + session_id
        try:
            data = self._redis.hgetall(key)
            return {k: v for k, v in data.items()}
        except Exception:
            return {}

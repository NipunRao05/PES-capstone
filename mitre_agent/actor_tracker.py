"""
actor_tracker.py — Cross-session IP-level threat actor correlation.

Maintains an ActorProfile per unique source IP in Redis.
Tracks cumulative risk, phase history, and technique observations
across all sessions from the same IP address.

This is the "same attacker across reconnects" detection.
Redis key format: actor:{ip}
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import redis

from models import ActorProfile, MitreSession

log = logging.getLogger(__name__)

REDIS_KEY_PREFIX = "actor:"
REDIS_TTL_SECONDS = 60 * 60 * 24 * 30   # 30 days


class ActorTracker:
    """
    Persists and updates ActorProfile objects in Redis.
    One profile per unique client_ip.
    """

    def __init__(self, redis_client: redis.Redis):
        self._redis = redis_client

    def update_from_session(self, session: MitreSession) -> ActorProfile:
        """
        Update (or create) the ActorProfile for session.client_ip
        using the completed session's data.
        Returns the updated profile.
        """
        ip = session.client_ip
        key = REDIS_KEY_PREFIX + ip
        now = datetime.now(timezone.utc).isoformat()

        existing = self._get(key)
        if existing:
            profile = ActorProfile(**existing)
            profile.last_seen = now
            profile.session_count += 1
            profile.cumulative_risk += session.final_risk_score

            # Extend phase history (keep last 200 phases)
            profile.phase_history.extend(session.attack_path)
            if len(profile.phase_history) > 200:
                profile.phase_history = profile.phase_history[-200:]

            # Extend technique history (deduplicated, keep last 100)
            for t in session.techniques_matched:
                tid = t.get("technique_id", "")
                if tid and tid not in profile.techniques_seen:
                    profile.techniques_seen.append(tid)
            if len(profile.techniques_seen) > 100:
                profile.techniques_seen = profile.techniques_seen[-100:]

            # Persona history
            if session.persona and session.persona not in profile.personas_seen:
                profile.personas_seen.append(session.persona)

            if session.trap_triggered:
                profile.trap_triggers += 1

            # Mark as known attacker if cumulative risk is high
            if profile.cumulative_risk >= 20:
                profile.is_known_attacker = True

        else:
            profile = ActorProfile(
                ip=ip,
                first_seen=now,
                last_seen=now,
                session_count=1,
                cumulative_risk=session.final_risk_score,
                phase_history=list(session.attack_path),
                techniques_seen=[
                    t.get("technique_id", "")
                    for t in session.techniques_matched
                    if t.get("technique_id")
                ],
                personas_seen=[session.persona] if session.persona else [],
                trap_triggers=1 if session.trap_triggered else 0,
                is_known_attacker=session.final_risk_score >= 20,
            )

        self._set(key, profile)
        log.info(
            "Actor updated: ip=%s cumulative_risk=%.1f sessions=%d known=%s",
            ip, profile.cumulative_risk, profile.session_count,
            profile.is_known_attacker,
        )
        return profile

    def get_profile(self, ip: str) -> ActorProfile | None:
        """Retrieve the ActorProfile for an IP, or None if not seen before."""
        key = REDIS_KEY_PREFIX + ip
        data = self._get(key)
        if data:
            return ActorProfile(**data)
        return None

    def get_cumulative_risk(self, ip: str) -> float:
        """Fast path: return just the cumulative risk for an IP."""
        profile = self.get_profile(ip)
        return profile.cumulative_risk if profile else 0.0

    def is_known_attacker(self, ip: str) -> bool:
        """Returns True if this IP has previously reached critical risk levels."""
        profile = self.get_profile(ip)
        return profile.is_known_attacker if profile else False

    def all_actors(self) -> list[ActorProfile]:
        """Return all stored actor profiles (for dashboard/analytics)."""
        keys = self._redis.scan_iter(REDIS_KEY_PREFIX + "*", count=200)
        profiles = []
        for key in keys:
            data = self._get(key)
            if data:
                try:
                    profiles.append(ActorProfile(**data))
                except Exception as e:
                    log.warning("Failed to deserialise actor profile %s: %s", key, e)
        return profiles

    # ─── Redis helpers ────────────────────────────────────────────────────────

    def _get(self, key: str) -> dict | None:
        try:
            raw = self._redis.get(key)
            if raw:
                return json.loads(raw)
        except Exception as e:
            log.error("Redis GET failed for key %s: %s", key, e)
        return None

    def _set(self, key: str, profile: ActorProfile) -> None:
        try:
            data = {
                "ip":                profile.ip,
                "first_seen":        profile.first_seen,
                "last_seen":         profile.last_seen,
                "session_count":     profile.session_count,
                "cumulative_risk":   profile.cumulative_risk,
                "phase_history":     profile.phase_history,
                "techniques_seen":   profile.techniques_seen,
                "personas_seen":     profile.personas_seen,
                "trap_triggers":     profile.trap_triggers,
                "is_known_attacker": profile.is_known_attacker,
            }
            self._redis.setex(key, REDIS_TTL_SECONDS, json.dumps(data))
        except Exception as e:
            log.error("Redis SET failed for key %s: %s", key, e)

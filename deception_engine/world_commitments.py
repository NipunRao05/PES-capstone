"""Bounded, append-only facts. Persistence/serialization locking belongs to caller.

No row values or SQL belong here. Missing principal fields load as an empty set.
The initial vocabulary is deliberately limited to stable relation metadata.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import re

MAX_FACTS = 128
FIELD = "world_commitments"


@dataclass(frozen=True)
class Fact:
    namespace: str
    subject: str
    property: str
    value: bool | str

    def __post_init__(self):
        if self.namespace != "relation" or not isinstance(self.subject, str) or not re.fullmatch(
                r"[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}", self.subject):
            raise ValueError("Invalid fact identity")
        if self.property == "exists" and type(self.value) is bool:
            return
        if self.property == "kind" and isinstance(self.value, str) and self.value in {"table", "view"}:
            return
        raise ValueError("Invalid canonical fact value")

    @property
    def key(self):
        return "|".join((self.namespace, self.subject, self.property))


class Commitments:
    """A private copy: callers can read snapshots, commit, then serialize explicitly.

    commit returns inserted/unchanged/conflict; a conflict preserves the first
    value and provenance. Never merge stale serialized copies into live records.
    """
    def __init__(self, record):
        entries = record.get(FIELD, {})
        if not isinstance(entries, dict) or len(entries) > MAX_FACTS:
            raise ValueError("Invalid commitment collection")
        self._entries = {}
        for key, item in entries.items():
            if not isinstance(item, dict) or set(item) != {
                    "namespace", "subject", "property", "value", "first_session_id",
                    "first_committed_at", "source"}:
                raise ValueError("Invalid commitment entry")
            fact = Fact(**{k: item[k] for k in ("namespace", "subject", "property", "value")})
            self._provenance(item["first_session_id"], item["first_committed_at"], item["source"])
            if key != fact.key:
                raise ValueError("Invalid commitment key")
            self._entries[key] = deepcopy(item)

    @staticmethod
    def _provenance(session_id, timestamp, source):
        if not isinstance(session_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", session_id):
            raise ValueError("Invalid provenance session")
        if not isinstance(timestamp, str) or len(timestamp) > 40:
            raise ValueError("Invalid provenance timestamp")
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
        if source != "synthetic_select_response":
            raise ValueError("Invalid provenance source")

    def get(self, fact):
        return deepcopy(self._entries.get(fact.key))

    def has(self, fact):
        return fact.key in self._entries

    def check(self, fact):
        existing = self._entries.get(fact.key)
        return "unobserved" if existing is None else (
            "unchanged" if existing["value"] == fact.value else "conflict")

    def list(self):
        return [deepcopy(self._entries[key]) for key in sorted(self._entries)]

    def commit(self, fact, *, session_id, timestamp, source="synthetic_select_response"):
        status = self.check(fact)
        if status != "unobserved":
            return status
        self._provenance(session_id, timestamp, source)
        if len(self._entries) >= MAX_FACTS:
            raise ValueError("Commitment limit exceeded")
        self._entries[fact.key] = dict(namespace=fact.namespace, subject=fact.subject,
            property=fact.property, value=fact.value, first_session_id=session_id,
            first_committed_at=timestamp, source=source)
        return "inserted"

    def serialize(self):
        return {key: deepcopy(self._entries[key]) for key in sorted(self._entries)}

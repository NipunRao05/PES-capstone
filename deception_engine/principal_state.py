"""Existing principal binding lifecycle; no new persisted fields or SQL semantics.

The binding is the sole session transaction representation. Committed mutations
remain in the principal record; working overlays remain in MutationStore. This
view intentionally preserves legacy/missing fields rather than migrating data.
"""
from enum import Enum
from typing import Callable


class PrincipalTransactionState(str, Enum):
    IDLE = "I"
    ACTIVE = "T"
    FAILED = "E"


class PrincipalTransactionConflict(Exception):
    """A pending transaction was based on an older committed principal revision."""


class PrincipalTransactionContext:
    def __init__(self, binding: dict):
        self.binding = binding

    @classmethod
    def new(cls, key: str, revision: int):
        # Keep the original login binding shape, including absent mutation_keys.
        return cls({"key": key, "tx": False, "failed": False, "revision": revision})

    @property
    def active(self) -> bool:
        return self.binding["tx"]

    @property
    def failed(self) -> bool:
        return self.binding["failed"]

    @property
    def state(self) -> PrincipalTransactionState:
        if self.failed:
            return PrincipalTransactionState.FAILED
        return PrincipalTransactionState.ACTIVE if self.active else PrincipalTransactionState.IDLE

    @property
    def expected_mutation_keys(self) -> list[str] | None:
        # Missing keys in an active legacy binding must still fail closed.
        return self.binding.get("mutation_keys")

    def refresh_revision(self, revision: int) -> None:
        self.binding["revision"] = revision

    def begin(self) -> None:
        # Existing repeated BEGIN preserves the pending overlays and baseline.
        self.binding["tx"] = True

    def abort(self) -> None:
        self.binding["failed"] = True

    def record_query_failure(self, protocol: str) -> None:
        if self.active and protocol == "postgres":
            self.abort()

    def track_working_keys(self, keys: list[str]) -> None:
        self.binding["mutation_keys"] = keys if self.active else []

    def commit(self, revision: int, promote: Callable[[], None],
               discard_snapshot: Callable[[], None], restore: Callable[[], None]) -> str:
        if self.active and not self.failed:
            if self.binding["revision"] != revision:
                self.abort()
                raise PrincipalTransactionConflict()
            promote()
        tag = "ROLLBACK" if self.failed else "COMMIT"
        self._finish(discard_snapshot, restore)
        return tag

    def rollback(self, discard_snapshot: Callable[[], None],
                 restore: Callable[[], None]) -> str:
        self._finish(discard_snapshot, restore)
        return "ROLLBACK"

    def _finish(self, discard_snapshot: Callable[[], None],
                restore: Callable[[], None]) -> None:
        # Preserve ordering: failed promotion never reaches here. For principals,
        # both ends delete the old tx snapshot and restore the committed record.
        self.binding["tx"], self.binding["failed"] = False, False
        discard_snapshot()
        restore()

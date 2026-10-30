"""Validation for proxy-authored private request metadata."""
from datetime import datetime
from uuid import UUID


def metadata(body):
    identity = body.get("query_execution_id")
    started = body.get("request_started_at")
    if not identity and not started:
        return {}
    if not isinstance(identity, str) or len(identity) != 36 or str(UUID(identity)) != identity:
        raise ValueError("Invalid query execution ID")
    if not isinstance(started, str) or len(started) > 40 or datetime.fromisoformat(started.replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("Invalid request start")
    return {"query_execution_id": identity, "request_started_at": started}

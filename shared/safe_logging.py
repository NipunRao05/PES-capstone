
"""JSON operational logs with secret-safe formatting; raw evidence stays in its pipeline."""
import json
import logging
import math
import os
import re
from datetime import datetime, timezone

SECRET_KEY = re.compile(r"password|passwd|pwd|secret|token|api[_-]?key|credential|verifier|scram|(?:^|_)key|salt", re.I)
ASSIGNMENT = re.compile(r"""(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\b["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)""")
SQL = re.compile(r"(?is)\b(select|insert\s+into|update\s+\S+\s+set|delete\s+from|create\s+(?:user|role)|alter\s+(?:user|role)|identified\s+by)\b")
VERIFIER = re.compile(r"(?i)SCRAM-SHA-256\$\S+")
SECRETS = tuple(value for key, value in os.environ.items() if SECRET_KEY.search(key) and len(value) >= 4)


def redact(value):
    text = str(value)
    for secret in SECRETS:
        text = text.replace(secret, "[REDACTED]")
    if SQL.search(text):
        return "[SQL-bearing operational message omitted; inspect sanitized evidence]"
    text = VERIFIER.sub("[REDACTED]", text)
    text = ASSIGNMENT.sub(lambda match: match[1] + "=[REDACTED]", text)
    return text[:2048]


class Formatter(logging.Formatter):
    def format(self, record):
        result = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "service": os.getenv("HONEYPOT_SERVICE", "python-service"),
            "component": record.name,
            "event": "service_log",
            "message": redact(record.getMessage()),
        }
        if record.exc_info:
            # Exception messages/tracebacks may contain SQL, credentials and payloads.
            result["error_category"] = record.exc_info[0].__name__
        for key in ("event", "protocol", "authority", "success", "latency_ms", "error_category"):
            if hasattr(record, key):
                value = getattr(record, key)
                if key == "success" and type(value) is bool:
                    result[key] = value
                elif key == "latency_ms" and type(value) in (int, float) and math.isfinite(value) and value >= 0:
                    result[key] = value
                else:
                    result[key] = redact(value)
        return json.dumps(result, ensure_ascii=True)


def install():
    handler = logging.StreamHandler()
    handler.setFormatter(Formatter())
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), handlers=[handler], force=True)
    # Uvicorn's access log includes attacker-controlled paths. Emit service logs
    # through the safe root handler and suppress raw HTTP access lines.
    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True

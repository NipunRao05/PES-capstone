"""Bounded read-only client for existing internal evidence services."""

from __future__ import annotations

import json
import math
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

_SESSION_HOSTS = {"127.0.0.1", "localhost", "session-module", "host.docker.internal"}
_REGISTRY_HOSTS = {"127.0.0.1", "localhost", "deception-engine", "host.docker.internal"}
_SESSION_PORT = 8003
_REGISTRY_PORT = 8001
_MAX_RESPONSE_BYTES = 4_000_000
_SESSION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SafeInternalEvidenceClient:
    """GET only from fixed internal/loopback hosts and ports."""

    def __init__(
        self,
        session_base_url: str = "http://session-module:8003",
        registry_base_url: str = "http://deception-engine:8001",
        timeout_seconds: float = 2.0,
    ):
        self.session_base_url = self._validate_base(
            session_base_url, _SESSION_HOSTS, _SESSION_PORT, "session"
        )
        self.registry_base_url = self._validate_base(
            registry_base_url, _REGISTRY_HOSTS, _REGISTRY_PORT, "registry"
        )
        if isinstance(timeout_seconds, bool):
            raise ValueError("timeout must be numeric")
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout must be numeric") from exc
        if not math.isfinite(timeout):
            raise ValueError("timeout must be finite")
        self.timeout_seconds = min(max(timeout, 0.1), 10.0)
        self._opener = build_opener(_NoRedirect())

    @staticmethod
    def _validate_base(url: str, hosts: set[str], port: int, label: str) -> str:
        parsed = urlparse(str(url or "").strip())
        if (
            parsed.scheme != "http"
            or parsed.hostname not in hosts
            or parsed.port != port
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError(f"{label} URL must be an approved internal HTTP endpoint")
        return f"http://{parsed.hostname}:{port}"

    def _get(self, url: str) -> dict:
        request = Request(url, method="GET", headers={"Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise ValueError("internal evidence request failed")
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise ValueError("internal evidence was unavailable") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ValueError("internal evidence response exceeds the size limit")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("internal evidence response is invalid") from exc
        if not isinstance(payload, dict):
            raise ValueError("internal evidence response must be an object")
        return payload

    def load_session(self, session_id: str) -> tuple[dict, dict, dict]:
        session_id = str(session_id or "").strip()
        if not _SESSION_ID.fullmatch(session_id):
            raise ValueError("session_id contains unsupported characters")
        encoded = quote(session_id, safe="")
        telemetry = self._get(f"{self.session_base_url}/telemetry/session/{encoded}")
        reward = self._get(f"{self.session_base_url}/reward/session/{encoded}")
        registry = self._get(f"{self.registry_base_url}/strategies")
        return telemetry, reward, registry

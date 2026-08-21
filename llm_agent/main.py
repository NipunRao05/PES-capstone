from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict


MODE = os.getenv("LLM_AGENT_MODE", "deterministic_local")
EVIDENCE_STORE_URL = os.getenv("EVIDENCE_STORE_URL", "http://evidence-store:8011").rstrip("/")
SANDBOX_REPLAY_URL = os.getenv("SANDBOX_REPLAY_URL", "http://sandbox-replay-engine:8012").rstrip("/")
REQUEST_TIMEOUT_SECONDS = min(max(float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", "3")), 0.25), 10.0)
MAX_RESPONSE_BYTES = min(max(int(os.getenv("LLM_MAX_RESPONSE_BYTES", "1048576")), 65536), 4 * 1024 * 1024)
MAX_REPORTS = min(max(int(os.getenv("LLM_MAX_REPORTS", "500")), 10), 5000)
MAX_TIMELINE_EVENTS = min(max(int(os.getenv("LLM_MAX_TIMELINE_EVENTS", "50")), 10), 200)
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_sandbox: bool = True


class BoundedReportStore:
    def __init__(self, max_reports: int) -> None:
        self.max_reports = max_reports
        self._reports: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, report: dict[str, Any]) -> None:
        report_id = str(report["report_id"])
        with self._lock:
            self._reports[report_id] = report
            self._reports.move_to_end(report_id)
            while len(self._reports) > self.max_reports:
                self._reports.popitem(last=False)

    def get(self, report_id: str) -> dict[str, Any] | None:
        with self._lock:
            report = self._reports.get(report_id)
            if report is not None:
                self._reports.move_to_end(report_id)
            return report


reports = BoundedReportStore(MAX_REPORTS)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bounded_text(value: Any, limit: int = 2048) -> str:
    text = str(value or "").replace("\x00", "")
    return text[:limit]


def safe_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def fetch_json(url: str) -> dict[str, Any]:
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS, stream=True)
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail=f"internal evidence dependency unavailable: {type(exc).__name__}") from exc

    if response.status_code == 404:
        raise HTTPException(status_code=404, detail="session evidence not found")
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail=f"internal evidence dependency returned HTTP {response.status_code}")

    content_length = int(response.headers.get("content-length", "0") or 0)
    if content_length > MAX_RESPONSE_BYTES:
        raise HTTPException(status_code=502, detail="internal evidence response exceeded size limit")
    payload = response.content
    if len(payload) > MAX_RESPONSE_BYTES:
        raise HTTPException(status_code=502, detail="internal evidence response exceeded size limit")
    try:
        value = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="internal evidence dependency returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=502, detail="internal evidence dependency returned a non-object response")
    return value


def link_report(report: dict[str, Any]) -> dict[str, Any]:
    """Persist only bounded report metadata so the evidence trace is end-to-end."""
    payload = {
        "report_id": report["report_id"],
        "session_id": report["session_id"],
        "generated_at": report["generated_at"],
        "risk_level": report["risk_level"],
        "summary": str(report["executive_summary"])[:4096],
    }
    try:
        response = requests.post(
            f"{EVIDENCE_STORE_URL}/evidence/report",
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        result = response.json()
        return {
            "linked": True,
            "stored_new": bool(result.get("stored", False)),
            "destination": "evidence-store",
        }
    except (requests.RequestException, ValueError, TypeError):
        return {"linked": False, "stored_new": False, "destination": "evidence-store", "reason": "link unavailable"}


def evidence_snapshot_hash(evidence: dict[str, Any], sandbox: dict[str, Any] | None) -> str:
    snapshot = {"evidence": evidence, "sandbox": sandbox or {}}
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def prepare_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Remove self-referential report links before deterministic report generation."""
    prepared = json.loads(json.dumps(evidence, default=str))
    prepared.pop("ai_report_id", None)
    prepared.pop("ai_reports", None)
    prepared.pop("last_seen", None)
    prepared.pop("timestamp", None)
    trace = prepared.get("trace") if isinstance(prepared.get("trace"), dict) else {}
    trace["ai_report"] = True
    trace["complete"] = all(bool(trace.get(stage)) for stage in ("connection", "query", "mitre", "scaling"))
    prepared["trace"] = trace
    return prepared


def citation(citation_id: str, source: str, path: str, value: Any) -> dict[str, Any]:
    return {
        "citation_id": citation_id,
        "source": source,
        "path": path,
        "value": value,
    }


def build_timeline(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for item in evidence.get("connection_events", [])[:MAX_TIMELINE_EVENTS]:
        events.append({
            "timestamp": bounded_text(item.get("timestamp"), 128),
            "stage": "connection",
            "event": bounded_text(item.get("event_type"), 64),
            "evidence_id": bounded_text(item.get("event_id"), 128),
        })
    for item in evidence.get("queries", [])[:MAX_TIMELINE_EVENTS]:
        events.append({
            "timestamp": bounded_text(item.get("timestamp"), 128),
            "stage": "query",
            "event": bounded_text(item.get("query_normalized"), 1024),
            "evidence_id": bounded_text(item.get("event_id"), 128),
        })
    for item in evidence.get("mitre_events", [])[:MAX_TIMELINE_EVENTS]:
        techniques = [
            bounded_text(match.get("technique_id"), 64)
            for match in item.get("techniques_matched", [])
            if isinstance(match, dict)
        ]
        events.append({
            "timestamp": bounded_text(item.get("timestamp"), 128),
            "stage": "mitre",
            "event": ", ".join(filter(None, techniques)) or bounded_text(item.get("technique_id"), 64),
            "evidence_id": bounded_text(item.get("event_id"), 128),
        })
    for item in evidence.get("scaling_events", [])[:MAX_TIMELINE_EVENTS]:
        events.append({
            "timestamp": bounded_text(item.get("timestamp"), 128),
            "stage": "scaling",
            "event": f"replica_target={int(safe_number(item.get('replica_target'), 1))}; {bounded_text(item.get('reason'), 512)}",
            "evidence_id": bounded_text(item.get("scale_event_id"), 128),
        })
    events.sort(key=lambda item: item["timestamp"])
    return events[:MAX_TIMELINE_EVENTS]


def sandbox_for_session(session_id: str, sandbox: dict[str, Any] | None) -> dict[str, Any]:
    if not sandbox or sandbox.get("available") is not True:
        return {"available": False, "reason": "no sandbox hardening report is available"}
    if bounded_text(sandbox.get("session_id"), 256) != session_id:
        return {"available": False, "reason": "latest sandbox hardening report belongs to another session"}
    verification = sandbox.get("verification") or {}
    return {
        "available": True,
        "hardening_report_id": bounded_text(sandbox.get("hardening_report_id"), 128),
        "status": bounded_text(sandbox.get("status"), 64),
        "recommendation_count": int(safe_number(sandbox.get("recommendation_count"))),
        "verified_count": int(safe_number(verification.get("verified_count"))),
        "before": sandbox.get("before") or {},
        "after": verification.get("after") or {},
        "recommendations": [
            {
                "issue": bounded_text(item.get("issue"), 512),
                "severity": bounded_text(item.get("severity"), 32),
                "affected_object": bounded_text(item.get("affected_object"), 256),
                "recommended_fix": bounded_text(item.get("recommended_fix"), 1024),
                "verification_step": bounded_text(item.get("verification_step"), 1024),
            }
            for item in (sandbox.get("recommendations") or [])[:20]
            if isinstance(item, dict)
        ],
    }


def build_report(evidence: dict[str, Any], sandbox: dict[str, Any] | None = None) -> dict[str, Any]:
    evidence = prepare_evidence(evidence)
    session_id = bounded_text(evidence.get("session_id"), 256)
    if not SESSION_ID_RE.fullmatch(session_id):
        raise HTTPException(status_code=422, detail="evidence contains an invalid session_id")

    trap_triggered = bool(evidence.get("trap_triggered"))
    risk_level = bounded_text(evidence.get("risk_level") or "unknown", 32).lower()
    risk_score = safe_number(evidence.get("risk_score"))
    techniques = [bounded_text(value, 64) for value in evidence.get("mitre_technique", [])[:20]]
    trace = evidence.get("trace") or {}
    query = bounded_text(evidence.get("query_normalized"), 1024)
    scaling_events = evidence.get("scaling_events") or []
    last_scale = scaling_events[-1] if scaling_events else {}
    sandbox_summary = sandbox_for_session(session_id, sandbox)

    citations = [
        citation("E1", "evidence-store", "/session_id", session_id),
        citation("E2", "evidence-store", "/risk_level", risk_level),
        citation("E3", "evidence-store", "/risk_score", risk_score),
        citation("E4", "evidence-store", "/trap_triggered", trap_triggered),
        citation("E5", "evidence-store", "/mitre_technique", techniques),
        citation("E6", "evidence-store", "/query_normalized", query),
        citation("E7", "evidence-store", "/trace/complete", bool(trace.get("complete"))),
        citation("E8", "evidence-store", "/scaling_events/-1/replica_target", int(safe_number(last_scale.get("replica_target"), 1))),
    ]
    if sandbox_summary.get("available"):
        citations.extend([
            citation("S1", "sandbox-replay", "/hardening/latest/status", sandbox_summary.get("status")),
            citation("S2", "sandbox-replay", "/hardening/latest/recommendation_count", sandbox_summary.get("recommendation_count")),
            citation("S3", "sandbox-replay", "/hardening/latest/verification/verified_count", sandbox_summary.get("verified_count")),
        ])

    if trap_triggered:
        executive_summary = (
            f"Session {session_id} triggered a database deception trap and was classified {risk_level.upper()} "
            f"by deterministic detection with risk score {risk_score:.1f}."
        )
    elif risk_level in {"high", "critical"}:
        executive_summary = (
            f"Session {session_id} was classified {risk_level.upper()} by deterministic detection; "
            "no trap-table flag is present in the stored evidence."
        )
    else:
        executive_summary = (
            f"Session {session_id} is currently classified {risk_level.upper()} by deterministic detection "
            "with no stored trap-table trigger."
        )

    findings = [
        {
            "claim": "The end-to-end evidence trace is complete." if trace.get("complete") else "The end-to-end evidence trace is incomplete.",
            "citations": ["E7"],
        },
        {
            "claim": f"Stored MITRE techniques: {', '.join(techniques) if techniques else 'none'}.",
            "citations": ["E5"],
        },
        {
            "claim": f"Latest logical replica target: {int(safe_number(last_scale.get('replica_target'), 1))}.",
            "citations": ["E8"],
        },
    ]
    if query:
        findings.append({"claim": f"Normalized captured query: {query}", "citations": ["E6"]})
    if sandbox_summary.get("available"):
        findings.append({
            "claim": (
                f"Sandbox hardening status is {sandbox_summary['status']} with "
                f"{sandbox_summary['verified_count']} verified recommendation(s)."
            ),
            "citations": ["S1", "S2", "S3"],
        })

    actions = [
        "Preserve the correlated session, MITRE, scaling, and report evidence for operator review.",
        "Keep all replay and hardening verification restricted to the disposable sandbox databases.",
    ]
    if trap_triggered:
        actions.append("Review the trap-table access path and the exposed decoy role; do not contact or scan the source.")
    if not trace.get("complete"):
        actions.append("Resolve missing evidence stages before using this session in research conclusions.")
    for recommendation in sandbox_summary.get("recommendations", []):
        actions.append(recommendation["recommended_fix"])
    actions = list(dict.fromkeys(action for action in actions if action))[:20]

    snapshot_hash = evidence_snapshot_hash(evidence, sandbox if sandbox_summary.get("available") else None)
    report_id = f"llm-local-{snapshot_hash[:24]}"
    report = {
        "report_id": report_id,
        "session_id": session_id,
        "mode": MODE,
        "generated_at": utc_now(),
        "evidence_snapshot_sha256": snapshot_hash,
        "decision_authority": "none; risk and scaling facts are copied from deterministic modules",
        "risk_level": risk_level,
        "executive_summary": executive_summary,
        "findings": findings,
        "timeline": build_timeline(evidence),
        "sandbox_assessment": sandbox_summary,
        "recommended_actions": actions,
        "citations": citations,
        "safety": {
            "real_database_access": False,
            "scaling_control": False,
            "attacker_contact": False,
            "outbound_internet": False,
            "free_form_tool_use": False,
            "structured_internal_evidence_only": True,
        },
    }
    return report


app = FastAPI(title="Capstone Bounded Evidence Report Agent", version="2.0.0")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "mode": MODE, "timestamp": utc_now()}


@app.get("/readyz")
def readyz() -> dict[str, Any]:
    evidence = fetch_json(f"{EVIDENCE_STORE_URL}/readyz")
    try:
        sandbox = fetch_json(f"{SANDBOX_REPLAY_URL}/readyz")
        sandbox_ready = sandbox.get("ready") is True
    except HTTPException:
        sandbox_ready = False
    evidence_ready = evidence.get("ready") is True
    return {
        "ready": evidence_ready,
        "mode": MODE,
        "dependencies": {
            "evidence_store": "ok" if evidence_ready else "unavailable",
            "sandbox_replay": "ok" if sandbox_ready else "optional_unavailable",
        },
        "safety": {
            "structured_internal_evidence_only": True,
            "scaling_control": False,
            "database_connections": False,
            "outbound_internet": False,
        },
    }


@app.post("/llm/report/session/{session_id}")
def report_session(session_id: str, request: ReportRequest) -> dict[str, Any]:
    if not SESSION_ID_RE.fullmatch(session_id):
        raise HTTPException(status_code=422, detail="invalid session_id")
    evidence = fetch_json(f"{EVIDENCE_STORE_URL}/evidence/session/{session_id}")
    sandbox: dict[str, Any] | None = None
    if request.include_sandbox:
        try:
            sandbox = fetch_json(f"{SANDBOX_REPLAY_URL}/hardening/latest")
        except HTTPException as exc:
            if exc.status_code != 404:
                sandbox = None
    report = build_report(evidence, sandbox)
    report["evidence_link"] = link_report(report)
    reports.put(report)
    return report


@app.get("/llm/report/{report_id}")
def get_report(report_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"llm-local-[a-f0-9]{24}", report_id):
        raise HTTPException(status_code=422, detail="invalid report_id")
    report = reports.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found in bounded local store")
    return report

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, Response
from pydantic import BaseModel


SCALING_AGENT_URL = os.getenv("SCALING_AGENT_URL", "http://scaling-agent:8080")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
METRICS_BRIDGE_URL = os.getenv("METRICS_BRIDGE_URL", "http://metrics-bridge:9100")
EVIDENCE_STORE_URL = os.getenv("EVIDENCE_STORE_URL", "http://evidence-store:8011")
POLL_TIMEOUT_SECONDS = float(os.getenv("POLL_TIMEOUT_SECONDS", "2"))


app = FastAPI(title="Capstone AI Agent", version="0.1.0")


class AgentStatus(BaseModel):
    status: str
    timestamp: str
    scaling_agent_url: str
    prometheus_url: str
    metrics_bridge_url: str
    evidence_store_url: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_json(url: str, default: Any) -> Any:
    try:
        response = requests.get(url, timeout=POLL_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        return {
            "error": str(exc),
            "source": url,
            "fallback": default,
        }


def post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        response = requests.post(url, json=payload, timeout=POLL_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        return {"stored": False, "error": str(exc), "source": url}


def prometheus_query(query: str) -> Dict[str, Any]:
    try:
        response = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=POLL_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        result = data.get("data", {}).get("result", [])
        if not result:
            return {"query": query, "value": None, "status": data.get("status")}
        value = result[0].get("value", [None, None])[1]
        return {"query": query, "value": value, "status": data.get("status")}
    except Exception as exc:
        return {"query": query, "value": None, "error": str(exc)}


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def extract_recent_scale_events(events_payload: Any, limit: int = 50) -> List[Dict[str, Any]]:
    if not isinstance(events_payload, dict):
        return []

    events = events_payload.get("events", [])
    if not isinstance(events, list):
        return []

    return events[-limit:]


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None

    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp
    except ValueError:
        return None


def analyze_recent_events(
    events: List[Dict[str, Any]],
    window: timedelta = timedelta(minutes=10),
) -> Dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - window
    recent_events: List[Dict[str, Any]] = []

    for event in events:
        timestamp = parse_timestamp(event.get("timestamp"))
        if timestamp is not None and timestamp >= cutoff:
            recent_events.append(event)

    high_events = [
        event
        for event in recent_events
        if max(
            to_float(event.get("raw_score")),
            to_float(event.get("smoothed_score")),
        )
        >= 0.6
    ]
    attacker_high_events = [
        event
        for event in high_events
        if event.get("session_id")
        and not str(event["session_id"]).startswith("metric-pressure-")
    ]

    return {
        "window_seconds": int(window.total_seconds()),
        "recent_event_count": len(recent_events),
        "recent_high_event_count": len(high_events),
        "attacker_high_event_count": len(attacker_high_events),
        "elevated_posture_event_count": len(high_events),
        "latest_high_event": attacker_high_events[-1] if attacker_high_events else None,
    }


def classify_pressure(
    pressure: float,
    trap_triggers: float,
    avg_actor_risk: float,
    recent_event_risk: Dict[str, Any],
) -> Dict[str, str]:
    latest_high_event = recent_event_risk.get("latest_high_event")

    if pressure >= 0.8 or avg_actor_risk >= 80:
        return {
            "risk_level": "critical",
            "summary": "High-confidence hostile or high-load behavior is present. Deception capacity should remain elevated.",
        }

    if latest_high_event:
        session_id = latest_high_event.get("session_id", "unknown")
        return {
            "risk_level": "high",
            "summary": f"Recent high-risk attacker activity was attributed to session {session_id}.",
        }

    if pressure >= 0.6 or trap_triggers > 0:
        return {
            "risk_level": "high",
            "summary": "Scaling pressure or trap-trigger evidence indicates elevated adversary activity.",
        }

    if pressure >= 0.3 or avg_actor_risk >= 40:
        return {
            "risk_level": "medium",
            "summary": "Moderate activity is present. Continue monitoring and preserve telemetry.",
        }

    return {
        "risk_level": "low",
        "summary": "Current telemetry does not show active scaling pressure.",
    }


def build_recommendations(risk_level: str, pressure: float, current_replicas: float) -> List[str]:
    if risk_level in {"critical", "high"}:
        return [
            "Keep deception services available and avoid resetting telemetry.",
            "Preserve MITRE events, session profiles, and scaling events for review evidence.",
            "Monitor whether scaling pressure remains above threshold.",
            "Check recent trap-triggered sessions and source fingerprints.",
        ]

    if risk_level == "medium":
        return [
            "Continue monitoring scaling pressure and MITRE session progression.",
            "Check whether repeated enumeration or trap-table access appears.",
            "Do not scale down manually until pressure remains low.",
        ]

    return [
        "Maintain baseline replica count.",
        "Continue passive monitoring.",
        "No immediate response action is required.",
    ]


def build_brief() -> Dict[str, Any]:
    scaling_metrics = get_json(f"{SCALING_AGENT_URL}/metrics", {})
    scaling_events = get_json(f"{SCALING_AGENT_URL}/scale/events", {"events": []})

    pressure_query = prometheus_query("capstone_scaling_scale_pressure")
    replicas_query = prometheus_query("capstone_scaling_current_replicas")
    trap_query = prometheus_query("capstone_mitre_trap_triggers_total")
    actor_risk_query = prometheus_query("capstone_mitre_avg_actor_risk")

    pressure = to_float(pressure_query.get("value"), to_float(scaling_metrics.get("scale_pressure", 0)))
    current_replicas = to_float(replicas_query.get("value"), to_float(scaling_metrics.get("current_replicas", 1)))
    prometheus_trap_triggers = to_float(trap_query.get("value"))
    scaling_agent_trap_triggers = to_float(scaling_metrics.get("trap_triggers", 0))
    trap_triggers = max(prometheus_trap_triggers, scaling_agent_trap_triggers)
    avg_actor_risk = to_float(actor_risk_query.get("value"), 0)

    attribution_events = extract_recent_scale_events(scaling_events)
    recent_event_risk = analyze_recent_events(attribution_events)
    recent_events = attribution_events[-5:]
    classification = classify_pressure(
        pressure,
        trap_triggers,
        avg_actor_risk,
        recent_event_risk,
    )
    recommendations = build_recommendations(
        classification["risk_level"],
        pressure,
        current_replicas,
    )

    report_id = str(uuid.uuid4())
    brief = {
        "report_id": report_id,
        "agent": "capstone-ai-agent",
        "generated_at": now_iso(),
        "risk_level": classification["risk_level"],
        "summary": classification["summary"],
        "scaling_interpretation": {
            "scale_pressure": pressure,
            "current_replicas": current_replicas,
            "trap_triggers": trap_triggers,
            "prometheus_trap_triggers": prometheus_trap_triggers,
            "scaling_agent_trap_triggers": scaling_agent_trap_triggers,
            "avg_actor_risk": avg_actor_risk,
            "decision": (
                "scale-up pressure present"
                if pressure >= 0.6
                else "hold or baseline pressure"
            ),
        },
        "evidence": {
            "prometheus": {
                "capstone_scaling_scale_pressure": pressure_query,
                "capstone_scaling_current_replicas": replicas_query,
                "capstone_mitre_trap_triggers_total": trap_query,
                "capstone_mitre_avg_actor_risk": actor_risk_query,
            },
            "scaling_agent_metrics": scaling_metrics,
            "recent_scale_events": recent_events,
            "recent_event_risk": recent_event_risk,
        },
        "recommended_response": recommendations,
    }

    latest_high_event = recent_event_risk.get("latest_high_event") or {}
    attacker_session_id = latest_high_event.get("session_id")
    if attacker_session_id:
        evidence_link = post_json(
            f"{EVIDENCE_STORE_URL}/evidence/report",
            {
                "report_id": report_id,
                "session_id": attacker_session_id,
                "generated_at": brief["generated_at"],
                "risk_level": brief["risk_level"],
                "summary": brief["summary"],
            },
        )
    else:
        evidence_link = {
            "stored": False,
            "reason": "no recent attacker session available for correlation",
        }
    brief["evidence"]["evidence_store_link"] = evidence_link
    return brief


def brief_to_markdown(brief: Dict[str, Any]) -> str:
    interp = brief["scaling_interpretation"]

    lines = [
        "# Capstone AI Agent Brief",
        "",
        f"Report ID: `{brief['report_id']}`",
        f"Generated: {brief['generated_at']}",
        f"Risk level: **{brief['risk_level'].upper()}**",
        "",
        "## Summary",
        "",
        brief["summary"],
        "",
        "## Scaling Interpretation",
        "",
        f"- Scale pressure: `{interp['scale_pressure']}`",
        f"- Current replicas: `{interp['current_replicas']}`",
        f"- Trap triggers: `{interp['trap_triggers']}`",
        f"- Prometheus trap triggers: `{interp['prometheus_trap_triggers']}`",
        f"- Scaling-agent trap triggers: `{interp['scaling_agent_trap_triggers']}`",
        f"- Average actor risk: `{interp['avg_actor_risk']}`",
        f"- Decision: `{interp['decision']}`",
        "",
        "## Recommended Response",
        "",
    ]

    for item in brief["recommended_response"]:
        lines.append(f"- {item}")

    lines.extend(["", "## Recent Scale Events", ""])

    recent_events = brief["evidence"].get("recent_scale_events", [])
    if not recent_events:
        lines.append("- No recent scale events available.")
    else:
        for event in recent_events:
            session_id = event.get("session_id", "unknown")
            reason = event.get("reason", "no reason")
            target = event.get("replica_target", "unknown")
            lines.append(f"- `{session_id}` -> target `{target}`: {reason}")

    return "\n".join(lines) + "\n"


@app.get("/healthz", response_model=AgentStatus)
def healthz() -> AgentStatus:
    return AgentStatus(
        status="ok",
        timestamp=now_iso(),
        scaling_agent_url=SCALING_AGENT_URL,
        prometheus_url=PROMETHEUS_URL,
        metrics_bridge_url=METRICS_BRIDGE_URL,
        evidence_store_url=EVIDENCE_STORE_URL,
    )


@app.get("/readyz")
def readyz() -> Dict[str, Any]:
    scaling = get_json(f"{SCALING_AGENT_URL}/metrics", {})
    prometheus = prometheus_query("up")
    evidence_store = get_json(f"{EVIDENCE_STORE_URL}/readyz", {})

    evidence_ready = "error" not in evidence_store and evidence_store.get("ready") is True
    ready = "error" not in scaling and "error" not in prometheus and evidence_ready

    return {
        "ready": ready,
        "timestamp": now_iso(),
        "dependencies": {
            "scaling_agent": "ok" if "error" not in scaling else scaling,
            "prometheus": "ok" if "error" not in prometheus else prometheus,
            "evidence_store": "ok" if evidence_ready else evidence_store,
        },
    }


@app.get("/brief/latest")
def latest_brief() -> Dict[str, Any]:
    return build_brief()


@app.get("/brief/markdown")
def latest_brief_markdown() -> Response:
    return Response(
        content=brief_to_markdown(build_brief()),
        media_type="text/markdown; charset=utf-8",
    )

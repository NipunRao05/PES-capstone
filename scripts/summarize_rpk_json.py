#!/usr/bin/env python3
"""Summarize Redpanda `rpk topic consume` JSON output.

`rpk topic consume` emits one JSON envelope per message, where the actual
application event is usually a JSON string inside the `value` field. This helper
turns those nested records into compact demo-friendly lines.

Examples:
  docker compose exec redpanda rpk topic consume mitre-events --num 5 --offset start \
    | python scripts/summarize_rpk_json.py

  python scripts/summarize_rpk_json.py saved_rpk_output.txt
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable


def _iter_json_objects(text: str) -> Iterable[dict]:
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            # Skip noise such as shell prompts or warning lines until the next
            # plausible JSON object.
            nxt = text.find("{", idx + 1)
            if nxt < 0:
                break
            idx = nxt
            continue
        if isinstance(obj, dict):
            yield obj
        idx = end


def _decode_value(envelope: dict) -> dict:
    value = envelope.get("value", {})
    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else {"value": decoded}
        except json.JSONDecodeError:
            return {"value": value}
    return {"value": value}


def _summarize(envelope: dict) -> str:
    topic = envelope.get("topic", "?")
    offset = envelope.get("offset", "?")
    event = _decode_value(envelope)
    session_id = str(event.get("session_id") or envelope.get("key") or "")
    sid = session_id[:8] if session_id else "-"

    if topic == "mitre-events":
        return (
            f"{topic}@{offset} session={sid} technique={event.get('technique_id','-')} "
            f"rule={event.get('rule_id','-')} risk={event.get('risk_score','-')} "
            f"level={event.get('risk_level','-')} phase={event.get('phase','-')} "
            f"proto={event.get('protocol','-')} db={event.get('database','-')}"
        )
    if topic == "mitre-sessions":
        techniques = event.get("techniques_matched") or []
        if isinstance(techniques, list):
            ids = []
            for t in techniques:
                if isinstance(t, dict):
                    ids.append(str(t.get("technique_id", "?")))
                else:
                    ids.append(str(t))
            technique_ids = ",".join(ids)
        else:
            technique_ids = str(techniques)
        return (
            f"{topic}@{offset} session={sid} risk={event.get('final_risk_score','-')} "
            f"level={event.get('risk_level','-')} persona={event.get('persona','-')} "
            f"techniques=[{technique_ids}] proto={event.get('protocol','-')} db={event.get('database','-')}"
        )
    if topic == "session-profiles":
        return (
            f"{topic}@{offset} session={sid} user={event.get('db_user','-')} "
            f"failed_auth={event.get('failed_auth','-')} queries={event.get('query_count','-')} "
            f"persona={event.get('persona','-')} proto={event.get('protocol','-')} db={event.get('database','-')}"
        )
    if topic.endswith("query-events"):
        query = str(event.get("query_normalized") or event.get("query_raw") or "")
        if len(query) > 80:
            query = query[:77] + "..."
        return (
            f"{topic}@{offset} session={sid} type={event.get('event_type','-')} "
            f"user={event.get('username','-')} query={query!r}"
        )
    return f"{topic}@{offset} session={sid} keys={','.join(sorted(event.keys())[:8])}"


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] not in {"-", "--"}:
        text = Path(argv[1]).read_text(encoding="utf-8", errors="replace")
    else:
        text = sys.stdin.read()
    count = 0
    for envelope in _iter_json_objects(text):
        print(_summarize(envelope))
        count += 1
    if count == 0:
        print("No rpk JSON envelopes found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

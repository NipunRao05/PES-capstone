#!/usr/bin/env python3
"""Assert that `rpk topic consume` output contains expected milestone evidence.

The input format is the JSON envelope emitted by `rpk topic consume`. The actual
application event is usually a JSON string inside the envelope's `value` field.

Examples:
  docker compose exec -T redpanda rpk topic consume mitre-events --num 50 --offset start \
    | python scripts/assert_rpk_milestone.py --technique T1110.001

  docker compose exec -T redpanda rpk topic consume mitre-sessions --num 50 --offset start \
    | python scripts/assert_rpk_milestone.py --technique T1213.006 --topic mitre-sessions
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator


def iter_json_objects(text: str) -> Iterator[dict]:
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
            nxt = text.find("{", idx + 1)
            if nxt < 0:
                break
            idx = nxt
            continue
        if isinstance(obj, dict):
            yield obj
        idx = end


def decode_value(envelope: dict) -> dict:
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


def iter_techniques(event: dict) -> Iterable[str]:
    direct = event.get("technique_id")
    if direct:
        yield str(direct)

    techniques = event.get("techniques_matched") or []
    if isinstance(techniques, list):
        for item in techniques:
            if isinstance(item, dict):
                tid = item.get("technique_id") or item.get("id")
                if tid:
                    yield str(tid)
            elif item:
                yield str(item)
    elif techniques:
        yield str(techniques)

    graph = event.get("attack_graph") or {}
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, dict):
                tid = node.get("technique_id") or node.get("id")
                if tid:
                    yield str(tid)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="Optional file containing rpk consume output. Defaults to stdin.")
    parser.add_argument("--topic", action="append", default=[], help="Topic name to count. May be repeated.")
    parser.add_argument("--technique", action="append", default=[], help="Required MITRE technique ID. May be repeated.")
    parser.add_argument("--min-count", type=int, default=1, help="Minimum count required for each requested topic/technique.")
    parser.add_argument("--print-matches", action="store_true", help="Print matching offsets and session IDs.")
    args = parser.parse_args(argv[1:])

    if not args.topic and not args.technique:
        parser.error("provide at least one --topic or --technique")

    text = Path(args.path).read_text(encoding="utf-8", errors="replace") if args.path else sys.stdin.read()
    topic_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    matches: list[str] = []

    envelope_count = 0
    for envelope in iter_json_objects(text):
        envelope_count += 1
        topic = str(envelope.get("topic", ""))
        topic_counts[topic] += 1
        event = decode_value(envelope)
        session_id = str(event.get("session_id") or envelope.get("key") or "")
        offset = envelope.get("offset", "?")
        for technique in set(iter_techniques(event)):
            technique_counts[technique] += 1
            if args.print_matches and technique in set(args.technique):
                matches.append(f"{topic}@{offset} session={session_id[:8] or '-'} technique={technique}")

    failures: list[str] = []
    for topic in args.topic:
        count = topic_counts.get(topic, 0)
        if count < args.min_count:
            failures.append(f"topic {topic!r} count {count} < {args.min_count}")
        else:
            print(f"[OK] topic {topic}: {count}")

    for technique in args.technique:
        count = technique_counts.get(technique, 0)
        if count < args.min_count:
            failures.append(f"technique {technique} count {count} < {args.min_count}")
        else:
            print(f"[OK] technique {technique}: {count}")

    if args.print_matches:
        for line in matches:
            print(line)

    if failures:
        print(f"[FAIL] processed {envelope_count} rpk envelopes", file=sys.stderr)
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        return 1

    print(f"[OK] processed {envelope_count} rpk envelopes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

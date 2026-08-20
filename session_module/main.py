"""
Local simulation runner for the session engine.

Production entry point is redpanda_consumer.py. This file is intentionally
broker-free so developers can sanity-check feature extraction without Redpanda,
SQLite, or Docker.
"""

from __future__ import annotations

import dataclasses
import json
import queue
import threading
import time

from models import Event
from session_engine import SessionEngine
from persona_mapper import map_sparse_session_to_persona
import config


class PrintSessionStore:
    """Minimal storage adapter used only by this local simulation."""

    def save_session(self, session_output) -> None:
        payload = dataclasses.asdict(session_output)
        features = [
            payload.get("entropy", 0.0),
            payload.get("failed_auth", 0),
            payload.get("depth_score", 0.0),
            payload.get("query_count", 0),
            payload.get("duration", 0.0),
            payload.get("timing_variance_ms", 0.0),
            payload.get("queries_per_second", 0.0),
        ]
        payload["cluster_id"] = -1
        payload["persona"] = map_sparse_session_to_persona(features)
        print(json.dumps(payload, indent=2, sort_keys=True))

    def close(self) -> None:
        pass


event_queue: queue.Queue[Event | None] = queue.Queue(maxsize=config.EVENT_QUEUE_MAX_SIZE)


def event_consumer(engine: SessionEngine) -> None:
    while True:
        event = event_queue.get()
        try:
            if event is None:
                return
            engine.process_event(event)
        finally:
            event_queue.task_done()


def put_event(source_ip: str, db_user: str, query: str, event_type: str = "query", *, session_id: str, protocol: str) -> None:
    event_queue.put(Event(
        timestamp=time.time(),
        source_ip=source_ip,
        db_user=db_user,
        query_fingerprint=query,
        event_type=event_type,
        session_id=session_id,
        protocol=protocol,
        database="testdb",
    ))


def generate_test_events() -> None:
    scenarios = [
        (
            "mysql-normal-1", "10.0.0.10", "app_user", "mysql",
            ["select * from products", "select * from cart where user_id=?", "select * from products where id=?"],
            12,
        ),
        (
            "pg-suspicious-1", "10.0.0.20", "admin", "postgres",
            ["select * from pg_catalog.pg_tables", "select password from users", "select * from admin_logs"],
            18,
        ),
        (
            "mysql-attacker-1", "192.168.1.200", "root", "mysql",
            ["select @@version", "select load_file('/etc/passwd')", "union select username,password from users", "sleep(5)"],
            24,
        ),
    ]

    for session_id, source_ip, db_user, protocol, queries, count in scenarios:
        for i in range(count):
            put_event(source_ip, db_user, queries[i % len(queries)], session_id=session_id, protocol=protocol)
            time.sleep(0.02)

    for _ in range(3):
        put_event("192.168.1.201", "postgres", "", "auth_fail", session_id="pg-bruteforce-1", protocol="postgres")


if __name__ == "__main__":
    print("Running local session-engine simulation. Production uses redpanda_consumer.py.\n")

    engine = SessionEngine(PrintSessionStore())
    worker = threading.Thread(target=event_consumer, args=(engine,), daemon=True)
    worker.start()

    generate_test_events()
    event_queue.join()
    event_queue.put(None)
    event_queue.join()

    engine.flush_all()
    engine.shutdown()
    print("\nSimulation complete.")

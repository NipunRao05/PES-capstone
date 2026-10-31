from prometheus_client import Gauge

PENDING=Gauge("honeypot_trace_outbox_pending","Durable pending deliveries")
TERMINAL=Gauge("honeypot_trace_outbox_terminal","Retained terminal failures")
OLDEST=Gauge("honeypot_trace_outbox_oldest_pending_age_seconds","Oldest pending age, -1 if legacy index incomplete")
CAPACITY=Gauge("honeypot_trace_outbox_capacity","Retained-entry capacity")
MEMORY=Gauge("honeypot_deception_redis_used_memory_bytes","Redis allocator memory")
LOSS=Gauge("honeypot_trace_delivery_integrity_events","Persistent delivery diagnostics",("reason",))


def collect(outbox):
    stats=outbox.stats()
    PENDING.set(stats["pending"]);TERMINAL.set(stats["terminal"]);CAPACITY.set(stats["capacity"])
    OLDEST.set(stats["oldest_pending_age_seconds"] if stats["oldest_pending_age_seconds"] is not None else -1)
    MEMORY.set(outbox.client.info("memory")["used_memory"])
    for reason in ("full_total","terminal_total","expired_total"):
        LOSS.labels(reason).set(stats[reason])
    return stats

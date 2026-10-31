"""Bounded operational gauges. No query/session/principal labels."""
import time
from prometheus_client import Gauge
from research_journal import HEALTH

MEMORY=Gauge("honeypot_evidence_redis_used_memory_bytes","Redis allocator memory")
PERSISTENCE=Gauge("honeypot_evidence_redis_persistence_ok","AOF enabled and last background write/rewrite healthy")
ENTRIES=Gauge("honeypot_trace_index_entries","Retained index memberships",("kind",))
CAPACITY=Gauge("honeypot_trace_index_capacity","Configured per-kind capacity",("kind",))
REMAINING=Gauge("honeypot_trace_index_capacity_remaining","Remaining admission slots",("kind",))
UTIL=Gauge("honeypot_trace_index_utilization","Membership/capacity",("kind",))
JOURNAL=Gauge("honeypot_research_journal_entries","Retained immutable event journal")
JOURNAL_CAP=Gauge("honeypot_research_journal_capacity","Journal admission capacity")
JOURNAL_GAPS=Gauge("honeypot_research_journal_integrity_events","Journal admission/retention diagnostics",("reason",))
EXPORT=Gauge("honeypot_evidence_export_last_success_timestamp_seconds","Last acknowledged validated operator export")
EXPORT_AGE=Gauge("honeypot_evidence_export_age_seconds","Age of last export, -1 if never acknowledged")
GAPS=Gauge("honeypot_evidence_integrity_events","Persistent bounded integrity diagnostics",("reason",))


def collect(repository):
    from trace_index import CAPACITY as LIMIT
    r=repository.client
    MEMORY.set(r.info("memory")["used_memory"])
    p=r.info("persistence")
    PERSISTENCE.set(int(p.get("aof_enabled")==1 and p.get("aof_last_write_status")=="ok" and p.get("aof_last_bgrewrite_status")=="ok"))
    for kind in ("decision","application","outcome"):
        n=r.zcard("evidence:strategy_trace:index:v1:"+kind+":members")
        ENTRIES.labels(kind).set(n);CAPACITY.labels(kind).set(LIMIT)
        REMAINING.labels(kind).set(max(0,LIMIT-n));UTIL.labels(kind).set(n/LIMIT)
    status=repository.journal.status()
    JOURNAL.set(status["entries"]);JOURNAL_CAP.set(status["capacity"])
    for reason in ("capacity_rejections","expired_records"):
        JOURNAL_GAPS.labels(reason).set(float(status["metadata"].get(reason,0)))
    last=float(r.hget(HEALTH,"export_last_success") or 0)
    EXPORT.set(last);EXPORT_AGE.set(max(0,time.time()-last) if last else -1)
    for reason in ("projection_window_rollovers","malformed_source_events","trace_capacity_rejections"):
        GAPS.labels(reason).set(float(r.hget(HEALTH,reason) or 0))

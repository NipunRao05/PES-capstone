
"""Build the primary dashboard from enabled features and authoritative producers."""


def make_dashboard(flags, obs):
    panels = []
    y = 0
    current_category = ""
    current_feature = None

    def row(title, category, feature=None):
        nonlocal y, current_category, current_feature
        current_category, current_feature = category, feature
        if not obs["categories"].get(category, True) or (feature and not flags[feature]):
            return False
        panels.append({"id": len(panels)+1, "type": "row", "title": title, "collapsed": False,
                       "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []})
        y += 1
        return True

    def chart(title, targets, unit="short", kind="timeseries", description=""):
        nonlocal y
        position = sum(1 for p in panels if p.get("_row") == current_category) % 2
        if position == 0 and panels and panels[-1]["type"] != "row":
            y += 8
        panels.append({
            "id": len(panels)+1, "_row": current_category,
            "type": kind, "title": title, "description": description,
            "datasource": {"type": "prometheus", "uid": "prometheus"},
            "gridPos": {"h": 8, "w": 12, "x": position*12, "y": y},
            "fieldConfig": {"defaults": {"unit": unit, "min": 0}, "overrides": []},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"},
                        "tooltip": {"mode": "multi"}, "reduceOptions": {"calcs": ["lastNotNull"]}},
            "targets": [{"refId": chr(65+i), "expr": expr, "legendFormat": legend}
                        for i, (expr, legend) in enumerate(targets)],
        })

    def finish():
        nonlocal y
        y += 8

    if row("Runtime Mode & Platform Health", "platform"):
        chart("Configured mode: deterministic_rule_based", [('honeypot_runtime_info', '{{mode}}')], kind="stat",
              description="Configured mode only. Service and dependency health are shown separately.")
        chart("Enabled Service Scrape Health", [('up', '{{job}}'), ('capstone_bridge_scrape_success', '{{service}}')], kind="stat")
        chart("PostgreSQL & MySQL Backend Availability", [('capstone_pgproxy_backend_healthy','PostgreSQL'),('capstone_mysqlproxy_backend_healthy','MySQL')], kind="stat")
        chart("Redis & Evidence Consumer Connectivity", [('honeypot_dependency_up','{{service}} / {{dependency}}')], kind="stat")
        finish()
    if row("Live Database Activity", "traffic"):
        chart("Active PostgreSQL / MySQL Connections", [('capstone_pgproxy_active_connections','PostgreSQL'),('capstone_mysqlproxy_active_connections','MySQL')])
        chart("New Connections / sec", [('rate(capstone_pgproxy_total_connections[$__rate_interval])','PostgreSQL'),('rate(capstone_mysqlproxy_total_connections[$__rate_interval])','MySQL')], "ops")
        chart("Rejected Connections / min", [('60 * rate(capstone_pgproxy_rejected_connections[$__rate_interval])','PostgreSQL'),('60 * rate(capstone_mysqlproxy_rejected_connections[$__rate_interval])','MySQL')])
        chart("Backend Connection Errors / min", [('60 * rate(capstone_pgproxy_backend_dial_errors[$__rate_interval])','PostgreSQL'),('60 * rate(capstone_mysqlproxy_backend_dial_errors[$__rate_interval])','MySQL')])
        if flags["analysis.evidence_store"]:
            chart("Verified Queries / sec", [('sum by (protocol) (rate(honeypot_query_outcomes_total{verified="true"}[$__rate_interval]))','{{protocol}}')], "ops", description="Accepted evidence events, asynchronously observed; counters restart with Evidence Store.")
            chart("Verified Query Failures / min", [('60 * sum by (protocol) (rate(honeypot_query_outcomes_total{verified="true",success="false"}[$__rate_interval]))','{{protocol}}')], "short")
            chart("Authentication Outcomes / min", [('60 * sum by (protocol, success) (rate(honeypot_authentication_total[$__rate_interval]))','{{protocol}} / success={{success}}')])
            chart("Unverified Query Evidence / min", [('60 * sum by (protocol) (rate(honeypot_query_outcomes_total{verified="false"}[$__rate_interval]))','{{protocol}}')])
        finish()
    if row("Deception Effectiveness", "deception"):
        chart("Decision HTTP Results / sec", [('sum by (result) (rate(honeypot_decision_requests_total[$__rate_interval]))','{{result}}')], "ops", description="HTTP decision handling, not proof that a response reached the attacker.")
        chart("Proxy Deception Fallbacks / min", [('60 * rate(capstone_pgproxy_deception_fallbacks_total[$__rate_interval])','PostgreSQL'),('60 * rate(capstone_mysqlproxy_deception_fallbacks_total[$__rate_interval])','MySQL')], description="Decision transport/status/decode failures, counted by each proxy.")
        chart("Decision Processing p95", [('histogram_quantile(0.95, sum by (le) (rate(honeypot_decision_seconds_bucket[$__rate_interval])))','p95')], "s")
        if flags["analysis.evidence_store"]:
            chart("Verified Backend vs Deception vs Policy Responses / sec", [('sum by (authority) (rate(honeypot_query_outcomes_total{verified="true"}[$__rate_interval]))','{{authority}}')], "ops")
            chart("Verified Deception Share", [('sum(rate(honeypot_query_outcomes_total{verified="true",authority="deception"}[$__rate_interval])) / clamp_min(sum(rate(honeypot_query_outcomes_total{verified="true"}[$__rate_interval])), 1e-9)','deception / verified outcomes')], "percentunit", description="Share of newly accepted verified outcomes with deception authority, including successful and failed outcomes. No series means no observed evidence.")
            chart("Verified Successful Trap Interactions / min", [('60 * sum by (protocol) (rate(honeypot_trap_interactions_total[$__rate_interval]))','{{protocol}}')])
        finish()
    if row("Session & Behavior", "sessions", "analysis.session_behavior"):
        chart("Active Sessions", [('active_sessions','active')], kind="stat")
        chart("Closed Sessions / min", [('60 * rate(sessions_closed_total[$__rate_interval])','closed')])
        chart("Session Active Duration p50 / p95", [('histogram_quantile(0.50, sum by (le) (rate(honeypot_session_duration_seconds_bucket[$__rate_interval])))','p50'),('histogram_quantile(0.95, sum by (le) (rate(honeypot_session_duration_seconds_bucket[$__rate_interval])))','p95')], "s")
        chart("Queries per Closed Session p95", [('histogram_quantile(0.95, sum by (le) (rate(honeypot_session_queries_bucket[$__rate_interval])))','p95')])
        chart("Session Depth p95", [('histogram_quantile(0.95, sum by (le) (rate(honeypot_session_depth_bucket[$__rate_interval])))','p95')])
        chart("Session Queue Backlog", [('honeypot_session_queue_depth','queued events')], description="Actual in-process queue depth; not Kafka consumer lag.")
        chart("Session Processing p95", [('histogram_quantile(0.95, sum by (le) (rate(honeypot_session_pipeline_seconds_bucket[$__rate_interval])))','p95')], "s")
        chart("Kafka Publish Failures / min", [('60 * rate(honeypot_session_publish_total{result="failed"}[$__rate_interval])','failed attempts')])
        finish()
    if row("Deceptive Persistence", "persistence", "deception.deceptive_principals"):
        chart("Distinct Attacker-Created Principals", [('deceptive_principals_created_total','created')], kind="stat")
        chart("Distinct Principals Reused", [('deceptive_principals_reused_total','reused')], kind="stat")
        chart("Successful Return Sessions", [('deceptive_principal_return_sessions_total','return sessions')], kind="stat")
        chart("Deceptive Persistence Re-engagement Rate", [('deceptive_persistence_reengagement_rate','reused / created')], "percentunit", kind="stat",
              description="Persisted distinct reused principals / distinct created principals; zero if none created.")
        if flags["analysis.evidence_store"]:
            chart("Time to First Reuse p95", [('histogram_quantile(0.95, sum by (le) (rate(honeypot_first_reuse_seconds_bucket[$__rate_interval])))','p95')], "s", description="Explicit first-return timestamps only; no data until observed.")
        finish()
    if row("Evidence Pipeline", "evidence", "analysis.evidence_store"):
        chart("Evidence Processing / sec", [('sum by (result) (rate(honeypot_evidence_ingest_total[$__rate_interval]))','{{result}}')], "ops", description="Kafka processing attempts; processed includes idempotent re-deliveries. Query/auth counters count new stored records.")
        chart("Evidence Processing p95", [('histogram_quantile(0.95, sum by (le) (rate(honeypot_evidence_ingest_seconds_bucket[$__rate_interval])))','p95')], "s")
        chart("New Session Links / min", [('60 * rate(honeypot_session_links_total[$__rate_interval])','links')])
        chart("Principal Creation / Authentication Evidence / min", [('60 * sum by (event) (rate(honeypot_principal_evidence_total[$__rate_interval]))','{{event}}')])
        chart("Behavior Profiles Accepted / min", [('60 * rate(honeypot_behavior_profiles_total[$__rate_interval])','profiles')])
        finish()
    if row("Scaling & Resources", "scaling", "infrastructure.scaling"):
        chart("Scaling Pressure", [('capstone_scaling_scale_pressure','pressure')], "percentunit")
        chart("Desired Replica Target & Budget", [('capstone_scaling_desired_replicas','target'),('capstone_scaling_max_replica_budget','budget')], description="Logical target only. This Compose deployment has no authoritative Kubernetes replica collector.")
        chart("Scale Up / Down Decisions / min", [('60 * rate(capstone_scaling_scale_up_events[$__rate_interval])','up'),('60 * rate(capstone_scaling_scale_down_events[$__rate_interval])','down')])
        chart("Safe Mode & Autoscaling State", [('capstone_scaling_safe_mode','safe mode'),('capstone_scaling_autoscaling_enabled','autoscaling enabled')], kind="stat")
        chart("Python Service Resident Memory", [('process_resident_memory_bytes{job=~"session-module|deception-engine|evidence-store"}','{{job}}')], "bytes")
        chart("Python Service CPU Seconds / sec", [('rate(process_cpu_seconds_total{job=~"session-module|deception-engine|evidence-store"}[$__rate_interval])','{{job}}')], description="Shown only when the service runtime exports native process metrics; not host or container totals.")
        finish()
    if flags["observability.loki"]:
        if row("Log Investigation", "platform"):
            panels.append({"id":len(panels)+1,"type":"logs","title":"Service Warnings & Errors",
                           "description":"Operational logs only. Query details belong in sanitized evidence.",
                           "datasource":{"type":"loki","uid":"loki"},"gridPos":{"h":9,"w":24,"x":0,"y":y},
                           "targets":[{"refId":"A","expr":'{compose_project="capstone-main", level=~"warning|warn|error|critical"}'}],
                           "options":{"showTime":True,"showLabels":False,"wrapLogMessage":True,"sortOrder":"Descending"}})
    for panel in panels:
        panel.pop("_row",None)
    return {"uid":"honeypot-operations","title":"Honeypot Operations & Research Overview",
            "description":"Deterministic baseline. Disabled-feature rows are omitted when configuration is prepared. No data can mean no observations; health is shown separately.",
            "schemaVersion":39,"version":1,"editable":False,"tags":["honeypot","deterministic"],
            "timezone":"browser","refresh":"15s","time":{"from":"now-1h","to":"now"},"panels":panels}

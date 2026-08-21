# Bounded Evidence Report Agent

This service is the local, reproducible AI Agent v2 reporting layer. It is not a
scaling controller and it has no database credentials, database drivers, remote
tool access, attacker-contact capability, or outbound internet network.

It reads a single session record from `evidence-store` and, when available, the
latest matching result from `sandbox-replay-engine`. Deterministic risk and
replica facts are copied rather than recalculated. Every analytical claim carries
an evidence citation. After generation, only bounded report-link metadata is
written back to the internal evidence store so the session trace records the
report ID.

Endpoints:

- `GET /healthz`
- `GET /readyz`
- `POST /llm/report/session/{session_id}`
- `GET /llm/report/{report_id}`

The only implemented mode is `deterministic_local`. Reports are retained in a
bounded in-memory store and are intentionally lost on restart; the structured
evidence remains authoritative.

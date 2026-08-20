# Scaling Agent State Persistence

The scaling agent stores its complete operational state in the existing private
`redis-mitre` service. A restart restores decisions and timers before Kafka or
Prometheus signals are processed.

## Redis configuration

```text
STATE_REDIS_ADDR=redis-mitre:6379
STATE_REDIS_DB=0
STATE_REDIS_KEY=capstone:scaling-agent:state:v1
STATE_REDIS_TIMEOUT=1s
STATE_PERSISTENCE_REQUIRED=true
```

The key has no TTL. The payload is versioned and validated before restoration.
With required persistence enabled, an unavailable Redis instance, malformed
JSON, an unsupported version, inconsistent replica counts, or out-of-range
values prevent the agent from starting with silently reset state.

## Persisted fields

- Current metrics, including desired replicas, trap triggers, scale-up/down
  counters, total signals, noise signals, and current pressure.
- Scorer replicas, per-session EWMA values, rolling Z-score statistics, the last
  scale-up timestamp, and global/per-session scale-down timestamps.
- Up to 1,000 recent scaling events.
- Manual target, safe-mode, and autoscaling-enabled control fields. These are
  durable now and will be activated by the Phase 8 control API.
- Processed event IDs. The durable field is reserved for the Phase 7
  idempotency implementation.

State is synchronously saved after every processed signal, after session-state
cleanup, and during graceful shutdown. The local Redis timeout bounds a failed
write to one second.

## Observability

`GET /metrics` includes:

```json
{
  "state_persistence": {
    "enabled": true,
    "restored": true,
    "last_saved_at": "...",
    "state_key": "capstone:scaling-agent:state:v1"
  }
}
```

`GET /metrics/raw` also exposes
`scaling_agent_state_persistence_enabled` and
`scaling_agent_state_restored` gauges.

## Validation

```powershell
Set-Location scaling_agent
go test ./...
go vet ./...

Invoke-RestMethod http://127.0.0.1:9095/metrics | ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:9095/scale/events | ConvertTo-Json -Depth 8

docker compose -f docker-compose.yml restart scaling-agent
```

After restart, compare `current_replicas`, `scorer_replicas`, trap and scale
counters, recent event IDs, `last_scale_up_at`, and `below_scale_down_since`
with the pre-restart Redis payload.

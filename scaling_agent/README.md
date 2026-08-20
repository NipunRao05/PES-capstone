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
- Up to 10,000 processed event IDs used by the active Phase 7 idempotency
  guard. The oldest identity is evicted when the bounded set is full.
- Duplicate/replayed event count.

State is synchronously saved after every processed signal, after session-state
cleanup, and during graceful shutdown. The local Redis timeout bounds a failed
write to one second.

## Observability

`GET /metrics` includes:

```json
{
  "duplicate_events": 5,
  "processed_event_count": 1,
  "state_persistence": {
    "enabled": true,
    "restored": true,
    "last_saved_at": "...",
    "state_key": "capstone:scaling-agent:state:v1"
  }
}
```

`GET /metrics/raw` also exposes
`scaling_agent_state_persistence_enabled`,
`scaling_agent_state_restored`, `scaling_agent_duplicate_events_total`, and
`scaling_agent_processed_event_ids`.

## Kafka idempotency

MITRE events carry a producer-generated `event_id`. For legacy records without
one, the scaling consumer derives a SHA-256 identity from the session, technique,
rule, normalized timestamp-second bucket, and query fingerprint. Session
profiles receive a corresponding content-derived identity.

The scaler claims each non-empty identity before changing counters, scorer
state, replica targets, or event history. Repeated delivery increments only the
duplicate counter. Processed IDs and all operational counters are saved together
in the same versioned Redis document, so restart and consumer-group replay use
the restored duplicate set before processing new signals. Prometheus-only
pressure samples do not represent Kafka records and therefore intentionally do
not receive event IDs.

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

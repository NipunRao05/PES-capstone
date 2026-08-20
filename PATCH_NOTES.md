# Capstone patched bundle v2

This bundle extends v1 with fixes that make the cross-module event pipeline more reliable during small demos and improve protocol/event correctness.

## v2 changes

- Session module
  - Keeps v1's 180 passing tests.
  - Adds source-label protocol fallback in the Redpanda consumer (`mysql` / `postgres`).
  - Publishes sparse session profiles when DBSCAN does not have enough samples, instead of leaving demo sessions buffered forever.
  - Keeps DBSCAN `cluster_id=-1` semantics as `unknown`, while using a separate rule-based sparse-profile persona fallback.

- MySQL proxy
  - Adds `protocol: "mysql"` to raw/auth/session events.
  - Fixes result-set row parsing so a valid text row beginning with `0x00` is not mistaken for an OK terminator.
  - Uses a non-cancelled timeout context for final publisher flush on shutdown.

- PostgreSQL proxy
  - Adds `protocol: "postgres"` to raw/auth/session events.
  - Uses a non-cancelled timeout context for final publisher flush on shutdown.

- MITRE agent
  - Falls back to the consumer source (`mysql` / `pg`) for protocol when events do not include `protocol`.
  - Avoids unsafe short-session-id slicing in logs.

- Deception engine
  - Fixes a runtime typo in request-local Faker seeding.
  - Uses the same deterministic effective row count for `COUNT(*)` and `SELECT` pagination.

- Scaling/observability
  - Exposes `scale_pressure` in scaling-agent JSON and Prometheus metrics.
  - Metrics bridge exports `capstone_scaling_scale_pressure`.

## Validation run in sandbox

- `session_module`: `python -m pytest -q` → 180 passed.
- Python compile: `deception_engine`, `mitre_agent`, `observability/metrics_bridge`, `session_module` → passed.
- Observability JSON/YAML parse → passed.
- `scaling_agent`: `go test ./internal/scorer ./tests` → passed.

## Not validated in sandbox

Docker is unavailable in the sandbox, so `docker compose config` / stack startup could not be run here.
Full Go module tests still require network access or a complete committed `go.sum`/vendor tree for `github.com/segmentio/kafka-go` and other dependencies.

## Still intentionally deferred

- PostgreSQL extended-query protocol rewrite.
- Proxy-side deception-engine HTTP client integration.
- Native MySQL/PostgreSQL fake response packet encoders.
- Real workload-pressure scaling signals such as QPS, active connections, CPU/memory, and Redpanda lag.

## v3 continuation patch

- Could not install Docker in the sandbox: Docker was not present and `apt-get update` timed out against Debian mirrors. Docker/Compose startup remains a local-machine validation step.
- Added `protocol` and `database` to session profile payloads so downstream modules do not lose protocol context after session close.
- Replaced stale `session_module/main.py` SQLite demo with a broker-free local simulation runner using a print store.
- MITRE agent now publishes a profile-only `mitre-sessions` summary when a `session-profiles` event arrives without live query-side state, preventing closed/sparse/auth-only sessions from disappearing from Redis/Grafana.
- MITRE agent normalizes `pg` to `postgres` and carries protocol into live session state.
- Metrics bridge now aggregates Redis actor profiles into persona, MITRE technique, phase, known-attacker, and trap-trigger metrics.
- Actor tracker now uses Redis `scan_iter` instead of blocking `KEYS` in `all_actors()`.
- Scaling agent marks `session-profiles` as closed-session signals and cleans EWMA/timer state after processing them.

Validation:

- `python -m py_compile session_module/*.py mitre_agent/*.py deception_engine/*.py observability/metrics_bridge/metrics_bridge.py`
- `cd session_module && python -m pytest -q` → 180 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- Repository JSON/YAML parse check passed, including multi-document MITRE YAML.

## v4 continuation patch

- Added persistent Kafka writers in both MySQL and PostgreSQL proxy publishers. This removes per-batch writer creation and reduces Redpanda connection churn.
- Normalized Go Dockerfiles to `COPY go.mod go.sum ./` + `go mod download` and removed `GOFLAGS=-mod=mod` checksum bypasses. `scaling_agent/go.sum` is present but still needs `go mod tidy` on a networked machine.
- Removed unused `github.com/google/uuid` dependency from `scaling_agent/go.mod`.
- Corrected MySQL/PostgreSQL Dockerfile exposed proxy ports to match runtime defaults (`3306` and `5432`).
- Fixed standalone module Compose files:
  - pinned Redpanda image to `v24.1.9`
  - normalized Redpanda flags to equals/split-safe forms
  - added Redpanda readiness loops before topic creation
  - added stable standalone network aliases: `mysql-redpanda`, `pg-redpanda`
  - wired standalone session module to auth/session topics too
  - removed obsolete Compose `version` from the MITRE standalone file
- Added a session-module healthcheck in the unified Compose stack using its Prometheus `/metrics` endpoint.
- Replaced noisy `print()` session-close output with structured logger output in `session_engine.py`.
- Added `scripts/offline_smoke.py` to validate Python syntax, dashboard/config parsing, and synthetic session aggregation without Docker/Redpanda.
- Added `runbooks/local_compose_demo.md` with local startup and verification commands.
- Added `k8s/keda-scaledobject-proxy.yaml` as the correct KEDA metrics-api pattern for `scale_pressure`.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 180 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- Repository YAML/JSON parse check → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests, because the sandbox cannot fetch `proxy.golang.org` and the Kafka dependency checksums still need local `go mod tidy`.

## v5 continuation patch

- MITRE rule engine now exposes `session.fingerprint_reuse` to rule modifiers and treats unknown session conditions as non-matches instead of silently passing them.
- MITRE fingerprint matching is now case-insensitive, and table extraction strips schema/quote/punctuation noise more consistently.
- MITRE consumer now ignores successful auth/session lifecycle records instead of treating them as query events with empty fingerprints.
- Scaling failed-auth normalization now handles auth-only brute-force sessions: `failed_auth > 0` with `query_count == 0` produces a real pressure signal instead of zero.
- Scaling agent now exposes `scale_pressure` from the latest smoothed score rather than deriving it indirectly from current replica count.
- MySQL and PostgreSQL proxy publishers now drain queued raw/session/dedup events on shutdown before closing persistent Kafka writers.
- Deception engine mutation handling no longer inserts `{}` into later SELECT results. INSERT now records a plausible generated row when the table is known.
- Deception mutation cleanup now uses Redis `scan_iter`, and DELETE mutations can reduce the fake count instead of being clamped at zero.
- Deception LIMIT/OFFSET parsing now supports MySQL `LIMIT offset,count` form.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 180 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- Python compile for session, MITRE, deception, observability bridge → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests, because dependency fetch/checksum completion requires network access or vendored modules.

## v6 continuation patch

- Fixed a Go compile-time struct literal issue in `mysqlproxy/internal/publisher/publisher.go` where `QueryRaw` was assigned twice in the same `RawEvent` literal.
- Corrected scaling-agent `/metrics` JSON and `/metrics/raw` Prometheus output so `scale_pressure` uses the latest smoothed pressure stored by the scaler, matching `/keda`, instead of recomputing pressure from replica count.
- Removed a duplicate `conditions:` key from `mitre_agent/rules/detection_rules.yaml`; duplicate YAML keys can silently override earlier rule blocks with PyYAML.
- Strengthened `scripts/offline_smoke.py` with a duplicate-key YAML loader and expanded coverage to MITRE rule YAML, technique YAML, HMM/deception rule YAML, and deception schema YAML.
- Improved MITRE table extraction for common scanner/demo SQL forms: schema-qualified names, quoted names, JOIN/INTO/UPDATE/FROM variants, and trailing punctuation are normalized more safely.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 180 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- Python compile/checks are covered by `scripts/offline_smoke.py`

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests, because dependency fetch/checksum completion requires network access or vendored modules.
- PostgreSQL extended-query protocol rewrite.
- Proxy-side deception-engine HTTP client integration and native fake database response encoders.

## v7 patch notes

- Removed the external `github.com/google/uuid` dependency from both Go proxy session packages.
  - Session IDs are now generated with local RFC 4122 v4-compatible random bytes.
  - This reduces offline-build friction; MySQL session package now compiles without fetching `google/uuid`.
- Hardened client IP extraction in both proxy session packages using `net.SplitHostPort`, including `[IPv6]:port` handling.
- Session module storage now waits briefly for Kafka producer acknowledgements when publishing closed sessions and profiles, surfacing broker-side async failures instead of silently dropping them.
- MITRE store now waits briefly for Kafka producer acknowledgements for `mitre-events` and `mitre-sessions`.
- MITRE event/session schemas now carry `protocol` and `database` through outputs so dashboards and later deception/scaling decisions can correlate MySQL vs PostgreSQL behavior.
- Fixed MITRE `protocol_mode` fallback so `protocol=mysql/postgres` is not misused as a protocol mode.
- Added MITRE rule-engine unit tests covering trap-table mapping, rule IDs, case-insensitive fingerprint matching, unknown-condition fail-closed behavior, and brute-force thresholds.
- Expanded `scripts/offline_smoke.py` with a MITRE trap-table smoke check and safer module-cache cleanup between package imports.
- Removed generated `__pycache__` directories from the packaged bundle.

## v8 continuation patch

- Refactored `session_module/session_engine.py` so Kafka/storage publishing happens outside the active-session lock.
  - Session objects are popped under lock, but serialization and `storage.save_session()` now run after the lock is released.
  - This prevents Redpanda stalls from blocking new event ingestion.
  - The timeout sweeper thread is now daemonized and `shutdown()` uses a bounded join.
- Added configurable consumer offset behavior for the session module and MITRE agent via `CONSUMER_AUTO_OFFSET_RESET`.
  - Defaults remain `latest` for live demos.
  - Set `CONSUMER_AUTO_OFFSET_RESET=earliest` to replay topic data during debugging.
- Fixed container healthcheck dependencies:
  - `mysqlproxy` runtime image now includes `wget` for its Compose healthcheck.
  - `scaling_agent` runtime image now includes `wget` for its Compose healthcheck.
- Made top-level Compose proxy host ports configurable:
  - `PGPROXY_HOST_PORT`, default `5432`
  - `MYSQLPROXY_HOST_PORT`, default `3306`
- Fixed Grafana datasource provisioning by assigning stable datasource UIDs:
  - `prometheus`
  - `loki`
- Fixed the MITRE log dashboard query so it works with the current plain-text Python MITRE logs instead of assuming JSON log fields.
- Expanded `scripts/offline_smoke.py`:
  - parses `k8s/*.yaml` files
  - exercises the actual session `map_proxy_event_to_event()` mapper using broker-free Kafka stubs
- Updated the local Compose runbook with replay and port-conflict guidance.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 180 passed
- `cd mitre_agent && python -m pytest -q test_rule_engine.py` → 4 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests, because `kafka-go` and `pgproto3` dependency fetching/checksum completion requires network access or vendored modules.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v9
- MITRE agent no longer publishes to Redpanda or updates Redis while holding its live-session lock.
  - Per-query `mitre-events` are built under lock but published after lock release.
  - Closed-session `mitre-sessions` and actor-profile updates are also emitted after lock release.
  - This avoids stalling live rule evaluation when Redpanda or Redis pauses.
- Session module clustering consumer now respects `CONSUMER_AUTO_OFFSET_RESET` instead of always replaying from earliest.
- Scaling agent now supports `CONSUMER_START_OFFSET=latest|earliest` and the unified Compose file wires it through.

## v10
- Session module ingestion is now more resilient under backpressure.
  - `event_worker()` catches processing exceptions, records `events_failed_total{stage="session_engine"}`, and always calls `queue.task_done()`.
  - Kafka consumer threads use bounded `event_queue.put(..., timeout=2)` instead of blocking forever when the queue is full.
  - Dropped queue events are counted with `events_dropped_total{reason="queue_full"}`.
- Session module shutdown now stops the clustering worker, drains/joins the queue worker, flushes active sessions, and closes storage in a deterministic order.
- Clustering worker no longer drops a final in-memory batch on shutdown.
  - Full batches are clustered.
  - Sparse batches are published through the rule-based profile fallback.
  - Poll errors are logged and retried instead of killing the thread.
- Added a broker-independent MITRE health endpoint on `HEALTH_ADDR` (`/healthz`, `/readyz`), defaulting to `0.0.0.0:8002`.
  - The unified Compose file now exposes this port and adds a MITRE healthcheck.
  - The MITRE Dockerfile now documents `EXPOSE 8002`.
- Session module Dockerfile now documents `EXPOSE 8000` for Prometheus metrics.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 180 passed
- `cd mitre_agent && python -m pytest -q` → 4 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests, because `kafka-go` and `pgproto3` dependency fetching/checksum completion requires network access or vendored modules.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v11
- Session module fallback session keys are now protocol/database-aware when proxy `session_id` is missing.
  - Legacy events without protocol metadata still use the old `(source_ip, db_user)` key so older tests/events remain compatible.
  - This prevents MySQL and PostgreSQL activity from the same IP/user from merging into one synthetic session.
- Session module now normalizes protocol aliases (`pg`, `postgresql` → `postgres`) and backfills missing session protocol/database metadata from later events in the same session.
- MITRE live session state now uses the first event timestamp as `first_seen` instead of wall-clock creation time.
  - This fixes QPS calculations when replaying events or when proxy timestamps differ from agent wall-clock time.
- MITRE event parsing now falls back to `query_normalized` when `fingerprint` is present but empty.
- MITRE profile-only summaries no longer duplicate classified phases before HMM scoring.
- Added tests for protocol-aware fallback session keys, MITRE fingerprint fallback, timestamp-based first_seen, and profile-only phase de-duplication.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 182 passed
- `cd mitre_agent && python -m pytest -q` → 7 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests, because `kafka-go` and `pgproto3` dependency fetching/checksum completion requires network access or vendored modules.
- `pgproxy/internal/session` still cannot be tested offline here because `github.com/jackc/pgproto3/v2` is not available in the sandbox cache.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v12
- Fixed MITRE agent health-server lifecycle regression.
  - `start()` no longer clears `_health_server` after binding `/healthz` and `/readyz`.
  - Added a unit test that starts the broker-independent health server on a free localhost port and verifies it can be stopped cleanly.
- MITRE session-profile consumer now catches unexpected exceptions, logs them, and continues instead of killing the profile consumer thread.
- Session module consumers now use `consumer_timeout_ms=1000` plus a shared shutdown event so they can exit cleanly on shutdown instead of relying only on daemon threads.
- Session module shutdown path now stops clustering, wakes the event worker, joins bounded workers, flushes active sessions, and then closes storage.
- Metrics bridge Redis aggregation now computes average actor risk over successfully parsed actor profiles instead of dividing by all scanned keys, and exports:
  - `capstone_mitre_parsed_actor_count`
  - `capstone_mitre_actor_parse_errors`
- Added metrics bridge unit tests for Prometheus metadata de-duplication and Redis actor-risk averaging with malformed Redis records.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 182 passed
- `cd mitre_agent && python -m pytest -q` → 8 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 2 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests, because external dependency fetch/checksum completion requires network access or vendored modules.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v13

- MITRE agent now preserves obvious technique evidence for profile-only sessions, instead of publishing an empty `techniques_matched` list when the live query stream was missed.
  - Auth-only brute-force profiles infer `T1110.001` from aggregate `failed_auth` counts.
  - Recon/suspicion profiles infer `T1082`.
  - Enumeration profiles infer `T1213.006` when depth evidence is present.
  - Exploitation/exfiltration phases infer `T1190` / `T1048`.
- Profile-only MITRE sessions now include an attack graph built from inferred aggregate technique matches.
- Added MITRE tests for profile-only brute-force technique preservation.

## v14 patch notes

- Session module shutdown order now stops and joins Redpanda consumer threads before draining the worker queue and sending the worker sentinel. This avoids stranding events behind the sentinel during Ctrl+C shutdown.
- MITRE agent query/session-profile consumers now retry KafkaConsumer creation instead of exiting permanently if Redpanda metadata is not ready during Compose startup.
- MITRE `/readyz` now reports HTTP 503 until all expected consumers have connected; `/healthz` remains a process liveness check.
- MITRE producer construction now retries Redpanda connection with configurable retry/timeout settings:
  - `PRODUCER_CONNECT_RETRIES`
  - `PRODUCER_CONNECT_RETRY_DELAY_SECONDS`
  - `PRODUCER_ACK_TIMEOUT_SECONDS`
- Session module storage now uses configurable `PRODUCER_ACK_TIMEOUT_SECONDS` for session/profile publishing acknowledgements.
- Added MITRE readiness unit coverage for `/readyz` returning 503 when a consumer is not connected.

## v15 patch notes

- MITRE consumer-group isolation:
  - `CONSUMER_GROUP` is now configurable through the environment.
  - MySQL and PostgreSQL query consumers now use source-specific group IDs (`<group>-mysql`, `<group>-pg`) instead of sharing the same group ID.
  - This avoids group/subscription interference when all topics live on one shared Redpanda broker.
- Session module timestamp hardening:
  - active-session `last_activity` is now monotonic, so replayed/out-of-order timestamps cannot shorten a session.
  - emitted session duration is clamped at zero or higher.
  - timing variance now sorts timestamps and clamps negative gaps before calculating stdev.
- Added tests for:
  - out-of-order/replayed session timestamps producing non-negative durations.
  - source-specific MITRE consumer-group naming.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 183 passed
- `cd mitre_agent && python -m pytest -q` → 11 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 2 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests requiring external dependency fetch/checksum completion.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v16 patch notes

- MITRE replay/timing hardening:
  - live session `first_seen` is now updated to the earliest observed event timestamp, not just the first event received.
  - live QPS now uses the observed event timestamp range instead of wall-clock order, preventing misleading zero/negative replay behaviour.
  - MITRE timing variance now sorts event timestamps and clamps gaps before calculating variance.
  - closed MITRE sessions prefer the session module's `duration` field over wall-clock duration, so replayed historical sessions do not get huge fake durations.
- Deception engine mutation consistency:
  - `COUNT(*)` responses now clamp negative delete deltas at zero.
  - `SELECT` pagination now uses the same mutation-adjusted row count as `COUNT(*)`, reducing consistency leaks after INSERT/DELETE operations.
- Added tests for:
  - MITRE replay/out-of-order timestamp QPS handling.
  - MITRE profile duration overriding wall-clock replay duration.
  - MITRE sorted timing variance.
  - deception `LIMIT offset,count` parsing.
  - deception count clamping after excessive DELETE deltas.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 183 passed
- `cd mitre_agent && python -m pytest -q` → 14 passed
- `cd deception_engine && python -m pytest -q` → 4 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 2 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests requiring external dependency fetch/checksum completion.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v17 patch notes

- Deception engine mutation safety:
  - INSERT/UPDATE/DELETE operations against unknown or unmanaged tables now return `passthrough` instead of recording fake mutation state.
  - This prevents empty `{}` rows from leaking into later fake SELECT responses for unknown tables.
- Deception engine PostgreSQL catalog support:
  - `SELECT datname FROM pg_database` now returns fake database rows with PostgreSQL-native `datname` column naming.
  - `pg_tables` / `information_schema.tables` enumeration now returns `schemaname` and `tablename` columns for PostgreSQL sessions while retaining MySQL `Tables_in_db` output for MySQL sessions.
- Session feature extraction:
  - `extract_features()` now clamps negative duration to zero for old `Session` objects with replayed/out-of-order timestamps.
- MITRE Compose healthcheck:
  - Unified and standalone Compose healthchecks now use `/readyz` instead of `/healthz` so orchestration waits for consumer readiness, not just process liveness.
- Added tests for:
  - unknown-table mutation passthrough without mutation recording.
  - PostgreSQL catalog/database enumeration response shape.
  - negative-duration clamping in session feature extraction.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 184 passed
- `cd mitre_agent && python -m pytest -q` → 14 passed
- `cd deception_engine && python -m pytest -q` → 7 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 2 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable.
- Full Go module tests requiring external dependency fetch/checksum completion.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v18 patch

- Deception engine now returns protocol-native PostgreSQL system-information responses for common discovery queries:
  - `SELECT version()` → `version`
  - `SELECT current_database()` / `current_database` → `current_database`
  - `SELECT current_user` / `current_user()` / `session_user` → native user columns
  - `SELECT inet_server_port()` → `inet_server_port`
- PostgreSQL system-info values are configurable with:
  - `DECEPTION_POSTGRES_VERSION`
  - `DECEPTION_POSTGRES_PORT`
- MITRE profile-only session summaries now tolerate malformed numeric fields and clamp negative durations to zero instead of letting bad session-profile payloads kill the profile consumer path.
- Metrics bridge now exposes `/healthz` and `/readyz` aliases in addition to `/health`.
- Offline smoke now validates PostgreSQL-native deception system-info behavior.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 184 passed
- `cd mitre_agent && python -m pytest -q` → 16 passed
- `cd deception_engine && python -m pytest -q` → 10 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 2 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

## v19

- Deception engine:
  - Added PostgreSQL-style schema enumeration for `information_schema.schemata` using `schema_name` columns.
  - Returned PostgreSQL-native `count` column names for fake `SELECT COUNT(*)` responses.
  - Added PostgreSQL `current_schema` fake system-info responses.
  - Made fake date/datetime generation deterministic with a fixed anchor instead of wall-clock `datetime.now()`.
  - Marked generated SSNs, card numbers, IBANs, and routing values with explicit `DECOY_*` prefixes to avoid realistic-looking sensitive data leaks in demos/scanners.
  - Added tests for protocol-native PostgreSQL shapes, deterministic date generation, and decoy-sensitive-value prefixes.

## v20

- Deception engine:
  - Added `/healthz` and `/readyz` endpoints.
  - `/healthz` is liveness-only; `/readyz` requires loaded schemas, initialized components, and a successful Redis ping.
  - Unified and standalone Compose healthchecks now use `/readyz` instead of `/health`.
  - Runbook health URL updated to the readiness endpoint.
- MITRE agent:
  - Live session-profile handling now uses safe numeric parsing for `entropy`, `depth_score`, `timing_variance_ms`, `queries_per_second`, and `suspicion_score`.
  - Malformed profile durations no longer fall back to huge wall-clock replay durations when the profile carried a bad value.
  - Existing live sessions now backfill missing protocol/database values from the closing `session-profile` event.
  - Query-event parsing now tolerates malformed `bytes_in` / `bytes_out` counters.
- Tests:
  - Added deception readiness/liveness endpoint tests.
  - Added MITRE tests for malformed live session profiles and bad byte counters.
  - Moved Python `unittest.main()` guards to the bottom of patched test files so direct script execution sees all test classes.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 184 passed
- `cd mitre_agent && python -m pytest -q` → 18 passed
- `cd deception_engine && python -m pytest -q` → 16 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 2 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

## v21

- Session module:
  - Auth/session event mapping now treats string/number false values (`"false"`, `"0"`, `0`) as failed authentication instead of requiring a strict JSON boolean `false`.
  - Legacy `Session.update()` now keeps `last_seen` monotonic for replayed/out-of-order events, matching the hardened `ActiveSession` behavior.
- MITRE agent:
  - Query-event parsing now normalizes auth status strings/numbers, so proxy or replay payloads with `success: "false"` or `auth_success: "false"` still become `auth_fail` events.
- Deception engine:
  - LIMIT/OFFSET parsing is now case-insensitive, so uppercase SQL such as `LIMIT 10 OFFSET 20` does not silently fall back to the default 100-row response.
  - Mutation store now tolerates malformed Redis mutation records: bad `count_delta` values fall back to `0`, and inserted-row lists are filtered to dictionaries only.
  - Exposure depth reads are clamped to the valid range `1..3`, preventing corrupt Redis state from exposing trap tables too early or hiding all tables.
- Observability:
  - Prometheus label escaping now handles newlines/carriage returns in addition to quotes and backslashes, preventing malformed scrapes from unusual persona/phase strings.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 186 passed
- `cd mitre_agent && python -m pytest -q` → 20 passed
- `cd deception_engine && python -m pytest -q` → 20 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 3 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/session` → passed

## v22

- Scaling agent now treats `session-profiles.depth_score` as `float64`, matching the Python session module output.
  This prevents `json.Unmarshal` from dropping session-profile signals when Python emits `1.0`/fractional depth scores.
- `scorer.NormaliseDepth` now accepts floating-point depth values and has regression coverage for fractional inputs.

## v23

- Session module now assigns deterministic synthetic session IDs for legacy events that lack a proxy `session_id`:
  - `protocol:source_ip:db_user`
  - `protocol:source_ip:db_user:database` when database is known
  This keeps session-profiles correlatable with MITRE live state instead of emitting random UUIDs at close time.
- MITRE query-event fallback session IDs now use the same database-aware convention as the session module.
- MITRE profile-only summaries now treat string `cluster_id: "-1"` the same as numeric `-1`.
- MITRE profile-only enumeration inference now respects fractional `depth_score` values instead of truncating them before threshold checks.
- Added regression tests for deterministic fallback IDs, string noise-cluster IDs, and fractional-depth MITRE inference.

## v24

Runtime-driven patch from local Compose testing:

- MySQL proxy:
  - Sanitizes captured `query_raw` by stripping MySQL COM_QUERY query-attribute control bytes such as `\x00\x01` before publishing query events.
  - The original wire payload is still forwarded unchanged; only telemetry is cleaned.
  - Added interceptor regression tests for raw-query cleanup.

- MITRE agent:
  - Added actor-level failed-auth rolling windows keyed by `protocol + client_ip + username + database`.
  - Separate failed-login proxy sessions can now aggregate into a brute-force detection and emit `T1110.001` once the window threshold is crossed.
  - Profile-only/auth-only session summaries also use the actor auth window, so repeated one-failure profiles can still become credential-access evidence.
  - Added tests proving three separate failed-login sessions trigger `T1110.001`.

- MITRE metadata/risk:
  - Added `T1213.006` metadata as `Data from Information Repositories: Databases` under Collection/TA0009.
  - Repeated schema enumeration now reaches medium risk instead of staying low when depth is already above the enumeration threshold.
  - Added tests for enriched sub-technique metadata and medium enumeration risk.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 188 passed
- `cd mitre_agent && python -m pytest -q` → 28 passed
- `cd deception_engine && python -m pytest -q` → 20 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 3 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/interceptor ./internal/session` → passed

## v25

Runtime/demonstration hardening after v24:

- MITRE agent:
  - Profile-only/auth-only brute-force aggregation now publishes an actor-window `mitre-events` alert as well as the closed `mitre-sessions` summary.
  - Actor-window brute-force alerts are throttled per actor/window bucket, preventing one burst from flooding `mitre-events` with duplicate `T1110.001` records.
  - Added tests proving separate one-failure profiles accumulate into one `T1110.001` event and that repeated profiles in the same rolling window do not emit duplicate alerts.
- Attack graph:
  - Uses `nx.node_link_data(..., edges="links")` to keep current JSON shape and remove the NetworkX future warning seen during local tests.
- Runtime/demo tooling:
  - Added `scripts/summarize_rpk_json.py` to convert nested `rpk topic consume` envelopes into compact readable lines for `session-profiles`, `mitre-events`, and `mitre-sessions`.
  - Added `scripts/demo_runtime_probe.ps1` to run health checks, generate MySQL/PostgreSQL demo traffic, wait for session close, and print summarized Redpanda topic output.
  - `scripts/offline_smoke.py` now compiles Python helper scripts and smoke-tests the RPK summarizer.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 188 passed
- `cd mitre_agent && python -m pytest -q` → 29 passed
- `cd deception_engine && python -m pytest -q` → 20 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 3 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/interceptor ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose runtime startup, because Docker is unavailable here.
- Full Go module tests requiring external dependency fetch/checksum completion.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v26 continuation patch

- Published the session-module and MITRE health/readiness ports in the top-level Compose file by default:
  - `SESSION_MODULE_HOST_PORT`, default `8000`
  - `MITRE_AGENT_HOST_PORT`, default `8002`
  This matches the runtime checks used during local validation and avoids needing a manual Compose edit.
- Improved `scripts/demo_runtime_probe.ps1`:
  - includes the session-module `/metrics` health check
  - uses `docker compose exec -T` for Redpanda topic commands so piping into Python works reliably
  - adds `-ConsumeNum` and `-ConsumeOffset` knobs for repeated demos on reused Redpanda volumes
- Hardened `scripts/summarize_rpk_json.py` so `mitre-sessions.techniques_matched` can be either the current list-of-objects shape or a future/simple list-of-strings shape.
- Updated `runbooks/local_compose_demo.md` with the actual host health URLs, current `rpk` command style, demo probe command, and the expected `T1110.001` / `T1213.006` milestones.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 188 passed
- `cd mitre_agent && python -m pytest -q` → 29 passed
- `cd deception_engine && python -m pytest -q` → 20 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 3 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/interceptor ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable in this sandbox.
- Full Go module tests requiring networked dependency resolution.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

## v27 continuation patch

Validation/demo hardening:

- Added `scripts/assert_rpk_milestone.py`:
  - parses raw `rpk topic consume` JSON envelopes
  - decodes nested JSON `value` fields
  - asserts expected topic counts and MITRE technique IDs
  - supports both live `mitre-events.technique_id` and closed-session `mitre-sessions.techniques_matched`
- Updated `scripts/demo_runtime_probe.ps1`:
  - added `-AssertMilestones` to fail fast when `T1110.001` or `T1213.006` is missing
  - added `-SkipTraffic` to summarize/assert existing topic data without generating new database traffic
  - captures topic output once, then reuses it for summary and assertions
- Updated `scripts/offline_smoke.py` to exercise the new milestone assertion helper.
- Added `runbooks/validate_v24_to_v27.md` with a version-by-version validation checklist for:
  - v24 MySQL query telemetry cleanup and MITRE metadata enrichment
  - v25 actor-window brute-force `T1110.001`
  - v26 host health port exposure and demo probe
  - v27 milestone assertions
- Updated `runbooks/local_compose_demo.md` to document `-AssertMilestones`.

Validation:

- `python scripts/offline_smoke.py` → passed
- `cd session_module && python -m pytest -q` → 188 passed
- `cd mitre_agent && python -m pytest -q` → 29 passed
- `cd deception_engine && python -m pytest -q` → 20 passed
- `cd observability/metrics_bridge && python -m pytest -q` → 3 passed
- `cd scaling_agent && go test ./internal/scorer ./tests` → passed
- `cd mysqlproxy && go test ./internal/interceptor ./internal/session` → passed

Still not validated in sandbox:

- Docker Compose startup, because Docker is unavailable in this sandbox.
- Full Go module tests requiring networked dependency resolution.
- PostgreSQL extended-protocol rewrite.
- Proxy-side deception-engine integration and native fake response encoders.

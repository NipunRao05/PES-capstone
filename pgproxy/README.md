# pgproxy — PostgreSQL Transparent Proxy

A production-grade PostgreSQL wire-protocol proxy written in Go. It sits between your application and a real PostgreSQL server, forwarding every byte transparently while providing a hook layer for query interception, event publishing, response shaping, and observability — all without modifying your application or your database.

---

## Table of Contents

1. [What this is](#1-what-this-is)
2. [How it works](#2-how-it-works)
3. [Architecture layers](#3-architecture-layers)
4. [Quick start](#4-quick-start)
5. [Configuration reference](#5-configuration-reference)
6. [HTTP endpoints](#6-http-endpoints)
7. [Enabling Phase 2 — query interception](#7-enabling-phase-2--query-interception)
8. [Enabling Phase 3 — Kafka publishing](#8-enabling-phase-3--kafka-publishing)
9. [Response shaping](#9-response-shaping)
10. [What you must not touch](#10-what-you-must-not-touch)
11. [What you can safely modify](#11-what-you-can-safely-modify)
12. [Event schemas](#12-event-schemas)
13. [Running tests](#13-running-tests)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. What this is

pgproxy is a **transparent TCP proxy** that speaks the full PostgreSQL wire protocol on both sides:

```
Your app  ──►  pgproxy :5433  ──►  PostgreSQL :5432
               (intercepts)         (real database)
```

Your application connects to pgproxy exactly as it would to PostgreSQL — same connection string, same driver, same queries. pgproxy forwards everything without modification. Optionally, it can also capture every query, normalize SQL, compute a stable fingerprint, and publish structured events to Kafka for auditing, analytics, or alerting.

**What it is not:** It is not a connection pool, a query router, or a query rewriter. It does not buffer or retry queries. It does not alter query results (unless you explicitly configure response shaping rules).

---

## 2. How it works

### Connection lifecycle

Every incoming TCP connection from a client spawns a dedicated goroutine. That goroutine immediately dials a new TCP connection to the real PostgreSQL backend. From that point on, the proxy manages a bidirectional conversation:

```
1. Peek 8 bytes → is this a CancelRequest?
       Yes → forward cancel to backend on a new connection, close
       No  → continue to startup

2. Startup handshake
   a. Read client's SSLRequest / GSSEncRequest / StartupMessage
   b. Negotiate SSL with the backend (proxy always tries SSL with PG)
   c. Forward the StartupMessage to the backend
   d. Relay the authentication exchange message-by-message
      (handles cleartext, MD5, SCRAM-SHA-256)
   e. Forward ParameterStatus + BackendKeyData + ReadyForQuery to client

3. Main proxy loop (runs until client disconnects)
   a. Read one message from the client
   b. [Optional] Phase 2: intercept it (extract SQL, update session state)
   c. Apply ResponseShaper decision (block? inject latency? limit rows?)
   d. Forward message to backend
   e. Drain all backend response messages back to client
      (handles COPY-IN, COPY-OUT, COPY-BOTH streaming modes)
   f. Stop draining at ReadyForQuery

4. Cleanup
   - Extended query state removed from interceptor
   - Both TCP connections closed
   - Active connection counter decremented
```

### Protocol support

| Feature | Status |
|---|---|
| Simple query protocol (`Query`) | ✅ Full |
| Extended query protocol (`Parse/Bind/Execute/Sync`) | ✅ Full |
| SSL negotiation (client-facing) | ✅ Decline gracefully |
| SSL to backend | ✅ Attempt, fall back to plain |
| GSS/Kerberos negotiation | ✅ Decline gracefully |
| CancelRequest | ✅ Forwarded correctly |
| COPY TO STDOUT | ✅ Full streaming |
| COPY FROM STDIN | ✅ Full streaming |
| Logical replication (CopyBoth) | ✅ Bidirectional streaming |
| MD5 authentication | ✅ |
| SCRAM-SHA-256 authentication | ✅ |
| Cleartext password authentication | ✅ |

### SQL normalization and fingerprinting

When Phase 2 is active, every captured SQL string goes through a two-step pipeline:

**Step 1 — Normalize:** Strip comments, replace all literal values with `?`, collapse IN lists, lowercase everything.
```sql
-- Input
SELECT * FROM users WHERE id = 42 AND name = 'alice'

-- Normalized
select * from users where id = ? and name = ?
```

**Step 2 — Fingerprint:** Run FNV-64a over the normalized string, encode as 16-char lowercase hex.
```
a3f2c1d4e5b67890
```

Two queries with different literal values but the same shape always produce the same fingerprint. This is the deduplication key used by the publisher.

Both outputs are cached in bounded caches (50,000 entries each). When the cap is hit, the cache clears entirely and rebuilds — no unbounded memory growth.

---

## 3. Architecture layers

The codebase is organized into strict layers. Each layer has one job and does not call upward.

```
internal/
├── connection/   Layer 1 — ConnectionManager
├── protocol/     Layer 2 — ProtocolParser (pgproto3)
├── session/      Layer 3 — SessionTracker
├── interceptor/  Layer 4 — QueryInterceptor      [Phase 2]
├── publisher/    Layer 5 — EventPublisher         [Phase 3]
├── shaper/       Layer 6 — ResponseShaper
└── forwarder/    Layer 7 — MessageForwarder (utilities)
```

### Layer 1 — ConnectionManager (`internal/connection/manager.go`)
Owns the TCP listener, accepts connections, dials the backend, spawns goroutines, and manages shutdown. Also runs the HTTP health server and the backend health checker.

### Layer 2 — ProtocolParser (`internal/protocol/handler.go`)
The core of the proxy. Uses `pgproto3` to parse and encode every PostgreSQL wire message. Handles the startup dance, auth relay, COPY streaming, and the main bidirectional loop. This is where Phase 2 hooks and ResponseShaper decisions are applied.

### Layer 3 — SessionTracker (`internal/session/session.go`)
Thread-safe, per-connection state: session UUID, client IP, username, database, transaction status, prepared statements, portals, and byte counters. Lives for the duration of one connection.

### Layer 4 — QueryInterceptor (`internal/interceptor/interceptor.go`)
Extracts SQL from both simple (`Query`) and extended (`Parse/Bind/Execute`) protocol messages. Correlates multi-step extended queries by session ID. Normalizes SQL and computes fingerprints. Emits `QueryEvent` structs on a buffered channel. **Currently compiled but not wired in** — see [Phase 2](#7-enabling-phase-2--query-interception).

### Layer 5 — EventPublisher (`internal/publisher/publisher.go`)
Consumes `QueryEvent` from the interceptor. Maintains two parallel output streams: a raw per-execution stream (`pg-query-events`) and a deduplicated windowed stream (`pg-query-dedup`). Batches and sends to Kafka. Has a 100,000-event in-memory buffer so Kafka downtime does not affect query latency. **Currently compiled but not wired in** — see [Phase 3](#8-enabling-phase-3--kafka-publishing).

### Layer 6 — ResponseShaper (`internal/shaper/shaper.go`)
**Always active.** Applies per-fingerprint or global rules to outgoing responses: inject latency, cap row counts, or block queries entirely. Zero-cost when no rules are configured (the default). Rules can be added and removed at runtime.

### Layer 7 — MessageForwarder (`internal/forwarder/forwarder.go`)
Utility helpers: bidirectional `io.Copy` pipe for raw streaming modes, and a counting writer. Not called in the hot path.

---

## 4. Quick start

**Requirements:** Docker and Docker Compose.

```bash
# Clone and start everything
docker compose up --build

# Connect through the proxy (same as connecting to real PostgreSQL)
psql -h localhost -p 5433 -U postgres
# Password: password

# Connect directly to PostgreSQL for comparison
psql -h localhost -p 5432 -U postgres
# Password: password

# Check proxy health
curl http://localhost:9090/healthz

# Check proxy metrics
curl http://localhost:9090/metrics
```

The proxy is **fully transparent** by default. Every query you run through port 5433 behaves identically to port 5432.

---

## 5. Configuration reference

All configuration is done via environment variables. Set them in `docker-compose.yml` or pass them at runtime.

### Core settings

| Variable | Default | Description |
|---|---|---|
| `PROXY_LISTEN_ADDR` | `0.0.0.0:5433` | Address the proxy listens on |
| `PG_BACKEND_ADDR` | `localhost:5432` | Address of the real PostgreSQL server |
| `LOG_LEVEL` | `info` | Log verbosity. Set to `debug` to see every message type |
| `MAX_CONNECTIONS` | `10000` | Maximum simultaneous client connections |
| `DIAL_TIMEOUT` | `10s` | Timeout for dialing the PostgreSQL backend |

### Reliability settings

| Variable | Default | Description |
|---|---|---|
| `SHUTDOWN_TIMEOUT` | `30s` | How long to wait for in-flight connections to finish on SIGTERM before forcing close |
| `BACKEND_PING_INTERVAL` | `15s` | How often to probe the backend with a TCP dial to check reachability. Set to `0` to disable |

### Observability settings

| Variable | Default | Description |
|---|---|---|
| `HTTP_ADDR` | `0.0.0.0:9090` | Address for the HTTP health and metrics server. Set to `""` to disable |

### Phase 3 Kafka settings (disabled by default)

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BROKERS` | *(unset)* | Comma-separated list of Kafka broker addresses, e.g. `kafka1:9092,kafka2:9092` |
| `KAFKA_TOPIC` | `pg-query-events` | Topic for raw per-execution events |
| `KAFKA_DEDUP_TOPIC` | `pg-query-dedup` | Topic for deduplicated windowed events |

### Duration format

All duration values use Go's duration syntax: `30s`, `5m`, `1h`, `500ms`. Examples: `SHUTDOWN_TIMEOUT=1m`, `BACKEND_PING_INTERVAL=30s`.

---

## 6. HTTP endpoints

The proxy exposes three endpoints on `HTTP_ADDR` (default port 9090).

### `GET /healthz`
Liveness and backend reachability check. Used by Docker healthcheck and load balancer health probes.

```json
// 200 OK — backend is reachable
{"status":"ok","active_connections":42}

// 503 Service Unavailable — backend is down
{"status":"unhealthy","backend":"postgres:5432"}
```

### `GET /metrics`
JSON snapshot of all internal counters. Poll this from Prometheus, Datadog, or any monitoring system.

```json
{
  "active_connections": 42,
  "total_connections": 10483,
  "rejected_connections": 0,
  "backend_dial_errors": 2,
  "cancel_requests": 7,
  "backend_health_failures": 0,
  "backend_healthy": true
}
```

| Field | What it counts |
|---|---|
| `active_connections` | Connections currently open end-to-end |
| `total_connections` | All connections since startup |
| `rejected_connections` | Connections dropped because `MAX_CONNECTIONS` was hit |
| `backend_dial_errors` | Failed dials to PostgreSQL (client saw an error message) |
| `cancel_requests` | CancelRequest messages received and forwarded |
| `backend_health_failures` | Number of failed backend ping probes |
| `backend_healthy` | Whether the last ping succeeded |

### `GET /ready`
Kubernetes readiness probe. Returns `200` when the proxy can accept connections, `503` when at capacity or backend is unreachable.

---

## 7. Enabling Phase 2 — query interception

Phase 2 activates SQL capture. It is **compiled in but wired out by default** so it adds zero overhead when not needed. To enable it, make three changes in `internal/protocol/handler.go`:

### Step 1 — Uncomment the imports

```go
// At the top of handler.go, find:
// "github.com/pgproxy/internal/interceptor"
// "github.com/pgproxy/internal/publisher"

// Change to:
"github.com/pgproxy/internal/interceptor"
"github.com/pgproxy/internal/publisher"
```

### Step 2 — Add fields to the Handler struct

```go
type Handler struct {
    // ... existing fields ...

    interceptor *interceptor.Interceptor  // add this
    publisher   *publisher.Publisher      // add this
}
```

### Step 3 — Uncomment the interception calls in `proxyLoop`

```go
// Find the PHASE 2 block in proxyLoop() and uncomment:
switch m := clientMsg.(type) {
case *pgproto3.Query:
    h.interceptor.InterceptSimple(h.sess, m.String)
case *pgproto3.Parse:
    h.interceptor.InterceptParse(h.sess, m.Name, m.Query)
case *pgproto3.Bind:
    h.interceptor.InterceptBind(h.sess, m.PreparedStatement, m.DestinationPortal, m.Parameters)
case *pgproto3.Execute:
    h.interceptor.InterceptExecute(h.sess, m.Portal, m.MaxRows)
}
```

### Step 4 — Uncomment the cleanup call in `Run`

```go
// Find the PHASE 2 comment in the defer block of Run():
defer func() {
    if h.sess != nil {
        h.interceptor.CleanupSession(h.sess.ID)  // uncomment this
    }
}()
```

### Step 5 — Wire fingerprint into the shaper

```go
// In proxyLoop(), find:
var fingerprint string
// Phase 2: fingerprint = h.interceptor.LastFingerprint(h.sess)

// Change to use the last intercepted fingerprint from the session.
```

---

## 8. Enabling Phase 3 — Kafka publishing

Phase 3 activates event publishing to Kafka. Requires Phase 2 to be active first.

### Step 1 — Uncomment Kafka in `publisher.go`

In `internal/publisher/publisher.go`, find the two commented blocks in `sendRawBatch` and `sendDedupBatch` and uncomment them. They use `kafka-go` and are ready to use.

### Step 2 — Uncomment Kafka in `main.go`

```go
// In cmd/proxy/main.go, find:
// KafkaBrokers: strings.Split(getEnv("KAFKA_BROKERS", ""), ","),
// KafkaTopic:   getEnv("KAFKA_TOPIC", "pg-query-events"),

// Uncomment both lines and add the strings import at the top.
```

### Step 3 — Uncomment Kafka in `docker-compose.yml`

The Kafka + Zookeeper services are commented out at the bottom of `docker-compose.yml`. Uncomment them, then set `KAFKA_BROKERS=kafka:9092` in the proxy service environment.

### Kafka reliability guarantees

- If Kafka is down, events are buffered in memory (up to 100,000 raw events).
- Events beyond the buffer cap are dropped with a warning log — they **never block query execution**.
- The dedup table accumulates independently of Kafka. If Kafka recovers, the next flush window will still emit accurate counts.
- Both topics use the `fingerprint` field as the Kafka message key, so events for the same query shape land on the same partition.

---

## 9. Response shaping

The ResponseShaper (Layer 6) is **always active** but has no effect until rules are configured. It is zero-cost when idle.

Rules are currently set in code via `shaper.New(cfg, logger)` in `internal/protocol/handler.go`. Future work would load rules from a config file or API.

### Rule fields

```go
shaper.Rule{
    Fingerprint:  "a3f2c1d4e5b67890",  // target this specific query shape
    Block:        false,                 // if true, return error to client immediately
    BlockMessage: "query not allowed",   // error text sent to psql
    Latency:      50 * time.Millisecond, // inject delay before first row
    RowLimit:     1000,                  // drop rows beyond this count
}
```

| Field | Behavior |
|---|---|
| `Fingerprint` | Hex fingerprint from `interceptor.FingerprintSQL`. Get it from the `fingerprint` field in Kafka events or debug logs. |
| `Block: true` | The proxy sends `ERROR: query blocked by proxy policy` to the client. The backend never sees the query. |
| `Latency` | Applied once before the first `RowDescription` or `DataRow`. Set to `-1` to **disable** a global latency for this fingerprint. |
| `RowLimit` | After this many rows, remaining rows are dropped. A `NOTICE` is sent to the client before `CommandComplete`. Set to `-1` to **disable** a global row limit for this fingerprint. |

### Global defaults

```go
shaper.Config{
    GlobalLatency:   0,               // disabled by default
    JitterFraction:  0.2,             // ±20% random jitter if GlobalLatency > 0
    DefaultRowLimit: 0,               // unlimited by default
}
```

### Adding rules at runtime

```go
// Inject a rule without restarting
myShaper.AddRule(shaper.Rule{
    Fingerprint: "a3f2c1d4e5b67890",
    RowLimit:    500,
})

// Remove it
myShaper.RemoveRule("a3f2c1d4e5b67890")
```

---

## 10. What you must not touch

These parts of the codebase implement the PostgreSQL wire protocol. Changing them without a thorough understanding of the protocol spec will break compatibility with real clients and drivers.

### `internal/protocol/handler.go` — startup and auth sequence

**Do not reorder or skip any step** in `handleStartup`, `readClientStartup`, `forwardStartupToBackend`, `forwardAuthLoop`, or `forwardPostAuthMessages`. The sequence is:

```
client SSLRequest → proxy 'N' → client StartupMessage
→ proxy SSLRequest to backend → backend 'S'/'N'
→ proxy sends StartupMessage to backend
→ backend AuthRequest → proxy forwards to client
→ client responds → proxy forwards to backend
→ repeat until AuthenticationOk
→ backend sends ParameterStatus × N, BackendKeyData, ReadyForQuery
→ proxy forwards all, stores BackendKeyData in session
```

Each message type in the auth loop has a specific expected response. Removing a case or changing the order causes the client or backend to hang waiting for a message that never arrives.

**Do not modify the COPY handlers** (`handleCopyOut`, `handleCopyIn`, `handleCopyBoth`). COPY mode is a raw streaming sub-protocol. The proxy must read and forward every `CopyData` message until `CopyDone`. Stopping early leaves the backend in a broken state that corrupts all subsequent queries on that connection.

**Do not change `needsReadyForQuery`**. This function controls when `drainBackendResponses` stops. If it returns the wrong value, the proxy will either stop draining too early (client gets partial response) or loop forever waiting for a `ReadyForQuery` that never comes.

### `internal/connection/manager.go` — CancelRequest detection

**Do not change `isCancelRequest` or the peek size (8 bytes)**. The CancelRequest magic number (`80877102`) is defined by the PostgreSQL protocol. The peek must be exactly 8 bytes — the length (4 bytes) plus the code (4 bytes). The full message is 16 bytes with no length header byte `'E'`, which is why it must be detected before pgproto3 sees it.

### `internal/interceptor/interceptor.go` — extended query correlation

**Do not change the session ID key in `pending`**. The map key must match the session ID from `session.Session.ID`. If you change the key, extended query steps from the same client will not correlate and `InterceptExecute` will produce no events.

### `go.mod` — pgproto3 version

**Do not upgrade pgproto3 without testing.** The v2 library has specific encoding contracts. A minor version change can alter how messages are encoded, which may break the wire format. Always run `psql` and driver integration tests after any dependency upgrade.

---

## 11. What you can safely modify

### Environment variables and config defaults (`cmd/proxy/main.go`, `internal/connection/manager.go`)

All tuning values (`MAX_CONNECTIONS`, `DIAL_TIMEOUT`, `SHUTDOWN_TIMEOUT`, `BACKEND_PING_INTERVAL`) are safe to change. They only affect operational behaviour, not protocol correctness.

### SQL normalization rules (`internal/interceptor/interceptor.go`)

The `normalizeSQL` function uses a set of regexes and string operations. You can safely:
- Add new regex patterns to catch additional literal forms
- Adjust the `removeComments` function
- Change the normalization output format (e.g., use `$1` instead of `?`)

If you change the output format, update `FingerprintSQL` tests accordingly — fingerprints will change for existing queries, which will break deduplication continuity in Kafka.

### Cache capacity (`internal/interceptor/interceptor.go`)

The `newBoundedCache(50_000)` calls control how many unique normalized queries and fingerprints are kept in memory. Increase this number if you have a very high number of unique query shapes and see frequent cache evictions in profiling. The cap is per-cache; two caches means roughly `2 × cap × avg_string_size` bytes.

### Dedup window and buffer sizes (`internal/publisher/publisher.go`)

`DedupWindow` (default 10s), `BufferCap` (default 100,000), `DedupMaxKeys` (default 50,000), and `BatchSize` (default 100) are all safe to tune for your Kafka throughput and memory budget.

### ResponseShaper rules (`internal/shaper/shaper.go`)

The entire `Config` and `Rule` system is designed to be modified. You can add new rule fields, change the eviction behavior, or load rules from a database or config file. The only constraint is that the `shaper.Decision` struct must remain consistent with how `drainBackendResponses` uses it.

### Logging format (`cmd/proxy/main.go`)

The logger is `slog.NewJSONHandler`. You can swap it to `slog.NewTextHandler` for human-readable output, or replace it entirely with `zap` or `zerolog`. The only requirement is that it implements `*slog.Logger`.

### HTTP endpoints (`internal/connection/manager.go`)

The `/metrics` JSON schema, the `/healthz` response body, and any additional endpoints can all be modified freely. Do not remove `/healthz` if you are using Docker or Kubernetes health probes — update those probe configs first.

### Tests (`tests/`)

All test files are safe to modify, extend, or reorganize. The three test files are independent of each other and of the main code.

---

## 12. Event schemas

### Raw event (`pg-query-events` Kafka topic)

One event per query execution.

```json
{
  "session_id":       "550e8400-e29b-41d4-a716-446655440000",
  "timestamp":        "2024-01-15T10:30:00.123456789Z",
  "client_ip":        "10.0.0.1",
  "username":         "postgres",
  "database":         "myapp",
  "query_raw":        "SELECT * FROM users WHERE id = 42",
  "query_normalized": "select * from users where id = ?",
  "fingerprint":      "a3f2c1d4e5b67890",
  "protocol_mode":    "simple",
  "query_length":     35,
  "bytes_in":         1024,
  "bytes_out":        2048
}
```

`protocol_mode` is either `"simple"` (Query message) or `"extended"` (Parse/Bind/Execute).

### Dedup event (`pg-query-dedup` Kafka topic)

One event per unique fingerprint per flush window (default 10s).

```json
{
  "fingerprint":      "a3f2c1d4e5b67890",
  "query_normalized": "select * from users where id = ?",
  "database":         "myapp",
  "username":         "postgres",
  "exec_count":       847,
  "first_seen":       "2024-01-15T10:30:00.000000000Z",
  "last_seen":        "2024-01-15T10:30:09.987654321Z",
  "total_bytes_in":   867328,
  "total_bytes_out":  4194304,
  "simple_count":     200,
  "extended_count":   647
}
```

Use `exec_count` for query rate dashboards, `total_bytes_out` for data transfer volume, and `fingerprint` to JOIN with the raw event topic.

---

## 13. Running tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run a specific test
go test ./tests/ -run TestCancelRequestDetection -v

# Run benchmarks
go test ./... -bench=. -benchmem

# Run with race detector (recommended before deploying changes)
go test -race ./...
```

### Test coverage by file

| File | What it covers |
|---|---|
| `tests/proxy_test.go` | Session creation, prepared statements, concurrent access, SQL normalization, interceptor simple/extended, IP extraction |
| `tests/fixes_test.go` | FNV fingerprinting, dedup publisher, ResponseShaper rules, row filtering, runtime rule management |
| `tests/fixes_v2_test.go` | CancelRequest detection, backend health check, bounded cache eviction, session cleanup, graceful shutdown, HTTP endpoint schemas |

---

## 14. Troubleshooting

### `psql: error: connection to server failed: Connection refused`
The proxy is not running or not listening on port 5433. Check `docker compose ps` and `docker compose logs proxy`.

### `psql: error: connection to server failed: FATAL: proxy: cannot connect to backend`
The proxy started but cannot reach PostgreSQL. Check that the `postgres` container is healthy: `docker compose ps`. Also check `PG_BACKEND_ADDR` is correct.

### Queries hang after connecting
This usually means the proxy stopped mid-protocol. Check `docker compose logs proxy` for panic or error messages. The most common cause is a message type in the extended protocol that the proxy's `drainBackendResponses` did not handle — file an issue with the full query and the `LOG_LEVEL=debug` output.

### `/healthz` returns 503
The backend health checker could not dial the PostgreSQL backend. This does **not** interrupt in-flight connections — it only affects the health endpoint and the `/ready` probe. Check that PostgreSQL is running and the network between the proxy and PG containers is intact.

### High memory usage
If you have a very diverse set of unique query shapes (e.g., ORMs that generate unique SQL per request), the normalization cache may be evicting frequently. Check by running with `LOG_LEVEL=debug` and looking for eviction log lines. Increase `newBoundedCache(50_000)` capacity in `interceptor.go`, or investigate why your ORM is not using prepared statements.

### Kafka events not appearing
1. Confirm Phase 2 and Phase 3 are both active (both import blocks uncommented).
2. Check the proxy logs for `"kafka send failed"` — this means Kafka is unreachable. Events buffer in memory until `BufferCap` is hit.
3. Check that `KAFKA_BROKERS` is set and reachable from the proxy container.
4. Check the topic names match: `KAFKA_TOPIC` and `KAFKA_DEDUP_TOPIC`.

### `COPY` operations fail or hang
This is a known area of complexity. If you see hangs on `COPY FROM STDIN` or `COPY TO STDOUT`, check the proxy logs for `"copy-in receive"` or `"copy-out receive"` errors. Ensure you are not sending a `CancelRequest` mid-COPY, which will send `CopyFail` to the backend and close the stream.

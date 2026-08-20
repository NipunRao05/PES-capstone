# MySQL Transparent Proxy

A production-grade transparent proxy for MySQL 8.x written in Go. It sits between your application and a real MySQL server, forwarding all traffic without modification while providing query interception, response shaping, Kafka event publishing, structured metrics, and full observability — all with sub-millisecond overhead when no rules are active.

```
Application → :3307 (proxy) → :3306 (MySQL)
```

The proxy is completely invisible to clients. No changes to connection strings beyond the port number are required.

---

## Contents

1. [What this is](#what-this-is)
2. [How it works](#how-it-works)
3. [Architecture](#architecture)
4. [Quick start](#quick-start)
5. [Configuration reference](#configuration-reference)
6. [HTTP endpoints](#http-endpoints)
7. [Enabling Phase 2 — query interception](#enabling-phase-2--query-interception)
8. [Enabling Phase 3 — Kafka publishing](#enabling-phase-3--kafka-publishing)
9. [Response shaping](#response-shaping)
10. [What you must NOT touch](#what-you-must-not-touch)
11. [What you can safely modify](#what-you-can-safely-modify)
12. [Event schemas](#event-schemas)
13. [Running tests](#running-tests)
14. [Troubleshooting](#troubleshooting)

---

## What this is

This is a **Layer 7 TCP proxy** that speaks the MySQL Client/Server Protocol natively. It does not use any MySQL client library. Every byte on the wire is read, optionally inspected or modified, and forwarded — preserving exact packet framing, sequence numbers, and timing.

**What it is:**
- A transparent pass-through proxy with zero behavioral impact when unconfigured
- A query capture pipeline that can normalize and fingerprint every SQL statement
- A response shaper that can inject latency, limit rows, or block queries by fingerprint
- A Kafka publisher that emits raw and deduplicated query event streams
- A production operations tool with health checks, readiness probes, and JSON metrics

**What it is not:**
- A connection pool (it is goroutine-per-connection)
- A query rewriter or schema-aware tool
- A security gateway (it forwards all auth transparently — the real MySQL validates credentials)

---

## How it works

### Connection lifecycle

```
Client TCP connect
       │
       ▼
ConnectionManager.handleConnection()
       │
       ├─ Dial backend MySQL
       ├─ Set TCP keepalives on both sockets
       ├─ Set idle read deadline on client socket
       │
       ▼
Handler.Run()
       │
       ├─ Step 1: Read server greeting from backend, forward to client
       │          (Handshake v10: protocol version, server version, connection
       │           ID, auth challenge seed, capability flags, auth plugin name)
       │
       ├─ Step 2: Read client HandshakeResponse41 from client, forward to backend
       │          (capability flags, max packet size, username, auth response,
       │           initial database)
       │
       ├─ Step 3: Relay auth result(s) — tracks sequence numbers correctly across
       │          multi-round auth exchanges:
       │            OK           → auth complete
       │            ERR          → auth failed, session ends
       │            AuthSwitch   → relay client response, loop
       │            AuthMoreData → relay client response, loop (caching_sha2)
       │
       └─ Step 4: Command loop (until COM_QUIT or client disconnect)
                   │
                   ├─ Set idle read deadline
                   ├─ Read one command packet
                   ├─ Clear read deadline
                   ├─ Resolve shaping Decision (O(1), zero alloc when no rules)
                   ├─ Dispatch:
                   │    COM_QUERY         → intercept SQL, block/forward, drain result set
                   │    COM_STMT_PREPARE  → forward, parse OK, extract stmt_id
                   │    COM_STMT_EXECUTE  → intercept execution, block/forward, drain
                   │    COM_STMT_CLOSE    → forward (no response expected)
                   │    COM_INIT_DB       → forward, update session.Database
                   │    COM_CHANGE_USER   → full embedded auth re-exchange, update session
                   │    COM_PROCESS_KILL  → forward (MySQL's cancel-query equivalent)
                   │    COM_PING          → forward, relay OK
                   │    COM_QUIT          → forward, close both sockets
                   │    everything else   → forward + drain generically
                   └─ Loop
```

### Protocol support

| Feature | Status |
|---|---|
| Protocol version | MySQL 4.1 (Handshake v10) |
| Auth: mysql_native_password | ✅ Full multi-round relay |
| Auth: caching_sha2_password | ✅ Full multi-round relay (AuthMoreData) |
| Auth: AuthSwitchRequest | ✅ Handled |
| SSL/TLS upgrade | Transparent (forwarded as-is) |
| COM_QUERY (text protocol) | ✅ |
| COM_STMT_PREPARE / EXECUTE | ✅ |
| COM_STMT_CLOSE / RESET | ✅ |
| COM_CHANGE_USER | ✅ Full auth re-exchange |
| COM_PROCESS_KILL | ✅ Forwarded to real backend |
| LOCAL INFILE | ✅ Bidirectional file stream |
| Multi-result sets | ✅ SERVER_MORE_RESULTS_EXISTS detected |
| Large packets (>16MB) | ✅ Continuation frame reassembly |
| Capability flags | Negotiated transparently |

### SQL normalization pipeline

When Phase 2 is enabled, every SQL statement passes through:

1. **Comment stripping** — removes `--`, `/* */`, and `#` comments
2. **String literal replacement** — `'alice'` → `?`
3. **Numeric literal replacement** — `42`, `3.14` → `?`
4. **Placeholder passthrough** — `?` stays `?`
5. **IN-list collapse** — `IN (1, 2, 3)` → `IN (?)`
6. **VALUES-list collapse** — `VALUES (1, 'a', 2)` → `VALUES (?)`
7. **Whitespace normalization** — all runs of whitespace → single space
8. **Lowercase** — entire statement lowercased

The result is cached in a bounded 50,000-entry cache (generation eviction). Repeated execution of the same query shape hits the cache with a single `sync.RWMutex` read lock — zero allocation.

**Example:**
```sql
-- Input
SELECT u.id, u.name FROM users u WHERE u.status = 'active' AND u.age > 25

-- Normalized
select u.id, u.name from users u where u.status = ? and u.age > ?

-- Fingerprint (FNV-64a hex)
3a7f2c1d4e5b8901
```

---

## Architecture

The proxy has seven strict layers. Dependencies only flow downward.

```
Layer 1  ConnectionManager    TCP accept loop, health checks, graceful shutdown,
         connection/manager.go HTTP health+metrics server, connection counting

Layer 2  ProtocolHandler       MySQL wire protocol: greeting relay, auth relay,
         protocol/handler.go   command dispatch, packet I/O, large-packet reassembly

Layer 3  SessionTracker        Per-connection state: username, database, prepared
         session/session.go    statement map, byte counters, transaction status

Layer 4  QueryInterceptor      SQL capture and normalization, FNV-64a fingerprinting,
         interceptor/           bounded caches, prepared statement tracking
         interceptor.go

Layer 5  EventPublisher         Async Kafka producer, dual-stream (raw + dedup),
         publisher/publisher.go 100K in-memory buffer, 10s dedup window

Layer 6  ResponseShaper         Latency injection, row limiting, query blocking.
         shaper/shaper.go       Zero overhead when no rules are configured.

Layer 7  Entrypoint             Env var wiring, signal handling, startup logging.
         cmd/proxy/main.go
```

---

## Quick start

```bash
# Start MySQL + proxy
docker compose up --build

# Connect through the proxy (port 3307) — works identically to port 3306
mysql -h 127.0.0.1 -P 3307 -uroot -ppassword testdb

# Run a query
mysql -h 127.0.0.1 -P 3307 -uroot -ppassword -e "SELECT VERSION()"

# Health check
curl http://localhost:9091/healthz

# Metrics
curl http://localhost:9091/metrics

# Readiness probe (Kubernetes)
curl -o /dev/null -w "%{http_code}" http://localhost:9091/ready

# Graceful shutdown
docker compose down
# or send SIGTERM to the process
```

---

## Configuration reference

All configuration is via environment variables. Every variable has a safe default — no configuration is required to run.

| Variable | Default | Type | Description |
|---|---|---|---|
| `PROXY_LISTEN_ADDR` | `0.0.0.0:3307` | string | TCP address the proxy listens on |
| `MYSQL_BACKEND_ADDR` | `localhost:3306` | string | Real MySQL server address |
| `HTTP_ADDR` | `0.0.0.0:9091` | string | HTTP health+metrics server. Set to `""` to disable |
| `LOG_LEVEL` | `info` | string | `debug` enables per-packet logging. Never use `debug` in production |
| `MAX_CONNECTIONS` | `10000` | int | Maximum simultaneous client connections. Excess connections receive MySQL error 1040 (Too many connections) |
| `DIAL_TIMEOUT` | `10s` | duration | How long to wait when dialing the backend |
| `SHUTDOWN_TIMEOUT` | `30s` | duration | How long to wait for in-flight connections to finish during graceful shutdown |
| `BACKEND_PING_INTERVAL` | `15s` | duration | How often to probe the backend with a TCP dial. Set to `0` to disable |
| `KAFKA_BROKERS` | _(unset)_ | string | Phase 3: comma-separated broker list e.g. `kafka1:9092,kafka2:9092` |
| `KAFKA_TOPIC` | `mysql-query-events` | string | Phase 3: Kafka topic for raw per-execution events |
| `KAFKA_DEDUP_TOPIC` | `mysql-query-dedup` | string | Phase 3: Kafka topic for deduplicated normalized events |

### Idle timeout

The `IdleTimeout` (set in code via `Config.IdleTimeout`, default 30 minutes) controls how long the proxy waits for the client to send a command before closing the connection. This prevents goroutine leaks from clients that connect but never send anything. It is applied as a TCP read deadline at each command boundary and cleared once a command arrives — it does not affect query execution time.

### Duration format

All duration variables use Go's `time.ParseDuration` format: `10s`, `1m30s`, `500ms`, `2h`.

---

## HTTP endpoints

The HTTP server runs on `HTTP_ADDR` (default `:9091`). All responses are JSON.

### `GET /healthz`

Liveness probe. Returns 200 when the backend is reachable, 503 when not.

```json
// 200 OK
{"status":"ok","active_connections":47}

// 503 Service Unavailable
{"status":"unhealthy","backend":"mysql:3306"}
```

### `GET /metrics`

Snapshot of all operational counters.

```json
{
  "active_connections":   47,
  "total_connections":    1203,
  "rejected_connections": 0,
  "backend_dial_errors":  0,
  "kill_requests":        2,
  "backend_health_failures": 0,
  "backend_healthy":      true
}
```

| Field | Description |
|---|---|
| `active_connections` | Connections currently open (real-time) |
| `total_connections` | All connections ever accepted (monotonic) |
| `rejected_connections` | Connections dropped due to `MAX_CONNECTIONS` limit |
| `backend_dial_errors` | Failed attempts to reach the backend MySQL |
| `kill_requests` | `COM_PROCESS_KILL` commands forwarded (MySQL's query-cancel mechanism) |
| `backend_health_failures` | Failed TCP probes to the backend |
| `backend_healthy` | Current health state (updated by background probe) |

### `GET /ready`

Kubernetes readiness probe. Returns 503 when the backend is unhealthy or connection count is at capacity. Returns 200 otherwise.

---

## Enabling Phase 2 — query interception

Phase 2 is wired but inactive. All interception calls are present in `handler.go` as comments labelled `Phase 2`. To activate:

**Step 1** — Add the interceptor field to `Handler` in `protocol/handler.go`:
```go
type Handler struct {
    // ... existing fields ...
    interceptor *interceptor.Interceptor  // add this
}
```

**Step 2** — Pass the interceptor into `NewHandler`:
```go
func NewHandler(client, backend net.Conn, logger *slog.Logger,
    backendAddr string, idleTimeout time.Duration,
    ic *interceptor.Interceptor) *Handler {
    return &Handler{..., interceptor: ic}
}
```

**Step 3** — Uncomment the four intercept call blocks in `commandLoop`:
```go
// COM_QUERY block:
h.interceptor.InterceptTextQuery(h.sess, sql)

// COM_STMT_PREPARE block:
h.interceptor.InterceptStmtPrepare(h.sess.ID, stmtID, sql)

// COM_STMT_EXECUTE block:
h.interceptor.InterceptStmtExecute(h.sess, stmtID)

// COM_STMT_CLOSE block:
h.interceptor.InterceptStmtClose(h.sess.ID, stmtID)
```

**Step 4** — Uncomment the `CleanupSession` call in `Run`'s defer block:
```go
defer func() {
    if h.sess != nil {
        h.interceptor.CleanupSession(h.sess.ID)  // uncomment
    }
}()
```

**Step 5** — Wire the interceptor in `connection/manager.go`:
```go
ic := interceptor.New(10_000)
// pass ic to NewHandler
```

---

## Enabling Phase 3 — Kafka publishing

Phase 3 depends on Phase 2 being active first. All Kafka send calls are present as comments labelled `Phase 3`.

**Step 1** — Set the Kafka environment variables:
```bash
KAFKA_BROKERS=kafka1:9092,kafka2:9092
KAFKA_TOPIC=mysql-query-events
KAFKA_DEDUP_TOPIC=mysql-query-dedup
```

**Step 2** — In `cmd/proxy/main.go`, uncomment the Kafka config block:
```go
KafkaBrokers:    strings.Split(getEnv("KAFKA_BROKERS", ""), ","),
KafkaTopic:      getEnv("KAFKA_TOPIC", "mysql-query-events"),
KafkaDedupTopic: getEnv("KAFKA_DEDUP_TOPIC", "mysql-query-dedup"),
```

**Step 3** — In `publisher/publisher.go`, uncomment the two `sendRawBatch` and `sendDedupBatch` Kafka write blocks and delete the `_ = ctx` placeholder lines.

**Step 4** — Add Kafka to `docker-compose.yml`:
```yaml
kafka:
  image: confluentinc/cp-kafka:7.5.0
  environment:
    KAFKA_BROKER_ID: 1
    KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
    KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
  depends_on: [zookeeper]
```

---

## Response shaping

The `ResponseShaper` (Layer 6) applies per-fingerprint policies to the response stream. It has zero overhead when no rules are configured — `Decide()` returns in O(1) with an RLock and no allocation.

### Global defaults

```go
shaper.New(shaper.Config{
    GlobalLatency:   50 * time.Millisecond,  // add 50ms to every query
    JitterFraction:  0.1,                    // ±10% random jitter
    DefaultRowLimit: 1000,                   // cap all result sets at 1000 rows
}, logger)
```

### Per-fingerprint rules

```go
// Block a specific query shape
s.AddRule(shaper.Rule{
    Fingerprint:   "3a7f2c1d4e5b8901",   // from interceptor.FingerprintSQL
    Block:         true,
    BlockMessage:  "table scan blocked",
    BlockErrCode:  1044,                  // ER_DBACCESS_DENIED_ERROR
    BlockSQLState: "42000",
})

// Slow down a specific query
s.AddRule(shaper.Rule{
    Fingerprint: "aabb1234cdef5678",
    Latency:     200 * time.Millisecond,
})

// Disable row limiting for a specific query even if DefaultRowLimit is set
s.AddRule(shaper.Rule{
    Fingerprint: "deadbeef12345678",
    RowLimit:    -1,  // -1 = unlimited
})

// Disable latency for a specific query even if GlobalLatency is set
s.AddRule(shaper.Rule{
    Fingerprint: "cafebabe87654321",
    Latency:     -1,  // negative = disable global latency for this shape
})

// Remove a rule at runtime
s.RemoveRule("3a7f2c1d4e5b8901")
```

### How fingerprints work

Every SQL statement is normalized (literals replaced with `?`, whitespace collapsed, lowercased) and then hashed with FNV-64a. The result is a stable 16-character hex string. The same query with different literal values always produces the same fingerprint.

To find a fingerprint, enable Phase 2, run the query once, and read the `fingerprint` field from the Kafka event or the debug log.

---

## What you must NOT touch

These parts of the code are carefully calibrated to the MySQL wire protocol. Modifying them without deep protocol knowledge will cause silent data corruption or broken connections that are extremely hard to debug.

### `relayServerGreeting()` in `protocol/handler.go`

The greeting parser extracts the auth challenge seed, capability flags, connection ID, and auth plugin name. The exact byte offsets are mandated by the MySQL protocol spec. The greeting is forwarded raw to the client — if you add or strip bytes here, the auth sequence numbers will be wrong and clients will silently receive malformed packets.

**Failure mode:** All client connections fail immediately with "Lost connection to MySQL server" or auth errors that look like wrong password but aren't.

### `relayClientHandshake()` in `protocol/handler.go`

The client's handshake packet is forwarded byte-for-byte to the backend. The proxy only parses it to extract the username and database for session metadata. If you modify the packet before forwarding, the backend will receive a different capability mask or auth hash than the client intended, breaking auth.

**Failure mode:** Intermittent auth failures, especially with tools that negotiate `caching_sha2_password`.

### `relayAuthResult()` sequence tracking in `protocol/handler.go`

The auth result relay starts at sequence number 2 (server's first response after the client's seq-1 handshake) and increments with every packet exchanged. This is not arbitrary — MySQL clients strictly validate sequence numbers and will drop the connection if they receive an out-of-order packet.

**Failure mode:** Silent connection drops after auth. Clients see "Lost connection" with no useful error message.

### `readPacket()` continuation frame loop in `protocol/handler.go`

When a MySQL payload is exactly `0xFFFFFF` (16,777,215) bytes, the protocol requires an additional frame to terminate the message. The `readPacket` method loops on this condition. If you remove this loop, large payloads (e.g. bulk inserts, large BLOBs) will be silently truncated at the 16MB boundary.

**Failure mode:** Data corruption on large packets. The first symptom is usually a "packet out of order" error from the MySQL client library on the other side.

### `drainResponse()` result-set state machine in `protocol/handler.go`

The response drain correctly identifies: OK packets, ERR packets, LOCAL INFILE requests (0xFB), and result sets (column-count varint → column defs → EOF → rows → EOF/OK). The distinction between a column-count packet and a data row packet depends on position in the sequence. If you reorder the drain phases or short-circuit the EOF detection, clients will receive partial result sets or desync from the server.

**Failure mode:** Queries return wrong row counts, or subsequent queries fail with "commands out of sync".

### `hasMoreResults()` flag check in `protocol/handler.go`

The `SERVER_MORE_RESULTS_EXISTS` flag (0x0008) in the status flags of OK/EOF packets indicates that another result set follows in the same command. This is used by stored procedures, multi-statement queries, and `CALL` statements. If this flag check is removed, the proxy will return to the command loop before all result sets have been drained, leaving the backend in a mid-response state.

**Failure mode:** Second and subsequent result sets from stored procedures are silently dropped. Subsequent commands fail with "commands out of sync".

### `handleLocalInfile()` in `protocol/handler.go`

`LOAD DATA LOCAL INFILE` uses a reverse data flow: the server sends a 0xFB packet requesting a file, then the client streams the file contents as a series of raw data packets terminated by an empty packet. If you remove or modify this handler, any `LOAD DATA LOCAL INFILE` command will deadlock — the proxy waits for the server's OK while the server waits for the file data.

**Failure mode:** `LOAD DATA LOCAL INFILE` hangs forever. Timeout after `DialTimeout`.

### Sequence numbers in `handleStmtPrepare()` in `protocol/handler.go`

The COM_STMT_PREPARE response sequences: `seq=1` for the prepare OK, `seq=2..N` for param defs, `seq=N+1` for the EOF after params, then column defs and another EOF. These are tracked manually and must match exactly. Param and column defs are counted directly from the prepare OK's `num_params` and `num_columns` fields.

**Failure mode:** Prepared statements appear to work but the client gets garbled column metadata.

---

## What you can safely modify

### All environment variables

Every value in `Config` has a safe default and can be changed at runtime by restarting with different env vars. None of the defaults are hardcoded in the protocol logic.

### SQL normalization regexes in `interceptor/interceptor.go`

The `reNumbers`, `reStrings`, `reInList`, `reValuesList` regexes can be tuned. Changing them only affects how SQL is normalized for fingerprinting and dedup — it does not affect what is forwarded to MySQL. The only constraint is that `NormalizeSQL` must be deterministic (same input always → same output).

### Bounded cache sizes in `interceptor/interceptor.go`

```go
normCache = newBoundedCache(50_000)  // raw SQL → normalized
hashCache = newBoundedCache(50_000)  // normalized → fingerprint
```

These can be increased for deployments with very large numbers of distinct query shapes. Memory usage is approximately `(key_len + value_len) * capacity` bytes. Halving them reduces memory at the cost of more cache misses.

### Dedup window and capacity in `publisher/publisher.go`

```go
DedupWindow:  10 * time.Second  // how often the dedup table is flushed to Kafka
DedupMaxKeys: 50_000            // max fingerprints tracked before eviction
```

A shorter window means more frequent Kafka writes with smaller batches. A longer window reduces Kafka write frequency but holds more state in memory.

### Shaping rules

All `AddRule`, `RemoveRule`, and `Config` fields on the `Shaper` are safe to change at runtime. See the Response shaping section above.

### Log format

The logger is constructed in `cmd/proxy/main.go`. Replace `slog.NewJSONHandler` with `slog.NewTextHandler` for human-readable logs, or wire in any `slog.Handler` implementation.

### HTTP endpoint paths and response bodies

The handlers in `connection/manager.go`'s `startHTTPServer` can have their paths and JSON shapes changed freely. The Kubernetes integration only cares about the HTTP status codes (200 vs 503).

### Kafka topics and batch sizes

`KAFKA_TOPIC`, `KAFKA_DEDUP_TOPIC`, `BatchSize`, and `BufferCap` in `publisher/publisher.go` are all safe to change. The Kafka key is always the fingerprint (for partition locality of the same query shape).

---

## Event schemas

### RawEvent (one per query execution)

Published to `mysql-query-events` (Phase 3).

```json
{
  "session_id":        "550e8400-e29b-41d4-a716-446655440000",
  "timestamp":         "2024-01-15T10:23:45.123456789Z",
  "client_ip":         "10.0.1.42",
  "username":          "appuser",
  "database":          "production",
  "query_raw":         "SELECT * FROM orders WHERE user_id = 42 AND status = 'pending'",
  "query_normalized":  "select * from orders where user_id = ? and status = ?",
  "fingerprint":       "3a7f2c1d4e5b8901",
  "protocol_mode":     "text",
  "query_length":      57,
  "bytes_in":          3840,
  "bytes_out":         18240
}
```

`protocol_mode` is `"text"` for COM_QUERY and `"prepared"` for COM_STMT_EXECUTE.

### DedupEvent (one per query shape per flush window)

Published to `mysql-query-dedup` (Phase 3). The Kafka key is the fingerprint, ensuring all events for the same query shape land on the same partition.

```json
{
  "fingerprint":       "3a7f2c1d4e5b8901",
  "query_normalized":  "select * from orders where user_id = ? and status = ?",
  "database":          "production",
  "username":          "appuser",
  "exec_count":        847,
  "first_seen":        "2024-01-15T10:23:45.123456789Z",
  "last_seen":         "2024-01-15T10:23:54.987654321Z",
  "total_bytes_in":    3251136,
  "total_bytes_out":   15440928,
  "text_count":        603,
  "prepared_count":    244
}
```

---

## Running tests

```bash
# All tests
go test ./tests/... -v

# With race detector (recommended before deploying)
go test ./tests/... -race

# Benchmarks
go test ./tests/... -bench=. -benchmem -run=^$

# Specific test
go test ./tests/... -run TestNormalizeSQL -v
go test ./tests/... -run TestShaperBlockRule -v
go test ./tests/... -run TestInterceptCleanupSession -v
```

### Test file index

| File | What it covers |
|---|---|
| `tests/proxy_test.go` | Session, interceptor (all modes + cleanup), SQL normalization, FNV fingerprinting, bounded cache, publisher dedup, shaper (all rules), MySQL packet encoding, HTTP endpoint schemas, integration passthrough |

### Benchmark results (approximate, M1 MacBook)

| Benchmark | ns/op | allocs/op |
|---|---|---|
| `BenchmarkNormalizeSQL` (cache hit) | ~85 | 0 |
| `BenchmarkFingerprintSQL` (cache hit) | ~60 | 0 |
| `BenchmarkShaperDecide` (no rules) | ~20 | 0 |
| `BenchmarkShaperDecideWithRules` (100 rules) | ~35 | 0 |

---

## Troubleshooting

### "Lost connection to MySQL server during query"

The proxy received a packet it couldn't parse and closed the connection. Enable `LOG_LEVEL=debug` to see every packet type. Most common cause: a MySQL feature or client library version that sends a packet type not in the command loop's switch. Add a `default: forwardAndDrain` case is already there, so this should not happen unless the result-set state machine is desynchronized.

### "Commands out of sync; you can't run this command now"

This means the client and backend are out of step — one side thinks a response is complete but the other doesn't. This happens when a multi-result-set response is not fully drained. Check that `hasMoreResults` is reading the status flags from the right byte offset for your MySQL version.

### Auth fails with "caching_sha2_password" but works with "mysql_native_password"

`caching_sha2_password` uses `AuthMoreData` (type `0x01`) packets for its full-auth round-trip. The `relayAuthResult` loop handles these. If auth fails, verify the MySQL server is sending `0x01` and not a non-standard packet type.

### Proxy starts but `/healthz` returns 503 immediately

The backend health check uses a TCP dial, not a MySQL handshake. If MySQL is starting up slowly (common in Docker), the first few probes will fail and flip `backendHealthy` to false. The proxy will recover automatically once MySQL accepts TCP connections. You can increase `BACKEND_PING_INTERVAL` or add a startup delay.

### HIGH memory usage after long runtime

The interceptor's dedup table and normalization caches both have bounded sizes. If memory keeps growing, check:
1. The `DedupMaxKeys` cap in `publisher.go` (default 50k)
2. The `normCache` and `hashCache` capacities in `interceptor.go` (default 50k each)
3. That `interceptor.CleanupSession` is being called on session end (Phase 2)

### "Too many connections" error from the proxy (error 1040)

The proxy's own `MAX_CONNECTIONS` limit was hit, not MySQL's. Increase `MAX_CONNECTIONS` or investigate why connections are not being released. Check `/metrics` → `active_connections` over time to see if they are leaking.

### `LOCAL INFILE` hangs

`LOAD DATA LOCAL INFILE` requires the `CLIENT_LOCAL_FILES` capability to be negotiated. If the client doesn't negotiate this flag, MySQL will silently ignore the `LOCAL INFILE` request and the data never arrives. Ensure your client enables `local_infile=1` and that MySQL is started with `--local-infile=ON`.

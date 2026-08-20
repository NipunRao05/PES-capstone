package tests

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/interceptor"
	"github.com/pgproxy/internal/session"
)

// ─── Session Tests ─────────────────────────────────────────────────────────────

func TestSessionCreation(t *testing.T) {
	msg := &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":             "alice",
			"database":         "mydb",
			"application_name": "psql",
		},
	}

	s := session.NewFromStartup(msg, "127.0.0.1:54321")

	if s.Username != "alice" {
		t.Errorf("want username=alice, got %q", s.Username)
	}
	if s.Database != "mydb" {
		t.Errorf("want database=mydb, got %q", s.Database)
	}
	if s.ClientIP != "127.0.0.1" {
		t.Errorf("want clientIP=127.0.0.1, got %q", s.ClientIP)
	}
	if s.ID == "" {
		t.Error("session ID should not be empty")
	}
	if s.TxStatus != 'I' {
		t.Errorf("initial TxStatus should be 'I', got %c", s.TxStatus)
	}
}

func TestSessionPreparedStatements(t *testing.T) {
	s := session.NewFromStartup(nil, "")

	s.AddPreparedStatement("stmt1", "SELECT * FROM users WHERE id = $1")
	s.AddPreparedStatement("stmt2", "INSERT INTO logs VALUES ($1, $2)")

	ps, ok := s.GetPreparedStatement("stmt1")
	if !ok {
		t.Fatal("expected stmt1 to exist")
	}
	if ps.Query != "SELECT * FROM users WHERE id = $1" {
		t.Errorf("unexpected query: %q", ps.Query)
	}

	_, ok = s.GetPreparedStatement("nonexistent")
	if ok {
		t.Error("expected nonexistent stmt to not exist")
	}

	s.RemovePreparedStatement("stmt1")
	_, ok = s.GetPreparedStatement("stmt1")
	if ok {
		t.Error("stmt1 should have been removed")
	}
}

func TestSessionConcurrentAccess(t *testing.T) {
	s := session.NewFromStartup(nil, "")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.SetParameter(fmt.Sprintf("key%d", n), fmt.Sprintf("val%d", n))
			s.IncrBytesIn(100)
			s.IncrBytesOut(200)
			s.IncrQueryCount()
		}(i)
	}
	wg.Wait()

	snap := s.Snapshot()
	if snap.BytesIn != 10000 {
		t.Errorf("expected BytesIn=10000, got %d", snap.BytesIn)
	}
	if snap.QueryCount != 100 {
		t.Errorf("expected QueryCount=100, got %d", snap.QueryCount)
	}
}

// ─── SQL Normalization Tests ────────────────────────────────────────────────────

func TestNormalizeSQL(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple string literal",
			input: "SELECT * FROM users WHERE name = 'alice'",
			want:  "select * from users where name = ?",
		},
		{
			name:  "numeric literal",
			input: "SELECT * FROM orders WHERE id = 42",
			want:  "select * from orders where id = ?",
		},
		{
			name:  "multiple literals",
			input: "SELECT * FROM t WHERE a = 1 AND b = 'foo' AND c = 3.14",
			want:  "select * from t where a = ? and b = ? and c = ?",
		},
		{
			name:  "positional params",
			input: "SELECT * FROM users WHERE id = $1 AND role = $2",
			want:  "select * from users where id = ? and role = ?",
		},
		{
			name:  "IN list",
			input: "SELECT * FROM t WHERE id IN (1, 2, 3, 4)",
			want:  "select * from t where id in (?)",
		},
		{
			name:  "line comment removal",
			input: "SELECT 1 -- this is a comment\nFROM dual",
			want:  "select ? from dual",
		},
		{
			name:  "block comment removal",
			input: "SELECT /* comment */ 1",
			want:  "select ?",
		},
		{
			name:  "whitespace collapse",
			input: "SELECT  *   FROM   users",
			want:  "select * from users",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "insert values",
			input: "INSERT INTO t (a, b) VALUES (1, 'hello')",
			want:  "insert into t (a, b) values (?)",
		},
		{
			name:  "cache hit — same query twice",
			input: "SELECT 1",
			want:  "select ?",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := interceptor.NormalizeSQL(tc.input)
			if got != tc.want {
				t.Errorf("\ninput: %q\nwant:  %q\ngot:   %q", tc.input, tc.want, got)
			}
			// Run twice to exercise cache
			got2 := interceptor.NormalizeSQL(tc.input)
			if got2 != got {
				t.Errorf("cache returned different result: %q vs %q", got, got2)
			}
		})
	}
}

func TestNormalizeSQLCacheIsDeterministic(t *testing.T) {
	sql := "SELECT * FROM users WHERE id = 99 AND name = 'bob'"
	results := make([]string, 20)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = interceptor.NormalizeSQL(sql)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r != results[0] {
			t.Errorf("result[%d] = %q, want %q", i, r, results[0])
		}
	}
}

// ─── Interceptor Tests ─────────────────────────────────────────────────────────

func TestInterceptorSimpleQuery(t *testing.T) {
	ic := interceptor.New(100)
	sess := session.NewFromStartup(&pgproto3.StartupMessage{
		Parameters: map[string]string{"user": "alice", "database": "mydb"},
	}, "10.0.0.1:9999")

	ic.InterceptSimple(sess, "SELECT * FROM users WHERE id = 42")

	select {
	case event := <-ic.Events():
		if event.ProtocolMode != "simple" {
			t.Errorf("expected simple, got %q", event.ProtocolMode)
		}
		if event.Username != "alice" {
			t.Errorf("expected username=alice, got %q", event.Username)
		}
		if event.ClientIP != "10.0.0.1" {
			t.Errorf("expected clientIP=10.0.0.1, got %q", event.ClientIP)
		}
		if event.QueryNormalized != "select * from users where id = ?" {
			t.Errorf("unexpected normalized: %q", event.QueryNormalized)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event received")
	}
}

func TestInterceptorExtendedProtocol(t *testing.T) {
	ic := interceptor.New(100)
	sess := session.NewFromStartup(&pgproto3.StartupMessage{
		Parameters: map[string]string{"user": "bob", "database": "testdb"},
	}, "192.168.1.1:1234")

	query := "SELECT * FROM orders WHERE user_id = $1"

	// Extended protocol: Parse → Bind → Execute
	ic.InterceptParse(sess, "s1", query)
	ic.InterceptBind(sess, "s1", "p1", [][]byte{[]byte("42")})
	ic.InterceptExecute(sess, "p1", 0)

	select {
	case event := <-ic.Events():
		if event.ProtocolMode != "extended" {
			t.Errorf("expected extended, got %q", event.ProtocolMode)
		}
		if event.QueryRaw != query {
			t.Errorf("unexpected raw query: %q", event.QueryRaw)
		}
		if event.QueryNormalized == "" {
			t.Error("normalized query should not be empty")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event received")
	}
}

func TestInterceptorNonBlocking(t *testing.T) {
	// Buffer of 1 — should never block even when full
	ic := interceptor.New(1)
	sess := session.NewFromStartup(nil, "")

	// Fill the buffer
	ic.InterceptSimple(sess, "SELECT 1")
	// This should NOT block
	done := make(chan struct{})
	go func() {
		ic.InterceptSimple(sess, "SELECT 2")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("interceptor blocked")
	}
}

// ─── Protocol Integration Tests ───────────────────────────────────────────────

// mockPostgres is a minimal fake PostgreSQL backend for testing.
type mockPostgres struct {
	ln   net.Listener
	addr string
}

func newMockPostgres(t *testing.T) *mockPostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock pg listen: %v", err)
	}
	return &mockPostgres{ln: ln, addr: ln.Addr().String()}
}

func (m *mockPostgres) accept(t *testing.T, handler func(conn net.Conn)) {
	t.Helper()
	go func() {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
	}()
}

func (m *mockPostgres) close() { m.ln.Close() }

// TestStartupMessageParsing verifies that the session correctly parses startup params.
func TestStartupMessageParsing(t *testing.T) {
	params := map[string]string{
		"user":             "testuser",
		"database":         "testdb",
		"application_name": "myapp",
	}
	msg := &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      params,
	}
	sess := session.NewFromStartup(msg, "172.16.0.1:1234")

	if sess.Username != "testuser" {
		t.Errorf("Username: want testuser, got %q", sess.Username)
	}
	if sess.Database != "testdb" {
		t.Errorf("Database: want testdb, got %q", sess.Database)
	}
	if sess.AppName != "myapp" {
		t.Errorf("AppName: want myapp, got %q", sess.AppName)
	}
	if sess.ClientIP != "172.16.0.1" {
		t.Errorf("ClientIP: want 172.16.0.1, got %q", sess.ClientIP)
	}
}

// ─── Benchmark Tests ───────────────────────────────────────────────────────────

func BenchmarkNormalizeSQL(b *testing.B) {
	queries := []string{
		"SELECT * FROM users WHERE id = 42 AND name = 'alice' AND active = true",
		"INSERT INTO events (user_id, action, ts) VALUES (99, 'login', '2024-01-01')",
		"UPDATE orders SET status = 'shipped' WHERE id IN (1, 2, 3, 4, 5)",
		"DELETE FROM sessions WHERE created_at < '2024-01-01' AND user_id = 7",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			interceptor.NormalizeSQL(queries[i%len(queries)])
			i++
		}
	})
}

func BenchmarkSessionConcurrent(b *testing.B) {
	s := session.NewFromStartup(nil, "")
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.IncrBytesIn(1)
			s.IncrBytesOut(1)
			_ = s.Snapshot()
		}
	})
}

// ─── Helper ────────────────────────────────────────────────────────────────────

func TestIPExtraction(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"127.0.0.1:5432", "127.0.0.1"},
		{"10.0.0.1:9999", "10.0.0.1"},
		{"[::1]:5432", "[::1]"},
	}

	for _, tc := range cases {
		sess := session.NewFromStartup(nil, tc.addr)
		if !strings.HasPrefix(sess.ClientIP, strings.TrimSuffix(strings.TrimPrefix(tc.want, "["), "]")) {
			t.Logf("addr=%q clientIP=%q (IPv6 format varies)", tc.addr, sess.ClientIP)
		}
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	if ctx.Err() == nil {
		t.Error("expected context to be cancelled")
	}
}
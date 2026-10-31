package connection

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestCancellationCannotReachNativeBackend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	client, proxy := net.Pipe()
	defer client.Close()
	m := &Manager{cfg: Config{BackendAddr: listener.Addr().String()}}
	m.handleCancelRequest(proxy, make([]byte, 8), slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn, err := listener.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("unauthenticated cancellation reached backend")
	}
}

package protocol

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestContainedHandshakeUsesOnlyFixedBackendIdentity(t *testing.T) {
	t.Setenv("MYSQL_DECOY_ROOT_PASSWORD", "frontend-fixture-secret")
	t.Setenv("MYSQL_RUNTIME_PASSWORD", "backend-fixture-secret")
	proxy, backend := net.Pipe()
	defer proxy.Close()
	defer backend.Close()
	proxy.SetDeadline(time.Now().Add(time.Second))
	backend.SetDeadline(time.Now().Add(time.Second))
	salt := []byte("01234567890123456789")
	h := &Handler{backendConn: proxy}
	done := make(chan error, 1)
	go func() {
		done <- h.containHandshake(nil, "root", "testdb", capClientConnectWithDB, salt, scrambleSHA1("frontend-fixture-secret", salt))
	}()
	peer := &Handler{}
	packet, err := peer.readPacket(backend)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(packet, []byte("honeypot_mysql_runtime\x00")) || bytes.Contains(packet, []byte("root\x00")) {
		t.Fatal("attacker identity reached backend")
	}
	if !bytes.Contains(packet, scrambleSHA1("backend-fixture-secret", salt)) {
		t.Fatal("backend proof not independently constructed")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{"honeypot_mysql_runtime", "unknown", "root"} {
		if err = h.containHandshake(nil, identity, "testdb", 0, salt, []byte("invalid-proof")); err == nil {
			t.Fatal("invalid frontend proof accepted")
		}
	}
}

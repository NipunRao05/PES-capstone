package protocol

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestClientOversizedPacketRejectedBeforeBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	h := &Handler{clientConn: server}
	go func() { _, _ = client.Write([]byte{255, 255, 255, 0}) }()
	_, err := h.readPacket(server)
	if err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("oversized client body accepted: %v", err)
	}
}

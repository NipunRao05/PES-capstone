package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/session"
	"github.com/xdg-go/scram"
)

// More ParameterStatus messages than the initial implementation's auth budget
// reproduces the live PostgreSQL handshake regression without a real database.
func TestContainedSCRAMSeparatesIdentitiesAndHandlesStartupParameters(t *testing.T) {
	t.Setenv("PG_DECOY_PASSWORD", "frontend-fixture-secret")
	t.Setenv("PG_RUNTIME_PASSWORD", "backend-fixture-secret")
	pc, client := net.Pipe()
	pb, backend := net.Pipe()
	for _, c := range []net.Conn{pc, client, pb, backend} {
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	h := NewHandler(pc, pb, slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, nil)
	h.sess = session.New("192.0.2.1", "postgres", "testdb")
	backendDone := make(chan error, 1)
	go func() {
		peer := &Handler{clientConn: backend}
		startup, err := peer.readRawMsg(backend)
		if err != nil {
			backendDone <- err
			return
		}
		if !bytes.Contains(startup, []byte(runtimeUser)) || bytes.Contains(startup, []byte("options")) {
			backendDone <- io.ErrUnexpectedEOF
			return
		}
		credentials, _ := scram.SHA256.NewClient("", "backend-fixture-secret", "")
		stored := credentials.GetStoredCredentials(scram.KeyFactors{Salt: "fixture-salt", Iters: 4096})
		server, _ := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) { return stored, nil })
		conv := server.NewConversation()
		if err = peer.sendToClient(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}); err != nil {
			backendDone <- err
			return
		}
		first, err := peer.readPrincipalPassword()
		if err != nil {
			backendDone <- err
			return
		}
		offset := strings.IndexByte(string(first), 0) + 5
		challenge, err := conv.Step(string(first[offset:]))
		if err != nil {
			backendDone <- err
			return
		}
		peer.sendToClient(&pgproto3.AuthenticationSASLContinue{Data: []byte(challenge)})
		proof, err := peer.readPrincipalPassword()
		if err != nil {
			backendDone <- err
			return
		}
		final, err := conv.Step(string(proof))
		if err != nil {
			backendDone <- err
			return
		}
		peer.sendToClient(&pgproto3.AuthenticationSASLFinal{Data: []byte(final)})
		peer.sendToClient(&pgproto3.AuthenticationOk{})
		for i := 0; i < 24; i++ {
			peer.sendToClient(&pgproto3.ParameterStatus{Name: "application_name", Value: "internal-only"})
		}
		backendDone <- peer.sendToClient(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	}()
	done := make(chan error, 1)
	go func() { done <- h.authenticateContained() }()
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
	credentials, _ := scram.SHA256.NewClient("postgres", "frontend-fixture-secret", "")
	conv := credentials.NewConversation()
	msg, err := front.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationSASL); !ok {
		t.Fatalf("unexpected %T", msg)
	}
	initial, _ := conv.Step("")
	raw := append([]byte("SCRAM-SHA-256\x00"), make([]byte, 4)...)
	binary.BigEndian.PutUint32(raw[len(raw)-4:], uint32(len(initial)))
	raw = append(raw, []byte(initial)...)
	writer := &Handler{backendConn: client}
	if err = writePassword(writer, raw); err != nil {
		t.Fatal(err)
	}
	msg, err = front.Receive()
	if err != nil {
		t.Fatal(err)
	}
	response, err := conv.Step(string(msg.(*pgproto3.AuthenticationSASLContinue).Data))
	if err != nil {
		t.Fatal(err)
	}
	writePassword(writer, []byte(response))
	for {
		msg, err = front.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if final, ok := msg.(*pgproto3.AuthenticationSASLFinal); ok {
			if _, err = conv.Step(string(final.Data)); err != nil {
				t.Fatal(err)
			}
		}
		if parameter, ok := msg.(*pgproto3.ParameterStatus); ok && parameter.Value == "internal-only" {
			t.Fatal("private backend parameter leaked")
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
		if _, ok := msg.(*pgproto3.ErrorResponse); ok {
			t.Fatal("authentication rejected")
		}
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-backendDone; err != nil {
		t.Fatal(err)
	}
}

func TestMalformedSCRAMFlagFailsBeforeBackendStartup(t *testing.T) {
	t.Setenv("PG_DECOY_PASSWORD", "frontend-fixture-secret")
	t.Setenv("PG_RUNTIME_PASSWORD", "backend-fixture-secret")
	pc, client := net.Pipe()
	pb, backend := net.Pipe()
	for _, c := range []net.Conn{pc, client, pb, backend} {
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
	}
	h := NewHandler(pc, pb, slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, nil)
	h.sess = session.New("192.0.2.1", "postgres", "testdb")
	done := make(chan error, 1)
	go func() { done <- h.authenticateContained() }()
	front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
	if _, err := front.Receive(); err != nil {
		t.Fatal(err)
	}
	malformed := ",,n=,r=not-a-supported-gs2-flag"
	raw := append([]byte("SCRAM-SHA-256\x00"), make([]byte, 4)...)
	binary.BigEndian.PutUint32(raw[len(raw)-4:], uint32(len(malformed)))
	raw = append(raw, []byte(malformed)...)
	if err := writePassword(&Handler{backendConn: client}, raw); err != nil {
		t.Fatal(err)
	}
	msg, err := front.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("unexpected %T", msg)
	}
	if err = <-done; err == nil {
		t.Fatal("malformed proof accepted")
	}
	backend.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	var b [1]byte
	if n, _ := backend.Read(b[:]); n != 0 {
		t.Fatal("malformed frontend reached backend")
	}
}

package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/publisher"
	"github.com/xdg-go/scram"
)

const runtimeUser = "honeypot_pg_runtime"

// Frontend SCRAM and backend SCRAM are independent conversations. No attacker
// startup parameter, identity, proof, or option is forwarded to the backend.
func (h *Handler) authenticateContained() (err error) {
	fail := errors.New("password authentication failed")
	stage := "frontend_configuration"
	_ = h.clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	_ = h.backendConn.SetDeadline(time.Now().Add(15 * time.Second))
	defer h.clientConn.SetDeadline(time.Time{})
	defer h.backendConn.SetDeadline(time.Time{})
	defer func() {
		if h.pub != nil {
			h.pub.EmitAuth(publisher.AuthEvent{Context: h.evidenceContext(), EventType: "auth", SessionID: h.sess.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), ClientIP: h.sess.ClientIP, Username: h.sess.Username, Database: h.sess.Database, AuthMethod: "scram-sha-256", Success: err == nil})
		}
	}()
	defer func() {
		if err != nil {
			h.logger.Warn("contained authentication rejected", "stage", stage)
			_ = h.sendToClient(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
			err = fail
		}
	}()
	password := os.Getenv("PG_DECOY_PASSWORD")
	backendPassword := os.Getenv("PG_RUNTIME_PASSWORD")
	if h.sess.Username != "postgres" || h.sess.Database != "testdb" || password == "" || backendPassword == "" {
		return fail
	}
	credentials, e := scram.SHA256.NewClient("", password, "")
	if e != nil {
		return fail
	}
	salt := make([]byte, 16)
	if _, e = rand.Read(salt); e != nil {
		return fail
	}
	stored := credentials.GetStoredCredentials(scram.KeyFactors{Salt: string(salt), Iters: 4096})
	server, e := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) { return stored, nil })
	if e != nil {
		return fail
	}
	conversation := server.NewConversation()
	if e = h.sendToClient(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}); e != nil {
		return fail
	}
	stage = "frontend_initial"
	first, e := h.readPrincipalPassword()
	if e != nil {
		return fail
	}
	mechanism := []byte("SCRAM-SHA-256\x00")
	if len(first) < len(mechanism)+4 || string(first[:len(mechanism)]) != string(mechanism) {
		return fail
	}
	n := int(binary.BigEndian.Uint32(first[len(mechanism):]))
	if n != len(first)-len(mechanism)-4 {
		return fail
	}
	// The SCRAM package expects a nonempty GS2 flag. Bound the supported
	// PostgreSQL form before parsing attacker-controlled bytes (no authzID).
	clientFirst := string(first[len(mechanism)+4:])
	if !strings.HasPrefix(clientFirst, "n,,n=") && !strings.HasPrefix(clientFirst, "y,,n=") {
		return fail
	}
	stage = "frontend_challenge"
	challenge, e := conversation.Step(clientFirst)
	if e != nil {
		return fail
	}
	if e = h.sendToClient(&pgproto3.AuthenticationSASLContinue{Data: []byte(challenge)}); e != nil {
		return fail
	}
	proof, e := h.readPrincipalPassword()
	if e != nil {
		return fail
	}
	stage = "frontend_proof"
	final, e := conversation.Step(string(proof))
	if e != nil || !conversation.Valid() {
		return fail
	}
	if e = h.sendToClient(&pgproto3.AuthenticationSASLFinal{Data: []byte(final)}); e != nil {
		return fail
	}

	stage = "backend_startup"
	startup := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": runtimeUser, "database": "testdb", "client_encoding": "UTF8"}})
	raw, e := startup.Encode(nil)
	if e != nil {
		return fail
	}
	if _, e = h.backendConn.Write(raw); e != nil {
		return fail
	}
	client, e := scram.SHA256.NewClient(runtimeUser, backendPassword, "")
	if e != nil {
		return fail
	}
	backend := client.NewConversation()
	for rounds := 0; rounds < 64; rounds++ {
		msg, e := h.readRawPGMsg(h.backendConn)
		if e != nil {
			return fail
		}
		switch msg[0] {
		case 'R':
			if len(msg) < 9 {
				return fail
			}
			sub := binary.BigEndian.Uint32(msg[5:9])
			switch sub {
			case 10:
				stage = "backend_mechanisms"
				if string(msg[9:]) != "SCRAM-SHA-256\x00\x00" {
					return fail
				}
				initial, e := backend.Step("")
				if e != nil {
					return fail
				}
				payload := append([]byte("SCRAM-SHA-256\x00"), make([]byte, 4)...)
				binary.BigEndian.PutUint32(payload[len(payload)-4:], uint32(len(initial)))
				payload = append(payload, []byte(initial)...)
				if e = writePassword(h, payload); e != nil {
					return fail
				}
			case 11:
				stage = "backend_challenge"
				response, e := backend.Step(string(msg[9:]))
				if e != nil {
					return fail
				}
				if e = writePassword(h, []byte(response)); e != nil {
					return fail
				}
			case 12:
				stage = "backend_signature"
				if _, e = backend.Step(string(msg[9:])); e != nil || !backend.Valid() {
					return fail
				}
			case 0:
				if !backend.Valid() {
					return fail
				}
			default:
				return fail
			}
		case 'E':
			return fail
		case 'Z':
			stage = "backend_ready"
			if !backend.Valid() {
				return fail
			}
			h.authMethod = "scram-sha-256"
			for _, m := range []pgproto3.BackendMessage{&pgproto3.AuthenticationOk{}, &pgproto3.ParameterStatus{Name: "server_version", Value: pgPersonaVersion()}, &pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"}, &pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"}, &pgproto3.ReadyForQuery{TxStatus: 'I'}} {
				if e = h.sendToClient(m); e != nil {
					return fail
				}
			}
			h.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(newBoundedFrontendReader(h.clientConn)), h.clientConn)
			h.backendFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(h.backendConn), h.backendConn)
			return nil
		}
	}
	return fail
}

func writePassword(h *Handler, payload []byte) error {
	raw := make([]byte, 5, len(payload)+5)
	raw[0] = 'p'
	binary.BigEndian.PutUint32(raw[1:], uint32(len(payload)+4))
	raw = append(raw, payload...)
	_, err := h.backendConn.Write(raw)
	return err
}

func pgPersonaVersion() string {
	if value := os.Getenv("PG_PERSONA_VERSION"); value != "" {
		return value
	}
	return "16.15"
}

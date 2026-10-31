package protocol

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"os"
)

// Validate the decoy challenge response locally, then replace the entire backend
// login. An attacker can never select a backend account or capability flags.
func (h *Handler) containHandshake(raw []byte, username, database string, caps uint32, salt, token []byte) error {
	password := ""
	switch username {
	case "root":
		password = os.Getenv("MYSQL_DECOY_ROOT_PASSWORD")
	case "proxyuser":
		password = os.Getenv("MYSQL_DECOY_PASSWORD")
	}
	runtimePassword := os.Getenv("MYSQL_RUNTIME_PASSWORD")
	if password == "" || runtimePassword == "" || (database != "" && database != "testdb") || subtle.ConstantTimeCompare(token, scrambleSHA1(password, salt)) != 1 {
		return errors.New("authentication failed")
	}
	// mysql_native_password is required by the idempotent runtime initializer.
	response := make([]byte, 32)
	// Fixed classic protocol capabilities: no compression, local files, multi-
	// statements, caller attributes, TLS upgrade or optional metadata negotiation.
	caps = (1 << 0) | (1 << 2) | (1 << 3) | (1 << 9) | (1 << 13) | (1 << 15) | (1 << 17) | (1 << 19)
	binary.LittleEndian.PutUint32(response, caps)
	response[8] = 45
	response = append(response, []byte("honeypot_mysql_runtime\x00")...)
	proof := scrambleSHA1(runtimePassword, salt)
	response = append(response, byte(len(proof)))
	response = append(response, proof...)
	response = append(response, []byte("testdb\x00mysql_native_password\x00")...)
	// Caller forwards this packet rather than the original, including no attrs.
	// Return by replacing the raw packet through a dedicated write here.
	return h.sendPacket(h.backendConn, response, 1)
}

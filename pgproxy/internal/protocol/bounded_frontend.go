package protocol

import (
	"encoding/binary"
	"errors"
	"github.com/jackc/pgproto3/v2"
	"io"
	"time"
)

const maxClientPacketBytes = maxDeceptionDecisionSQLBytes + 4096

// Validate the length before pgproto3's chunk reader can allocate the body.
// This does not change decoding or supported SQL/protocol semantics.
type boundedFrontendReader struct {
	source     io.Reader
	header     [5]byte
	headerPos  int
	remaining  int
	haveHeader bool
}

func newBoundedFrontendReader(source io.Reader) io.Reader {
	return &boundedFrontendReader{source: source}
}
func (r *boundedFrontendReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.haveHeader && r.headerPos == 5 && r.remaining == 0 {
		r.haveHeader = false
	}
	if !r.haveHeader {
		if _, err := io.ReadFull(r.source, r.header[:]); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint32(r.header[1:]))
		if length < 4 || length > maxClientPacketBytes {
			return 0, errors.New("frontend packet exceeds runtime size bound")
		}
		r.headerPos = 0
		r.remaining = length - 4
		r.haveHeader = true
	}
	if r.headerPos < 5 {
		n := copy(p, r.header[r.headerPos:])
		r.headerPos += n
		return n, nil
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.source.Read(p)
	r.remaining -= n
	return n, err
}

func (h *Handler) receiveClientMessage() (pgproto3.FrontendMessage, error) {
	if h.clientConn != nil {
		_ = h.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		defer h.clientConn.SetReadDeadline(time.Time{})
	}
	return h.clientBackend.Receive()
}

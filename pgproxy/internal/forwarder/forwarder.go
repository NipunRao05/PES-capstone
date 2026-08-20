// Package forwarder implements Layer 7: MessageForwarder
// Provides helpers for transparent, zero-copy message forwarding.
package forwarder

import (
	"io"
	"net"
	"sync"
)

// Pipe creates a bidirectional copy between two connections.
// This is used as a fallback for raw byte forwarding (e.g., COPY mode).
func Pipe(a, b net.Conn) error {
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	setErr := func(err error) {
		errOnce.Do(func() { firstErr = err })
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(a, b); err != nil {
			setErr(err)
		}
		// Half-close to unblock the other goroutine
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(b, a); err != nil {
			setErr(err)
		}
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	return firstErr
}

// CountingWriter wraps a writer and counts bytes written.
type CountingWriter struct {
	W     io.Writer
	Count int64
	mu    sync.Mutex
}

func (cw *CountingWriter) Write(p []byte) (int, error) {
	n, err := cw.W.Write(p)
	cw.mu.Lock()
	cw.Count += int64(n)
	cw.mu.Unlock()
	return n, err
}

func (cw *CountingWriter) Total() int64 {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.Count
}

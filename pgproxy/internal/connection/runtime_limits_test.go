package connection

import (
	"sync"
	"testing"
)

func TestConcurrentListenerAdmissionHasOneSharedBound(t *testing.T) {
	m := &Manager{cfg: Config{MaxConnections: 3}}
	var wait sync.WaitGroup
	for i := 0; i < 64; i++ {
		wait.Add(1)
		go func() { defer wait.Done(); m.admitConnection() }()
	}
	wait.Wait()
	if m.metrics.ActiveConnections.Load() != 3 || m.metrics.TotalConnections.Load() != 3 || m.metrics.RejectedConns.Load() != 61 {
		t.Fatal("connection admission exceeded shared bound")
	}
}

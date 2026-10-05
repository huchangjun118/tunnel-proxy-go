package metrics

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestBasic(t *testing.T) {
	r := NewRegistry()
	r.TunnelOpened()
	r.AddBytesClientToTarget(10)
	r.AddBytesTargetToClient(20)
	r.RejectedAuth()
	r.ErrorDial()
	s := r.Snapshot()
	if s.ActiveTunnels != 1 || s.BytesClientToTarget != 10 ||
		s.BytesTargetToClient != 20 || s.RejectedAuth != 1 || s.ErrorsDial != 1 {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
	r.TunnelClosed()
	if r.Snapshot().ActiveTunnels != 0 {
		t.Fatal("gauges should be zero")
	}
}

func TestConcurrentConsistency(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.TunnelOpened()
				r.AddBytesClientToTarget(1)
				r.TunnelClosed()
			}
		}()
	}
	wg.Wait()
	s := r.Snapshot()
	if s.ActiveTunnels != 0 {
		t.Fatalf("active must be 0, got %d", s.ActiveTunnels)
	}
	if s.TotalTunnels != 10000 || s.BytesClientToTarget != 10000 {
		t.Fatalf("counters wrong: %+v", s)
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) == 0 {
		t.Fatalf("marshal: %s %v", b, err)
	}
}

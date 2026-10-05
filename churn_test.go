package proxy

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// TestMetrics_Churn hammers the proxy with many short-lived tunnels over both
// protocols concurrently and asserts active returns to zero and total/byte
// counters stay consistent with no slot or connection leaks.
func TestMetrics_Churn(t *testing.T) {
	target, _ := startEchoTarget(t)
	const workers = 32
	const each = 15
	cfg := testConfig()
	cfg.MaxTunnels = workers
	cfg.LimitPolicy = PolicyQueue
	cfg.QueueTimeout = 3 * time.Second
	cfg.HalfCloseTimeout = time.Second
	srv, addr := startServer(t, cfg)

	var wg sync.WaitGroup
	var totalUp, totalDown int64
	var mu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				var c net.Conn
				if (id+i)%2 == 0 {
					c = dialSOCKS(t, addr, target, "", "")
				} else {
					c = dialHTTP(t, addr, target, "", "")
				}
				payload := fmt.Sprintf("w%d-m%d\n", id, i)
				echoRoundTrip(t, c, payload)
				mu.Lock()
				totalUp += int64(len(payload))
				totalDown += int64(len("echo:" + payload))
				mu.Unlock()
				_ = c.Close()
			}
		}(w)
	}
	wg.Wait()

	waitZeroActiveDeadline(t, srv, 5*time.Second)
	m := srv.Metrics()
	wantTotal := int64(workers * each)
	if m.TotalTunnels != wantTotal {
		t.Fatalf("total tunnels = %d, want %d", m.TotalTunnels, wantTotal)
	}
	if m.ActiveTunnels != 0 {
		t.Fatalf("active after churn = %d, want 0 (leak)", m.ActiveTunnels)
	}
	if m.BytesUp < totalUp || m.BytesDown < totalDown {
		t.Fatalf("byte accounting too small: up=%d>=%d down=%d>=%d",
			m.BytesUp, totalUp, m.BytesDown, totalDown)
	}
	if errs := m.Errors[StageRelay]; errs != 0 {
		t.Fatalf("clean churn produced relay errors: %d", errs)
	}
}

// TestMetrics_ConcurrentRejects ensures reject counters are consistent under
// concurrent over-capacity attempts.
func TestMetrics_ConcurrentRejects(t *testing.T) {
	target, _ := startBlockingTarget(t)
	cfg := testConfig()
	cfg.MaxTunnels = 2
	cfg.LimitPolicy = PolicyReject
	cfg.IdleTimeout = 30 * time.Second
	srv, addr := startServer(t, cfg)

	// Fill the two slots.
	c1 := dialSOCKS(t, addr, target, "", "")
	c2 := dialSOCKS(t, addr, target, "", "")
	waitActive(t, srv, 2)
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	const n = 40
	rejects := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(http bool) {
			defer wg.Done()
			if http {
				code := rawHTTP(t, addr,
					"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
				rejects <- code == 503
			} else {
				rejects <- tryDialSOCKS(t, addr, target, "", "") == nil
			}
		}(i%2 == 0)
	}
	wg.Wait()
	close(rejects)
	count := 0
	for r := range rejects {
		if !r {
			t.Fatal("a saturated attempt was not rejected as expected")
		}
		count++
	}
	if got := srv.Metrics().Rejected[ReasonLimitRejected]; int(got) != count {
		t.Fatalf("limit-rejected counter = %d, want %d", got, count)
	}
}

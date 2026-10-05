package proxy

import (
	"net"
	"testing"
	"time"
)

// TestLimit_Reject opens exactly MaxTunnels long-lived tunnels and then
// asserts the next attempt is rejected before reaching the target.
func TestLimit_Reject(t *testing.T) {
	target, targetConns := startBlockingTarget(t)

	cfg := testConfig()
	cfg.MaxTunnels = 2
	cfg.LimitPolicy = PolicyReject
	cfg.IdleTimeout = 30 * time.Second
	cfg.HalfCloseTimeout = 300 * time.Millisecond
	srv, srvAddr := startServer(t, cfg)

	var tunnels []net.Conn
	openN := func(n int) {
		for i := 0; i < n; i++ {
			c := dialSOCKS(t, srvAddr, target, "", "")
			tunnels = append(tunnels, c)
		}
	}
	openN(2)
	waitActive(t, srv, 2)

	// Third attempt must be rejected; the target must not accept it.
	if c := tryDialSOCKS(t, srvAddr, target, "", ""); c != nil {
		c.Close()
		t.Fatal("expected limit rejection")
	}
	m := srv.Metrics()
	if m.Rejected[ReasonLimitRejected] != 1 {
		t.Fatalf("limit-rejected = %d, want 1", m.Rejected[ReasonLimitRejected])
	}

	// HTTP face must honor the very same slot pool.
	if code := rawHTTP(t, srvAddr,
		"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); code != 503 {
		t.Fatalf("http at capacity status = %d, want 503", code)
	}

	// Releasing one slot admits exactly one more.
	_ = tunnels[0].Close()
	waitActive(t, srv, 1)
	c := dialHTTP(t, srvAddr, target, "", "")
	waitActive(t, srv, 2)
	_ = c.Close()
	for _, tc := range tunnels[1:] {
		_ = tc.Close()
	}

	// The target must only ever have accepted the established tunnels.
	waitZeroActive(t, srv)
	got := len(targetConns)
	if got != 3 {
		t.Fatalf("target accepted %d connections, want 3", got)
	}
}

// TestLimit_QueueTimeout verifies a waiter past QueueTimeout is rejected.
func TestLimit_QueueTimeout(t *testing.T) {
	target, _ := startBlockingTarget(t)

	cfg := testConfig()
	cfg.MaxTunnels = 1
	cfg.LimitPolicy = PolicyQueue
	cfg.QueueTimeout = 300 * time.Millisecond
	cfg.IdleTimeout = 30 * time.Second
	srv, srvAddr := startServer(t, cfg)

	first := dialSOCKS(t, srvAddr, target, "", "")
	defer first.Close()
	waitActive(t, srv, 1)

	start := time.Now()
	if c := tryDialSOCKS(t, srvAddr, target, "", ""); c != nil {
		c.Close()
		t.Fatal("expected queue timeout")
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("queue returned too fast: %s", elapsed)
	}
	if m := srv.Metrics(); m.Rejected[ReasonQueueTimeout] != 1 {
		t.Fatalf("queue-timeout = %d, want 1", m.Rejected[ReasonQueueTimeout])
	}
}

// TestLimit_QueueProceed verifies a queued waiter proceeds the instant a slot
// frees (even when the freeing tunnel needs half-close draining).
func TestLimit_QueueProceed(t *testing.T) {
	target, targetConns := startBlockingTarget(t)

	cfg := testConfig()
	cfg.MaxTunnels = 1
	cfg.LimitPolicy = PolicyQueue
	cfg.QueueTimeout = 2 * time.Second
	cfg.HandshakeTimeout = 5 * time.Second
	cfg.IdleTimeout = 30 * time.Second
	cfg.HalfCloseTimeout = 300 * time.Millisecond
	srv, srvAddr := startServer(t, cfg)

	first := dialSOCKS(t, srvAddr, target, "", "")
	waitActive(t, srv, 1)

	gotConn := make(chan net.Conn, 1)
	go func() {
		gotConn <- dialSOCKS(t, srvAddr, target, "", "")
	}()
	// Give the server time to park the second session in the slot wait.
	time.Sleep(150 * time.Millisecond)
	releaseAt := time.Now()
	_ = first.Close()
	select {
	case c := <-gotConn:
		// The slot should transfer quickly: released as soon as the first
		// tunnel's half-close drain ends.
		if d := time.Since(releaseAt); d > time.Second {
			t.Fatalf("queued tunnel took %s to proceed", d)
		}
		_ = c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("queued tunnel did not proceed after slot release")
	}
	waitZeroActive(t, srv)
	// Exactly two target connections: the timed-out/failed sessions never dial.
	if got := len(targetConns); got != 2 {
		t.Fatalf("target accepted %d connections, want 2", got)
	}
}

func waitActive(t *testing.T, srv *Server, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Metrics().ActiveTunnels == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("active tunnels = %d, want %d", srv.Metrics().ActiveTunnels, want)
}

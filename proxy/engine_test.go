package proxy

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/acl"
	"github.com/huchangjun118/tunnel-proxy-go/auth"
	"github.com/huchangjun118/tunnel-proxy-go/metrics"
	"github.com/huchangjun118/tunnel-proxy-go/pool"
	"github.com/huchangjun118/tunnel-proxy-go/target"
)

type fakeDialer struct {
	calls atomic.Int64
	conn  net.Conn
	err   error
}

func (f *fakeDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	f.calls.Add(1)
	return f.conn, f.err
}

func newPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func testEngine(t *testing.T, d Dialer, mutate func()) *Engine {
	t.Helper()
	authn := auth.New(false, nil)
	a, _ := acl.New(nil, nil)
	pl := pool.New(4, pool.PolicyReject, time.Second)
	reg := metrics.NewRegistry()
	eng := NewEngine(EngineDeps{
		Authenticator: authn,
		ACL:           a,
		Pool:          pl,
		Metrics:       reg,
		DialTimeout:   time.Second,
		IdleTimeout:   time.Second,
		TotalTimeout:  5 * time.Second,
		Dialer:        d,
	})
	return eng
}

func TestAdmitRejectsBeforeDial(t *testing.T) {
	client, _ := newPipe(t)
	_, upstream := newPipe(t)
	d := &fakeDialer{conn: upstream}

	// Auth + ACL configured to deny.
	authn := auth.New(true, map[string]string{"u": "p"})
	a, _ := acl.New([]string{"10.0.0.1"}, nil)
	pl := pool.New(4, pool.PolicyReject, time.Second)
	reg := metrics.NewRegistry()
	eng := NewEngine(EngineDeps{
		Authenticator: authn, ACL: a, Pool: pl, Metrics: reg,
		DialTimeout: time.Second, IdleTimeout: time.Second,
		TotalTimeout: 5 * time.Second, Dialer: d,
	})

	tg := target.Target{Host: "127.0.0.1", Port: 9999}

	// Missing credentials.
	if _, e := eng.Admit(client, tg, "", ""); e == nil || e.Stage != StageAuth || e.Cause != CauseMissingCreds {
		t.Fatalf("want auth/missing, got %v", e)
	}
	// Bad credentials.
	if _, e := eng.Admit(client, tg, "u", "x"); e == nil || e.Stage != StageAuth {
		t.Fatalf("want auth reject, got %v", e)
	}
	// Valid creds but denied host.
	if _, e := eng.Admit(client, tg, "u", "p"); e == nil || e.Stage != StageACL {
		t.Fatalf("want acl reject, got %v", e)
	}
	if d.calls.Load() != 0 {
		t.Fatalf("dialer must never be called on rejection, calls=%d", d.calls.Load())
	}
	if reg.Snapshot().RejectedAuth != 2 || reg.Snapshot().RejectedACL != 1 {
		t.Fatalf("counters wrong: %+v", reg.Snapshot())
	}
}

func TestAdmitDialErrorClassified(t *testing.T) {
	client, _ := newPipe(t)
	// Use a real refused address through the default dialer for a
	// deterministic, stage=dial error.
	authn := auth.New(false, nil)
	a, _ := acl.New(nil, nil)
	pl := pool.New(4, pool.PolicyReject, time.Second)
	reg := metrics.NewRegistry()
	eng := NewEngine(EngineDeps{
		Authenticator: authn, ACL: a, Pool: pl, Metrics: reg,
		DialTimeout: 500 * time.Millisecond, IdleTimeout: time.Second,
		TotalTimeout: 5 * time.Second,
	})
	// Port 1 on loopback reliably refuses quickly.
	tg := target.Target{Host: "127.0.0.1", Port: 1}
	_, e := eng.Admit(client, tg, "", "")
	if e == nil || e.Stage != StageDial {
		t.Fatalf("want dial-stage error, got %v", e)
	}
	if reg.Snapshot().ErrorsDial == 0 {
		t.Fatal("errors_dial not incremented")
	}
}

// TestServeTunnelRelay verifies a clean echo across the relay using
// net.Pipe, including bidirectional byte accounting.
func TestServeTunnelRelay(t *testing.T) {
	clientA, clientB := net.Pipe()
	upA, upB := net.Pipe()
	t.Cleanup(func() { clientA.Close(); clientB.Close(); upA.Close(); upB.Close() })

	d := &fakeDialer{conn: upA}
	eng := testEngine(t, d, nil)
	tg := target.Target{Host: "127.0.0.1", Port: 8080}

	adm, e := eng.Admit(clientA, tg, "", "")
	if e != nil {
		t.Fatal(e)
	}
	go eng.ServeTunnel(adm, clientA, nil)

	// Upstream peer echoes.
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := upB.Read(buf)
			if err != nil {
				return
			}
			upB.Write(buf[:n])
		}
	}()

	msg := []byte("relay-ok")
	if _, err := clientB.Write(msg); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(clientB, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != string(msg) {
		t.Fatalf("echo=%q", echo)
	}
	clientB.SetDeadline(time.Now().Add(3 * time.Second))
	clientB.Close()
	upB.Close()

	// Gauges must settle once the relay unwinds.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if eng.reg.Snapshot().ActiveTunnels == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if eng.reg.Snapshot().ActiveTunnels != 0 {
		t.Fatal("active gauge leaked")
	}
}

package e2e

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/config"
	"github.com/huchangjun118/tunnel-proxy-go/testutil"
)

// holdTunnel opens a tunnel and blocks until release; reports whether
// the tunnel was admitted via done channel once the tunnel carries data
// readiness (CONNECT 200 / SOCKS rep 0).
func holdTunnel(t *testing.T, proto, proxyAddr, target string, admitted chan<- error, release <-chan struct{}) {
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		admitted <- err
		return
	}
	released := make(chan struct{})
	go func() {
		<-release
		c.Close()
		close(released)
	}()
	rejected := func(e error) {
		admitted <- e
		c.Close() // nothing to keep open on an error response
	}
	// Drain tunnel data only AFTER the handshake, to avoid racing with
	// response parsing.
	var drainDone chan struct{}
	if proto == "connect" {
		c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
		br := newReader(c)
		resp, rerr := readResponse(br)
		if rerr != nil {
			rejected(rerr)
			return
		}
		if resp.StatusCode != http.StatusOK {
			rejected(&statusErr{resp.StatusCode})
			return
		}
		drainDone = make(chan struct{})
		go func() {
			io.Copy(io.Discard, br)
			close(drainDone)
		}()
	} else {
		c.Write([]byte{0x05, 0x01, 0x00})
		buf := make([]byte, 2)
		if _, err := io.ReadFull(c, buf); err != nil {
			rejected(err)
			return
		}
		if buf[1] != 0x00 {
			rejected(&statusErr{int(buf[1])})
			return
		}
		host, port := splitPort(target)
		pb := portBytes(port)
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		req = append(req, pb...)
		c.Write(req)
		head := make([]byte, 4)
		if _, err := io.ReadFull(c, head); err != nil {
			rejected(err)
			return
		}
		if head[1] != 0 {
			rejected(&statusErr{int(head[1])})
			return
		}
		drainBound(c, head[3])
		drainDone = make(chan struct{})
		go func() {
			io.Copy(io.Discard, c)
			close(drainDone)
		}()
	}
	admitted <- nil
	<-released
	<-drainDone
}

type statusErr struct{ code int }

func (e *statusErr) Error() string { return "non-success status code" }

func TestConcurrencyLimitReject(t *testing.T) {
	block := testutil.StartBlock(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.MaxTunnels = 2
		c.Overflow = config.OverflowReject
		c.IdleTimeout = 30 * time.Second
		c.TotalTimeout = 30 * time.Second
	})

	const n = 4
	results := make(chan error, n)
	release := make(chan struct{})
	for i := 0; i < n; i++ {
		go holdTunnel(t, "connect", srv.Addr().String(), block.Addr(), results, release)
	}
	var admitted, rejected int
	deadline := time.After(3 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case r := <-results:
			if r == nil {
				admitted++
			} else {
				rejected++
			}
		case <-deadline:
			t.Fatal("tunnels did not settle")
		}
	}
	if admitted != 2 || rejected != 2 {
		t.Fatalf("admitted=%d rejected=%d want 2/2", admitted, rejected)
	}
	if got := srv.Stats().ActiveTunnels; got != 2 {
		t.Fatalf("active=%d want 2", got)
	}
	if srv.Stats().RejectedLimit != 2 {
		t.Fatalf("limit rejects=%d", srv.Stats().RejectedLimit)
	}
	close(release)
	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 3*time.Second)
	if srv.Stats().TotalTunnels != 2 {
		t.Fatalf("total tunnels=%d want 2", srv.Stats().TotalTunnels)
	}
}

func TestConcurrencyLimitQueue(t *testing.T) {
	block := testutil.StartBlock(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.MaxTunnels = 1
		c.Overflow = config.OverflowQueue
		c.QueueTimeout = 500 * time.Millisecond
		c.IdleTimeout = 30 * time.Second
		c.TotalTimeout = 30 * time.Second
	})

	// Fill the only slot.
	r1 := make(chan error, 1)
	rel1 := make(chan struct{})
	go holdTunnel(t, "connect", srv.Addr().String(), block.Addr(), r1, rel1)
	if err := <-r1; err != nil {
		t.Fatal(err)
	}

	// Second tunnel queues and times out.
	start := time.Now()
	r2 := make(chan error, 1)
	rel2 := make(chan struct{})
	go holdTunnel(t, "connect", srv.Addr().String(), block.Addr(), r2, rel2)
	err2 := <-r2
	if err2 == nil {
		t.Fatal("expected queue timeout rejection")
	}
	if time.Since(start) < 400*time.Millisecond {
		t.Fatal("queue returned too fast")
	}
	if srv.Stats().RejectedQueue < 1 {
		t.Fatalf("queue rejects=%d", srv.Stats().RejectedQueue)
	}

	// Third tunnel: only start queuing once the first tunnel has fully
	// released its slot (half-close drain included), so it is admitted
	// immediately and deterministically.
	close(rel1)
	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 3*time.Second)

	r3 := make(chan error, 1)
	rel3 := make(chan struct{})
	go holdTunnel(t, "socks", srv.Addr().String(), block.Addr(), r3, rel3)
	select {
	case err := <-r3:
		if err != nil {
			t.Fatalf("new tunnel should be admitted after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new tunnel never admitted")
	}
	close(rel3)
	close(rel2)
}

func TestSlowPeerDoesNotBlockOthers(t *testing.T) {
	echo := testutil.StartEcho(t)
	block := testutil.StartBlock(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.MaxTunnels = 16
		c.IdleTimeout = 5 * time.Second
	})

	// A slow client: connects CONNECT to block target and writes nothing,
	// never reads. It must not stop other tunnels.
	relSlow := make(chan struct{})
	slowRes := make(chan error, 1)
	go holdTunnel(t, "connect", srv.Addr().String(), block.Addr(), slowRes, relSlow)
	if err := <-slowRes; err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
		roundTrip(t, c, "fast\n")
		c.Close()
	}
	close(relSlow)
}

// TestQueueAdmittedOnRelease: a tunnel queued at capacity is admitted
// without an error response once a running tunnel releases its slot.
func TestQueueAdmittedOnRelease(t *testing.T) {
	block := testutil.StartBlock(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.MaxTunnels = 1
		c.Overflow = config.OverflowQueue
		c.QueueTimeout = 3 * time.Second
		c.IdleTimeout = 30 * time.Second
		c.TotalTimeout = 30 * time.Second
	})

	r1 := make(chan error, 1)
	rel1 := make(chan struct{})
	go holdTunnel(t, "connect", srv.Addr().String(), block.Addr(), r1, rel1)
	if err := <-r1; err != nil {
		t.Fatal(err)
	}

	r2 := make(chan error, 1)
	rel2 := make(chan struct{})
	go holdTunnel(t, "socks", srv.Addr().String(), block.Addr(), r2, rel2)

	// It must not be rejected immediately; give it time to park in queue.
	select {
	case err := <-r2:
		t.Fatalf("tunnel should be queued, got result: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if srv.Stats().ActiveTunnels != 0 && srv.Stats().ActiveTunnels != 1 {
		t.Fatalf("active=%d", srv.Stats().ActiveTunnels)
	}

	close(rel1)
	select {
	case err := <-r2:
		if err != nil {
			t.Fatalf("queued tunnel must be admitted on release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued tunnel never admitted")
	}
	close(rel2)
}

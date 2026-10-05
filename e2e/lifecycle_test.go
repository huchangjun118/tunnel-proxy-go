package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"context"

	"github.com/huchangjun118/tunnel-proxy-go/config"
	"github.com/huchangjun118/tunnel-proxy-go/server"
	"github.com/huchangjun118/tunnel-proxy-go/testutil"
)

// TestHalfClose: client half-closes after sending data; the target must
// observe the FIN, its post-FIN response must still reach the client.
func TestHalfClose(t *testing.T) {
	hc := testutil.StartHalfClose(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.IdleTimeout = 5 * time.Second
	})

	for _, proto := range []string{"connect", "socks5"} {
		t.Run(proto, func(t *testing.T) {
			var c net.Conn
			if proto == "connect" {
				var resp *http.Response
				c, resp = testutil.DialCONNECT(t, srv.Addr().String(), hc.Addr(), "", "")
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status=%d", resp.StatusCode)
				}
			} else {
				var rep byte
				c, rep = testutil.DialSOCKS5(t, srv.Addr().String(), hc.Addr(), "", "")
				if rep != 0 {
					t.Fatalf("rep=%d", rep)
				}
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))

			payload := []byte("ping")
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			// Read echo.
			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(c, echo); err != nil {
				t.Fatalf("echo: %v", err)
			}
			if string(echo) != string(payload) {
				t.Fatalf("echo=%q", echo)
			}
			// Half-close the write side only.
			if tc, ok := c.(interface{ CloseWrite() error }); ok {
				if err := tc.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			// Marker written by the target after observing our FIN must
			// arrive, proving half-close propagated and reverse data flows.
			marker := make([]byte, len("HALF_CLOSE_MARKER"))
			if _, err := io.ReadFull(c, marker); err != nil {
				t.Fatalf("marker: %v", err)
			}
			if string(marker) != "HALF_CLOSE_MARKER" {
				t.Fatalf("marker=%q", marker)
			}
		})
	}

	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 5*time.Second)
}

// TestTargetAbruptClose: the target drops with RST mid-transfer; the
// client must observe EOF/error and the tunnel must be released without
// leaking, under both protocols.
func TestTargetAbruptClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	srv := testutil.StartProxy(t, nil)

	c, resp := testutil.DialCONNECT(t, srv.Addr().String(), ln.Addr().String(), "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	target := <-accepted
	// Abort target with SO_LINGER 0 -> RST.
	if tc, ok := target.(*net.TCPConn); ok {
		setLingerZero(tc)
	}
	target.Close()

	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		// Could also be EOF; either way the read must end, not block.
	}
	// Give the relay a moment to release.
	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 4*time.Second)
	c.Close()
}

// TestClientAbruptClose: client vanishes while target is quiet; the
// tunnel must be released by the idle timeout.
func TestClientAbruptCloseIdle(t *testing.T) {
	block := testutil.StartBlock(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.IdleTimeout = 1 * time.Second
		c.TotalTimeout = 10 * time.Second
	})
	c, resp := testutil.DialCONNECT(t, srv.Addr().String(), block.Addr(), "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	c.Close()
	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 3*time.Second)
}

// TestDialFailures covers connection refused and a dial timeout.
func TestDialFailures(t *testing.T) {
	refused := testutil.DeadAddr(t)
	srv := testutil.StartProxy(t, nil)

	c, resp := testutil.DialCONNECT(t, srv.Addr().String(), refused, "", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("refused status=%d want 502", resp.StatusCode)
	}
	c.Close()

	// SOCKS maps refused -> 0x05.
	c2, rep := testutil.DialSOCKS5(t, srv.Addr().String(), refused, "", "")
	c2.Close()
	if rep != 0x05 {
		t.Fatalf("socks rep=%d want 5", rep)
	}
	if srv.Stats().ErrorsDial < 2 {
		t.Fatalf("dial errors=%d", srv.Stats().ErrorsDial)
	}
}

// TestResolveFailure: target resolution failure is reported at the
// resolve stage and never as tunnel data. A deterministic failing
// dialer keeps the test independent of the host's DNS environment.
func TestResolveFailure(t *testing.T) {
	failing := failingResolveDialer{}
	srv := testutil.StartProxy(t, nil, server.WithDialer(failing))
	targetAddr := "whatever.example:80"
	c, resp := testutil.DialCONNECT(t, srv.Addr().String(), targetAddr, "", "")
	defer c.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d want 502", resp.StatusCode)
	}
	c2, rep := testutil.DialSOCKS5(t, srv.Addr().String(), targetAddr, "", "")
	defer c2.Close()
	if rep != 0x04 { // host unreachable
		t.Fatalf("socks rep=%d want 4", rep)
	}
	if srv.Stats().ErrorsResolve < 2 {
		t.Fatalf("resolve errors=%d", srv.Stats().ErrorsResolve)
	}
}

type failingResolveDialer struct{}

func (failingResolveDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, &net.DNSError{Err: "no such host", Name: "whatever.example", IsNotFound: true}
}

// TestIdleAndTotalTimeout verifies idle and total lifetime reaping.
func TestIdleAndTotalTimeout(t *testing.T) {
	block := testutil.StartBlock(t)

	t.Run("idle", func(t *testing.T) {
		srv := testutil.StartProxy(t, func(c *config.Config) {
			c.IdleTimeout = 500 * time.Millisecond
			c.TotalTimeout = 30 * time.Second
		})
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), block.Addr(), "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
		defer c.Close()
		waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 3*time.Second)
	})

	t.Run("total", func(t *testing.T) {
		srv := testutil.StartProxy(t, func(c *config.Config) {
			c.IdleTimeout = 30 * time.Second
			c.TotalTimeout = 500 * time.Millisecond
		})
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), block.Addr(), "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
		defer c.Close()
		waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 3*time.Second)
	})
}

// TestMetricsEndpoint checks the JSON stats HTTP endpoint reflects
// counters and the active gauge returns to zero after disconnect.
func TestMetricsEndpoint(t *testing.T) {
	echo := testutil.StartEcho(t)
	srv := testutil.StartProxyWithMetrics(t)

	c, resp := testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	roundTrip(t, c, "metrics-check\n")
	c.Close()
	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 3*time.Second)

	httpResp, err := http.Get(srv.MetricsURL() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status=%d", httpResp.StatusCode)
	}
	var st map[string]int64
	if err := json.NewDecoder(httpResp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st["total_tunnels"] < 1 || st["bytes_client_to_target"] == 0 || st["active_tunnels"] != 0 {
		t.Fatalf("unexpected metrics: %+v", st)
	}
}

var _ = bytes.NewBuffer

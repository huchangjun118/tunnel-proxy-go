package e2e

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/config"
	"github.com/huchangjun118/tunnel-proxy-go/testutil"
)

// happyPath verifies bidirectional data flow through both protocols.
func TestHappyPathBothProtocols(t *testing.T) {
	echo := testutil.StartEcho(t)
	srv := testutil.StartProxy(t, nil)

	for _, name := range []string{"connect", "socks5"} {
		t.Run(name, func(t *testing.T) {
			var c net.Conn
			if name == "connect" {
				var resp *http.Response
				c, resp = testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "", "")
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status=%d", resp.StatusCode)
				}
			} else {
				var rep byte
				c, rep = testutil.DialSOCKS5(t, srv.Addr().String(), echo.Addr(), "", "")
				if rep != 0x00 {
					t.Fatalf("socks rep=%d", rep)
				}
			}
			defer c.Close()
			roundTrip(t, c, "hello tunnel\n")
			s := srv.Stats()
			if s.BytesClientToTarget == 0 || s.BytesTargetToClient == 0 {
				t.Fatalf("byte counters not incremented: %+v", s)
			}
		})
	}

	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, time.Second)
}

func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// TestAuthFailure covers missing/invalid credentials for both protocols.
func TestAuthFailure(t *testing.T) {
	echo := testutil.StartEcho(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.AuthEnabled = true
		c.Credentials = map[string]string{"alice": "s3cret"}
	})

	t.Run("connect_valid", func(t *testing.T) {
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "alice", "s3cret")
		defer c.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
		roundTrip(t, c, "ok\n")
	})
	t.Run("connect_missing", func(t *testing.T) {
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "", "")
		defer c.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status=%d want 407", resp.StatusCode)
		}
	})
	t.Run("connect_bad", func(t *testing.T) {
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "alice", "nope")
		defer c.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status=%d want 407", resp.StatusCode)
		}
	})
	t.Run("socks_valid", func(t *testing.T) {
		c, rep := testutil.DialSOCKS5(t, srv.Addr().String(), echo.Addr(), "alice", "s3cret")
		defer c.Close()
		if rep != 0x00 {
			t.Fatalf("rep=%d", rep)
		}
		roundTrip(t, c, "ok\n")
	})
	t.Run("socks_bad", func(t *testing.T) {
		c, rep := testutil.DialSOCKS5(t, srv.Addr().String(), echo.Addr(), "alice", "nope")
		defer c.Close()
		if rep != 0x01 {
			t.Fatalf("auth status=%d want 1", rep)
		}
	})
	t.Run("socks_no_method", func(t *testing.T) {
		raw, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		raw.Write([]byte{0x05, 0x01, 0x00}) // only no-auth
		buf := make([]byte, 2)
		io.ReadFull(raw, buf)
		if buf[1] != 0xFF {
			t.Fatalf("method rep=%d want 0xFF", buf[1])
		}
	})

	s := srv.Stats()
	if s.RejectedAuth < 4 {
		t.Fatalf("expected >=4 auth rejections, got %d", s.RejectedAuth)
	}
	// A rejected request must never have reached the echo target.
	if echo.Accepted.Load() != 2 {
		t.Fatalf("target accepted %d conns, want 2 (only valid auth)", echo.Accepted.Load())
	}
}

// TestACLReject verifies target access control and spelling independence.
func TestACLReject(t *testing.T) {
	echo := testutil.StartEcho(t)
	echoHost, _, _ := net.SplitHostPort(echo.Addr())
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.AllowedHosts = []string{"10.0.0.1"} // does not include echo
	})
	_ = echoHost

	t.Run("connect_denied", func(t *testing.T) {
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "", "")
		defer c.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status=%d want 403", resp.StatusCode)
		}
	})
	t.Run("socks_denied", func(t *testing.T) {
		c, rep := testutil.DialSOCKS5(t, srv.Addr().String(), echo.Addr(), "", "")
		defer c.Close()
		if rep != 0x02 {
			t.Fatalf("rep=%d want 0x02", rep)
		}
	})
	if echo.Accepted.Load() != 0 {
		t.Fatalf("denied target must not be dialed, accepted=%d", echo.Accepted.Load())
	}
	if srv.Stats().RejectedACL < 2 {
		t.Fatalf("acl rejects=%d", srv.Stats().RejectedACL)
	}

	// Port deny.
	srv2 := testutil.StartProxy(t, func(c *config.Config) {
		c.AllowedPorts = []int{1}
	})
	c, resp := testutil.DialCONNECT(t, srv2.Addr().String(), echo.Addr(), "", "")
	defer c.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("port deny status=%d", resp.StatusCode)
	}
}

// TestACLSpellingIndependence: allow loopback, reach it under any spelling.
func TestACLSpellingIndependence(t *testing.T) {
	echo := testutil.StartEcho(t)
	_, portStr, _ := net.SplitHostPort(echo.Addr())
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.AllowedHosts = []string{"localhost"}
	})
	for _, host := range []string{"127.0.0.1", "localhost", "127.1"} {
		c, resp := testutil.DialCONNECT(t, srv.Addr().String(), net.JoinHostPort(host, portStr), "", "")
		if resp.StatusCode != http.StatusOK {
			c.Close()
			t.Fatalf("%s: status=%d", host, resp.StatusCode)
		}
		roundTrip(t, c, "x\n")
		c.Close()
	}
}

func waitFor(t *testing.T, cond func() bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", within)
}

var _ = strconv.Itoa

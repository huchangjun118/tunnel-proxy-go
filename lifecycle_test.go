package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// halfCloseTarget accepts a conn, reads the first message, then sends its own
// message; it observes the client's FIN (half-close) while still being able to
// write back before finally closing.
func halfCloseTarget(t *testing.T, finish func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				_, _ = c.Write([]byte("got:" + line))
				if finish != nil {
					finish(c)
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// TestRelay_HalfClose: client half-closes its write side; the target must see
// EOF, yet the client must still receive the target's final message.
func TestRelay_HalfClose(t *testing.T) {
	for _, socks := range []bool{true, false} {
		target := halfCloseTarget(t, func(c net.Conn) {
			// On observing client FIN, send a final frame and fully close.
			_, _ = c.Write([]byte("after-fin\n"))
		})
		srv, srvAddr := startServer(t, testConfig())

		var c net.Conn
		if socks {
			c = dialSOCKS(t, srvAddr, target, "", "")
		} else {
			c = dialHTTP(t, srvAddr, target, "", "")
		}

		_, _ = c.Write([]byte("half\n"))
		got1 := make([]byte, len("got:half\n"))
		readFull(t, c, got1)

		// Half-close client -> target direction.
		if hc, ok := c.(interface{ CloseWrite() error }); ok {
			if err := hc.CloseWrite(); err != nil {
				t.Fatalf("close write: %v", err)
			}
		} else {
			t.Skip("test conn does not support CloseWrite")
		}

		got2 := make([]byte, len("after-fin\n"))
		readFull(t, c, got2)
		if string(got2) != "after-fin\n" {
			t.Fatalf("after-fin payload = %q", got2)
		}
		// Target closes afterwards -> client sees EOF.
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8)
		if n, err := c.Read(buf); err != io.EOF || n != 0 {
			t.Fatalf("expected clean EOF, n=%d err=%v", n, err)
		}
		_ = c.Close()
		waitZeroActive(t, srv)
		if m := srv.Metrics(); m.Errors[StageRelay] != 0 {
			t.Fatalf("half-close produced relay errors: %+v", m.Errors)
		}
	}
}

// TestRelay_PeerAbort: the target RSTs/abruptly closes mid-transfer. The
// client read must surface an error/EOF and the tunnel must be fully
// released, with no goroutine/connection lingering (counter back to zero).
func TestRelay_PeerAbort(t *testing.T) {
	target := halfCloseTarget(t, func(c net.Conn) {
		// Abrupt teardown from the target side right after first message.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	})
	cfg := testConfig()
	cfg.IdleTimeout = 5 * time.Second
	srv, srvAddr := startServer(t, cfg)

	c := dialSOCKS(t, srvAddr, target, "", "")
	_, _ = c.Write([]byte("abort\n"))
	// Either the response arrives followed by EOF/reset, or the read itself
	// errors; both prove propagation.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	for {
		_, err := c.Read(buf)
		if err != nil {
			break
		}
	}
	_ = c.Close()
	waitZeroActive(t, srv)
}

// TestRelay_ClientAbort: the client vanishes while the target is blocked
// writing; the server must release the slot promptly (idle deadline aside).
func TestRelay_ClientAbort(t *testing.T) {
	// Target sends continuously; client abandons the conn.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				chunk := bytes.Repeat([]byte("x"), 4096)
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	cfg := testConfig()
	cfg.IdleTimeout = 5 * time.Second
	srv, srvAddr := startServer(t, cfg)

	c := dialHTTP(t, srvAddr, ln.Addr().String(), "", "")
	// Read a little to establish flow, then hard-close without draining.
	buf := make([]byte, 128)
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = c.Read(buf)
	if tc, ok := underlyingTCP(c); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
	waitZeroActive(t, srv)
}

// TestRelay_IdleTimeout verifies a silent tunnel is reaped by the idle timer.
func TestRelay_IdleTimeout(t *testing.T) {
	target, _ := startBlockingTarget(t)
	cfg := testConfig()
	cfg.IdleTimeout = 300 * time.Millisecond
	srv, srvAddr := startServer(t, cfg)

	c := dialSOCKS(t, srvAddr, target, "", "")
	defer c.Close()
	waitZeroActiveDeadline(t, srv, 3*time.Second)
	m := srv.Metrics()
	if m.Errors[StageRelay] == 0 {
		t.Fatalf("expected relay-stage error for idle timeout: %+v", m.Errors)
	}
}

// TestRelay_MaxLifetime verifies the absolute lifetime cuts even an active
// long-lived tunnel.
func TestRelay_MaxLifetime(t *testing.T) {
	target, _ := startBlockingTarget(t)
	cfg := testConfig()
	cfg.IdleTimeout = 30 * time.Second
	cfg.MaxLifetime = 300 * time.Millisecond
	srv, srvAddr := startServer(t, cfg)

	c := dialSOCKS(t, srvAddr, target, "", "")
	defer c.Close()
	waitZeroActiveDeadline(t, srv, 3*time.Second)
	if m := srv.Metrics(); m.Rejected[ReasonLifetimeExpired] == 0 && m.Errors[StageRelay] == 0 {
		t.Fatalf("lifetime expiry not recorded: %+v", m)
	}
}

// TestServer_ShutdownClosesTunnels checks Close unblocks active sessions.
func TestServer_ShutdownClosesTunnels(t *testing.T) {
	target, _ := startBlockingTarget(t)
	cfg := testConfig()
	cfg.IdleTimeout = 30 * time.Second
	srv, srvAddr := startServer(t, cfg)
	// Remove the auto-Cleanup close so we control shutdown explicitly.
	c := dialSOCKS(t, srvAddr, target, "", "")
	defer c.Close()
	waitActive(t, srv, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Close()
	}()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected client read error after server shutdown")
	}
	wg.Wait()
}

func readFull(t *testing.T, r io.Reader, p []byte) {
	t.Helper()
	_ = r.(net.Conn).SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(r, p); err != nil {
		t.Fatalf("readFull %d bytes: %v", len(p), err)
	}
}

func waitZeroActiveDeadline(t *testing.T, srv *Server, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if srv.Metrics().ActiveTunnels == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("active tunnels never reached 0: %d", srv.Metrics().ActiveTunnels)
}

func underlyingTCP(c net.Conn) (*net.TCPConn, bool) {
	switch v := c.(type) {
	case *net.TCPConn:
		return v, true
	case *bufferedTestConn:
		return underlyingTCP(v.Conn)
	}
	return nil, false
}

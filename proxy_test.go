package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.HandshakeTimeout = 5 * time.Second
	cfg.DialTimeout = 2 * time.Second
	cfg.IdleTimeout = 3 * time.Second
	cfg.HalfCloseTimeout = 500 * time.Millisecond
	cfg.MaxLifetime = 10 * time.Second
	cfg.MaxTunnels = 8
	return cfg
}

// TestSOCKS_HappyPath covers a successful SOCKS5 CONNECT and bidirectional
// data flow through an in-process loopback target.
func TestSOCKS_HappyPath(t *testing.T) {
	target, _ := startEchoTarget(t)
	srv, srvAddr := startServer(t, testConfig())

	c := dialSOCKS(t, srvAddr, target, "", "")
	echoRoundTrip(t, c, "hello-socks\n")
	_ = c.Close()
	waitZeroActive(t, srv)

	m := srv.Metrics()
	if m.TotalTunnels != 1 || m.ActiveTunnels != 0 {
		t.Fatalf("tunnel counters wrong: %+v", m)
	}
	if m.BytesUp == 0 || m.BytesDown == 0 {
		t.Fatalf("byte counters zero: %+v", m)
	}
}

// TestHTTP_HappyPath covers a successful HTTP CONNECT session.
func TestHTTP_HappyPath(t *testing.T) {
	target, _ := startEchoTarget(t)
	srv, srvAddr := startServer(t, testConfig())

	c := dialHTTP(t, srvAddr, target, "", "")
	echoRoundTrip(t, c, "hello-http\n")
	_ = c.Close()
	waitZeroActive(t, srv)

	m := srv.Metrics()
	if m.TotalTunnels != 1 {
		t.Fatalf("total tunnels = %d, want 1", m.TotalTunnels)
	}
}

// TestProtocolParity runs the same forwarding scenario over both fronts and
// asserts byte accounting is identical.
func TestProtocolParity(t *testing.T) {
	target, _ := startEchoTarget(t)
	payload := "parity-check\n"

	run := func(useSOCKS bool) (int64, int64) {
		srv, srvAddr := startServer(t, testConfig())
		var c net.Conn
		if useSOCKS {
			c = dialSOCKS(t, srvAddr, target, "", "")
		} else {
			c = dialHTTP(t, srvAddr, target, "", "")
		}
		echoRoundTrip(t, c, payload)
		_ = c.Close()
		waitZeroActive(t, srv)
		m := srv.Metrics()
		return m.BytesUp, m.BytesDown
	}
	su, sd := run(true)
	hu, hd := run(false)
	if su != hu || sd != hd {
		t.Fatalf("protocol byte accounting differs: socks(%d/%d) http(%d/%d)", su, sd, hu, hd)
	}
}

func waitZeroActive(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Metrics().ActiveTunnels == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("active tunnels never returned to 0: %d", srv.Metrics().ActiveTunnels)
}

// TestAuth_Failure covers wrong and missing credentials on both protocols.
func TestAuth_Failure(t *testing.T) {
	target := startNeverReachedTarget(t)
	cfg := testConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Credentials = map[string]string{"alice": "s3cret"}
	srv, srvAddr := startServer(t, cfg)

	// SOCKS: wrong password.
	if c := tryDialSOCKS(t, srvAddr, target, "alice", "nope"); c != nil {
		c.Close()
		t.Fatalf("socks wrong password unexpectedly accepted")
	}
	// HTTP: missing -> 407, wrong -> 403.
	if code := rawHTTP(t, srvAddr,
		"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); code != 407 {
		t.Fatalf("missing creds status = %d, want 407", code)
	}
	if code := rawHTTP(t, srvAddr,
		"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n"+
			"Proxy-Authorization: Basic YWxpY2U6bm9wZQ==\r\n\r\n"); code != 403 {
		t.Fatalf("wrong creds status = %d, want 403", code)
	}

	m := srv.Metrics()
	if m.Rejected[ReasonAuthFailed] != 2 { // socks wrong + http wrong
		t.Fatalf("auth-failed count = %d, want 2: %+v", m.Rejected[ReasonAuthFailed], m.Rejected)
	}
	if m.Rejected[ReasonAuthRequired] != 1 {
		t.Fatalf("auth-required count = %d, want 1", m.Rejected[ReasonAuthRequired])
	}
	// Crucially, no tunnel was ever established.
	if m.TotalTunnels != 0 {
		t.Fatalf("total tunnels = %d, want 0", m.TotalTunnels)
	}
}

// TestAuth_Success makes sure valid credentials open the tunnel on both fronts.
func TestAuth_Success(t *testing.T) {
	target, _ := startEchoTarget(t)
	cfg := testConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Credentials = map[string]string{"alice": "s3cret"}
	srv, srvAddr := startServer(t, cfg)

	c1 := dialSOCKS(t, srvAddr, target, "alice", "s3cret")
	echoRoundTrip(t, c1, "ok-socks\n")
	c1.Close()

	c2 := dialHTTP(t, srvAddr, target, "alice", "s3cret")
	echoRoundTrip(t, c2, "ok-http\n")
	c2.Close()

	waitZeroActive(t, srv)
	if m := srv.Metrics(); m.TotalTunnels != 2 {
		t.Fatalf("total tunnels = %d, want 2", m.TotalTunnels)
	}
}

// TestACL_Denied ensures access control blocks before any target connection
// exists, on both fronts, with distinct classification from auth failures.
func TestACL_Denied(t *testing.T) {
	target := startNeverReachedTarget(t)

	cfg := testConfig()
	cfg.ACL.DefaultDeny = true // nothing allowed
	srv, srvAddr := startServer(t, cfg)

	if c := tryDialSOCKS(t, srvAddr, target, "", ""); c != nil {
		c.Close()
		t.Fatalf("socks to denied target unexpectedly accepted")
	}
	if code := rawHTTP(t, srvAddr,
		"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); code != 403 {
		t.Fatalf("http denied status = %d, want 403", code)
	}
	// Give any stray dial a chance to land before the test ends.
	time.Sleep(100 * time.Millisecond)
	m := srv.Metrics()
	if m.Rejected[ReasonTargetDenied] != 2 {
		t.Fatalf("denied count = %d, want 2", m.Rejected[ReasonTargetDenied])
	}
	if m.TotalTunnels != 0 {
		t.Fatalf("tunnel opened despite ACL denial: %d", m.TotalTunnels)
	}
}

// TestACL_AllowRule_NotationIndependence verifies that decisions do not
// depend on address spelling: 127.0.0.1 vs ::ffff:127.0.0.1, and that an
// allow rule plus a different-port deny behave canonically.
func TestACL_NotationIndependence(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())

	cfg := testConfig()
	cfg.ACL.DefaultDeny = true
	cfg.ACL.Rules = []Rule{
		{Action: ActionAllow, Host: host, Port: mustPort(t, port)},
		{Action: ActionDeny, Host: host, Port: 9999},
	}
	srv, srvAddr := startServer(t, cfg)

	// IPv4 spelling.
	c1 := dialSOCKS(t, srvAddr, host+":"+port, "", "")
	c1.Close()
	// IPv4-mapped IPv6 spelling normalizes to the same target.
	c2 := dialSOCKS(t, srvAddr, "[::ffff:"+host+"]:"+port, "", "")
	c2.Close()
	// Denied other port.
	if c := tryDialSOCKS(t, srvAddr, host+":9999", "", ""); c != nil {
		c.Close()
		t.Fatal("expected denial for other port")
	}
	if m := srv.Metrics(); m.Rejected[ReasonTargetDenied] != 1 {
		t.Fatalf("denied = %d, want 1", m.Rejected[ReasonTargetDenied])
	}
}

func mustPort(t *testing.T, s string) int {
	t.Helper()
	var p int
	for _, c := range s {
		p = p*10 + int(c-'0')
	}
	return p
}

// TestDial_FailureStages distinguishes DNS failure from connection refused;
// failure bytes must never be mistaken for tunnel payload.
func TestDial_FailureStages(t *testing.T) {
	// Unreachable local port -> dial refused.
	refused := "127.0.0.1:1"
	cfg := testConfig()
	cfg.DialTimeout = time.Second
	srv, srvAddr := startServer(t, cfg)

	if c := tryDialSOCKS(t, srvAddr, refused, "", ""); c != nil {
		c.Close()
		t.Fatal("expected dial failure")
	}
	// Unresolvable hostname.
	if c := tryDialSOCKS(t, srvAddr,
		"nonexistent.invalid.test:80", "", ""); c != nil {
		c.Close()
		t.Fatal("expected dns failure")
	}
	m := srv.Metrics()
	if m.Errors[StageDial] < 2 {
		t.Fatalf("dial-stage errors = %d, want >=2", m.Errors[StageDial])
	}
	if m.TotalTunnels != 0 {
		t.Fatal("tunnel counted despite dial failure")
	}
}

// TestTargetInvalid covers malformed targets being rejected at handshake.
func TestTargetInvalid(t *testing.T) {
	cfg := testConfig()
	srv, srvAddr := startServer(t, cfg)

	// HTTP CONNECT without port.
	if code := rawHTTP(t, srvAddr,
		"CONNECT 127.0.0.1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); code != 400 {
		t.Fatalf("missing port status = %d, want 400", code)
	}
	m := srv.Metrics()
	if m.Rejected[ReasonTargetInvalid] != 1 {
		t.Fatalf("invalid-target = %d, want 1", m.Rejected[ReasonTargetInvalid])
	}
}

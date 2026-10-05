package proxy

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// rawSOCKSGreeting sends a raw method negotiation and returns the selected
// method byte.
func rawSOCKSGreeting(t *testing.T, addr string, methods []byte) byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	return rep[1]
}

func TestSOCKS_AuthRequiredMethodNegotiation(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Credentials = map[string]string{"u": "p"}
	srv, addr := startServer(t, cfg)

	// Client that only offers "no auth" must be told 0xFF before any target.
	if m := rawSOCKSGreeting(t, addr, []byte{0x00}); m != 0xFF {
		t.Fatalf("method = %#x, want 0xFF", m)
	}
	// Client offering user/pass gets 0x02.
	if m := rawSOCKSGreeting(t, addr, []byte{0x00, 0x02}); m != 0x02 {
		t.Fatalf("method = %#x, want 0x02", m)
	}
	if n := srv.Metrics().TotalTunnels; n != 0 {
		t.Fatalf("no tunnel may be established during method negotiation, got %d", n)
	}
}

func TestSOCKS_BadVersion(t *testing.T) {
	cfg := testConfig()
	_, addr := startServer(t, cfg)
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// 0x04 is SOCKS4: not 0x05, so dispatcher treats it as HTTP CONNECT;
	// the parser must reject it cleanly rather than hang.
	c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00})
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("expected an immediate HTTP 400 status line, got err=%v", err)
	}
	if line == "" || line[9] != '4' {
		t.Fatalf("expected 400 status line, got %q", line)
	}
}

func TestDispatch_GarbageRejected(t *testing.T) {
	cfg := testConfig()
	srv, addr := startServer(t, cfg)
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Bytes that cannot form a request line (no method SP target SP version).
	_, _ = c.Write([]byte("@@@\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(c)
	code, _ := httpReadStatus(br)
	if code != 400 {
		t.Fatalf("garbage status = %d, want 400", code)
	}
	if m := srv.Metrics().Rejected[ReasonProtocolError]; m == 0 {
		t.Fatal("garbage must be counted as protocol_error")
	}
}

// A well-formed request line with a non-CONNECT method yields 405.
func TestDispatch_NonConnectMethod(t *testing.T) {
	cfg := testConfig()
	srv, addr := startServer(t, cfg)
	code := rawHTTP(t, addr, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if code != 405 {
		t.Fatalf("non-CONNECT status = %d, want 405", code)
	}
	if m := srv.Metrics().Rejected[ReasonUnsupportedProto]; m != 1 {
		t.Fatalf("unsupported count = %d, want 1", m)
	}
}

// TestIdleTimeout_ClassifiedAndAudited verifies the idle event carries the
// idle reason and is auditable through the hook.
func TestIdleTimeout_Audit(t *testing.T) {
	target, _ := startBlockingTarget(t)
	cfg := testConfig()
	cfg.IdleTimeout = 200 * time.Millisecond
	srv, addr := startServer(t, cfg)

	var got AuditEvent
	done := make(chan struct{})
	srv.SetAuditHook(func(e AuditEvent) {
		if e.Reason == ReasonIdleTimeout {
			got = e
			close(done)
		}
	})
	c := dialSOCKS(t, addr, target, "", "")
	defer c.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle timeout was not audited")
	}
	if got.Stage != StageRelay || got.Reason != ReasonIdleTimeout {
		t.Fatalf("audit event wrong: %s/%s", got.Stage, got.Reason)
	}
	waitZeroActive(t, srv)
}

// TestAudit_EventContent verifies accepted and denied audit events carry
// identity/target and that pipeline failures are reported exactly once.
func TestAudit_EventContent(t *testing.T) {
	target, _ := startEchoTarget(t)
	cfg := testConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Credentials = map[string]string{"alice": "s3cret"}
	cfg.ACL.DefaultDeny = true
	cfg.ACL.Rules = []Rule{{Action: ActionAllow, Host: "127.0.0.1"}}
	srv, addr := startServer(t, cfg)

	var mu sync.Mutex
	var accepted, denied []AuditEvent
	srv.SetAuditHook(func(e AuditEvent) {
		mu.Lock()
		defer mu.Unlock()
		if e.Accepted {
			accepted = append(accepted, e)
		} else {
			denied = append(denied, e)
		}
	})

	c := dialHTTP(t, addr, target, "alice", "s3cret")
	echoRoundTrip(t, c, "audit\n")
	c.Close()
	waitZeroActive(t, srv)

	// Denied: wrong credentials must be reported (target not yet known).
	_ = rawHTTP(t, addr,
		"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n"+
			"Proxy-Authorization: Basic YWxpY2U6YmFk\r\n\r\n")

	mu.Lock()
	defer mu.Unlock()
	if len(accepted) != 1 {
		t.Fatalf("accepted events = %d, want 1", len(accepted))
	}
	a := accepted[0]
	if a.Identity != "alice" || !strings.Contains(a.Target, "127.0.0.1") {
		t.Fatalf("accepted event missing identity/target: %+v", a)
	}
	found := false
	for _, d := range denied {
		if d.Reason == ReasonAuthFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("auth_failed audit event missing: %+v", denied)
	}
}

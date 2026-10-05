package proxy

import (
	"errors"
	"net"
	"testing"
)

func TestParseTarget_Canonicalization(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
		ip   bool
	}{
		{"127.0.0.1", 80, "127.0.0.1:80", true},
		{"[::ffff:127.0.0.1]", 80, "127.0.0.1:80", true}, // v4-mapped v6 normalized
		{"[2001:db8::1]", 443, "[2001:db8::1]:443", true},
		{"2001:db8::1", 443, "[2001:db8::1]:443", true},
		{"Example.COM", 80, "example.com:80", false},
		{"  host.test  ", 80, "host.test:80", false},
	}
	for _, c := range cases {
		got, err := parseTarget(c.host, c.port)
		if err != nil {
			t.Fatalf("parseTarget(%q): %v", c.host, err)
		}
		if got.String() != c.want {
			t.Errorf("parseTarget(%q)=%q want %q", c.host, got.String(), c.want)
		}
		if c.ip && got.IP == nil {
			t.Errorf("parseTarget(%q) expected numeric IP", c.host)
		}
		if !c.ip && got.IP != nil {
			t.Errorf("parseTarget(%q) did not expect numeric IP", c.host)
		}
	}
}

func TestParseTarget_Invalid(t *testing.T) {
	bad := []struct {
		host string
		port int
	}{
		{"", 80},
		{"127.0.0.1", 0},
		{"127.0.0.1", 70000},
		{"bad host", 80},
		{".example.com", 80},
		{"example..com", 80},
	}
	for _, c := range bad {
		if _, err := parseTarget(c.host, c.port); err == nil {
			t.Fatalf("parseTarget(%q,%d) expected error", c.host, c.port)
		} else if err.Stage != StageHandshake || err.Reason != ReasonTargetInvalid {
			t.Fatalf("parseTarget(%q,%d) wrong class: %s/%s", c.host, c.port, err.Stage, err.Reason)
		}
	}
}

func TestACL_IPNotationUnit(t *testing.T) {
	cfg := ACLConfig{
		DefaultDeny: true,
		Rules: []Rule{
			{Action: ActionAllow, Host: "127.0.0.1", Port: 8080},
		},
	}
	a := NewACL(cfg)

	allowed, _ := parseTarget("127.0.0.1", 8080)
	if err := a.Check(allowed); err != nil {
		t.Fatalf("explicit form denied: %v", err)
	}
	mapped, _ := parseTarget("[::ffff:127.0.0.1]", 8080)
	if err := a.Check(mapped); err != nil {
		t.Fatalf("v4-mapped form denied: %v", err)
	}
	denied, _ := parseTarget("127.0.0.2", 8080)
	if err := a.Check(denied); err == nil || err.Reason != ReasonTargetDenied {
		t.Fatalf("different IP should be denied, got %v", err)
	}
	deniedPort, _ := parseTarget("127.0.0.1", 9090)
	if err := a.Check(deniedPort); err == nil {
		t.Fatal("different port should be denied")
	}
}

func TestACL_HostnameSuffix(t *testing.T) {
	// Deny precedes the broad suffix allow, so the specific deny wins.
	a := NewACL(ACLConfig{
		DefaultDeny: true,
		Rules: []Rule{
			{Action: ActionDeny, Host: "evil.example.com"},
			{Action: ActionAllow, Host: ".example.com"}, // suffix
		},
	})
	for _, h := range []string{"example.com", "api.example.com"} {
		tg, _ := parseTarget(h, 443)
		if err := a.Check(tg); err != nil {
			t.Fatalf("%s should be allowed: %v", h, err)
		}
	}
	tg, _ := parseTarget("evil.example.com", 443)
	if err := a.Check(tg); err == nil {
		t.Fatal("explicit deny listed first must win over suffix allow")
	}
	tg, _ = parseTarget("notexample.com", 443)
	if err := a.Check(tg); err == nil {
		t.Fatal("substring lookalike must not match suffix")
	}

	// First-match semantics: an allow placed before the deny wins.
	b := NewACL(ACLConfig{
		DefaultDeny: true,
		Rules: []Rule{
			{Action: ActionAllow, Host: ".example.com"},
			{Action: ActionDeny, Host: "evil.example.com"},
		},
	})
	tg, _ = parseTarget("evil.example.com", 443)
	if err := b.Check(tg); err != nil {
		t.Fatalf("first-match allow must win: %v", err)
	}
}

func TestACL_CIDR(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	a := NewACL(ACLConfig{
		DefaultDeny: true,
		Rules:       []Rule{{Action: ActionAllow, CIDR: n}},
	})
	ok, _ := parseTarget("10.1.2.3", 1)
	if err := a.Check(ok); err != nil {
		t.Fatalf("CIDR member denied: %v", err)
	}
	no, _ := parseTarget("11.1.2.3", 1)
	if err := a.Check(no); err == nil {
		t.Fatal("CIDR outsider allowed")
	}
}

func TestAuthenticator(t *testing.T) {
	a := NewAuthenticator(AuthConfig{
		Enabled:     true,
		Credentials: map[string]string{"bob": "hunter2"},
	})
	if id, err := a.Authenticate("bob", "hunter2"); err != nil || !id.Authenticated {
		t.Fatalf("valid creds rejected: %v", err)
	}
	if _, err := a.Authenticate("bob", "x"); err == nil || err.Reason != ReasonAuthFailed {
		t.Fatal("wrong password must be auth_failed")
	}
	if _, err := a.Authenticate("ghost", "x"); err == nil || err.Reason != ReasonAuthFailed {
		t.Fatal("unknown user must not be distinguishable (auth_failed)")
	}
	if _, err := a.Authenticate("", ""); err == nil || err.Reason != ReasonAuthRequired {
		t.Fatal("empty user must be auth_required")
	}

	// Disabled authenticator never rejects.
	off := NewAuthenticator(AuthConfig{Enabled: false})
	if _, err := off.Authenticate("any", "thing"); err != nil {
		t.Fatalf("disabled auth rejected: %v", err)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Fatal("equal strings should compare equal")
	}
	if constantTimeEqual("abc", "abd") || constantTimeEqual("abc", "ab") {
		t.Fatal("unequal strings should compare unequal")
	}
}

func TestSocksReplyCodeMapping(t *testing.T) {
	m := map[Reason]byte{
		ReasonTargetDenied: repNotAllowed,
		ReasonDNSFailed:    repHostUnreachable,
		ReasonDialTimeout:  repTTLExpired,
		ReasonDialFailed:   repConnectionRefused,
	}
	for r, want := range m {
		if got := socksReplyCode(&ProxyError{Reason: r}); got != want {
			t.Errorf("reason %s -> %d, want %d", r, got, want)
		}
	}
}

func TestProxyErrorUnwrap(t *testing.T) {
	inner := errors.New("boom")
	e := wrapProxyError(StageDial, ReasonDialFailed, "ctx", inner)
	if !errors.Is(e, inner) {
		t.Fatal("Unwrap must expose the cause")
	}
	if e.Error() == "" {
		t.Fatal("Error() must not be empty")
	}
}

func TestHTTPBasicAuthParsing(t *testing.T) {
	_, _, ok := parseProxyBasicAuth("Basic dXNlcjpwYXNz")
	if !ok {
		t.Fatal("valid basic header rejected")
	}
	if u, p, ok := parseProxyBasicAuth("basic dXNlcjpwYXNz"); !ok || u != "user" || p != "pass" {
		t.Fatalf("case-insensitive scheme parsing failed: %q/%q/%v", u, p, ok)
	}
	if _, _, ok := parseProxyBasicAuth("Bearer xyz"); ok {
		t.Fatal("non-basic scheme accepted")
	}
	if _, _, ok := parseProxyBasicAuth("basic !!!"); ok {
		t.Fatal("malformed base64 accepted")
	}
}

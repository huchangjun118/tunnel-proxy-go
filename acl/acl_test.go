package acl

import (
	"testing"

	"github.com/huchangjun118/tunnel-proxy-go/target"
)

func mustTarget(t *testing.T, h string, p int) target.Target {
	tt, err := target.Parse(h, p)
	if err != nil {
		t.Fatal(err)
	}
	return tt
}

func TestEmptyAllows(t *testing.T) {
	a, _ := New(nil, nil)
	if a.Check(mustTarget(t, "1.2.3.4", 9999)) != ACLAllow {
		t.Fatal("empty ACL should allow all")
	}
}

func TestHostAndPort(t *testing.T) {
	a, _ := New([]string{"localhost", ".example.com", "10.0.0.1"}, []int{80, 443})
	allow := []struct {
		h string
		p int
	}{
		{"127.0.0.1", 80}, // localhost alias normalized
		{"::1", 443},      // loopback normalized
		{"api.example.com", 80},
		{"example.com", 443},
		{"10.0.0.1", 80},
	}
	for _, c := range allow {
		if a.Check(mustTarget(t, c.h, c.p)) != ACLAllow {
			t.Errorf("expected allow %s:%d", c.h, c.p)
		}
	}
	deny := []struct {
		h string
		p int
	}{
		{"evil.com", 80},
		{"10.0.0.2", 80},
		{"127.0.0.1", 22}, // port not allowed
	}
	for _, c := range deny {
		if a.Check(mustTarget(t, c.h, c.p)) != ACLDeny {
			t.Errorf("expected deny %s:%d", c.h, c.p)
		}
	}
}

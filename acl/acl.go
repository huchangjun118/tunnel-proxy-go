// Package acl implements target access control. All checks operate on
// normalized target.Target values, so different spellings of the same
// host can never bypass a rule.
package acl

import (
	"strings"

	"github.com/huchangjun118/tunnel-proxy-go/target"
)

// ACL decides whether a normalized target may be accessed.
type ACL struct {
	hosts    map[string]bool // exact host match
	suffixes []string        // rules like ".example.com"
	hasHosts bool
	ports    map[int]bool
	hasPorts bool
}

// New builds an ACL. Empty allow lists mean "allow everything".
// Host entries may be exact names ("example.com"), wildcard suffixes
// (".example.com" matches the domain and any subdomain) or IP literals.
func New(allowedHosts []string, allowedPorts []int) (*ACL, error) {
	a := &ACL{}
	if len(allowedHosts) > 0 {
		a.hasHosts = true
		a.hosts = make(map[string]bool, len(allowedHosts))
		for _, raw := range allowedHosts {
			h := strings.ToLower(strings.TrimSpace(raw))
			h = strings.TrimPrefix(h, "*.")
			if strings.HasPrefix(h, ".") {
				a.suffixes = append(a.suffixes, h) // ".example.com"
				// Also allow the apex domain itself.
				a.hosts[strings.TrimPrefix(h, ".")] = true
				continue
			}
			// Normalize IP / localhost spellings through the target package.
			if t, err := target.Parse(h, 80); err == nil {
				h = t.Host
			}
			a.hosts[h] = true
		}
	}
	if len(allowedPorts) > 0 {
		a.hasPorts = true
		a.ports = make(map[int]bool, len(allowedPorts))
		for _, p := range allowedPorts {
			a.ports[p] = true
		}
	}
	return a, nil
}

// Decision is the ACL verdict.
type Decision int

const (
	ACLDeny Decision = iota
	ACLAllow
)

// Check returns the verdict for an already-normalized target.
func (a *ACL) Check(t target.Target) Decision {
	if a.HostAllowed(t.Host) && a.PortAllowed(t.Port) {
		return ACLAllow
	}
	return ACLDeny
}

// HostAllowed reports whether the host matches the host allow list.
// An empty list allows all hosts.
func (a *ACL) HostAllowed(host string) bool {
	if !a.hasHosts {
		return true
	}
	if a.hosts[host] {
		return true
	}
	for _, suf := range a.suffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

// PortAllowed reports whether the port matches the port allow list.
// An empty list allows all ports.
func (a *ACL) PortAllowed(port int) bool {
	if !a.hasPorts {
		return true
	}
	return a.ports[port]
}

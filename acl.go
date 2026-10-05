package proxy

import (
	"net"
	"strings"
)

// Action is the policy result of an ACL rule.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Rule matches a canonical Target. It may match by:
//   - exact host (IP literal or hostname) and optional port;
//   - hostname suffix (Host beginning with "." matches the domain and any
//     sub-domain, e.g. ".example.com" matches example.com and a.example.com);
//   - CIDR for numeric IP targets;
//
// zero Port matches any port.
type Rule struct {
	Action Action
	Host   string
	Port   int
	CIDR   *net.IPNet
}

// ACLConfig configures destination access control.
type ACLConfig struct {
	// DefaultDeny rejects anything not explicitly allowed. When false the
	// policy is "allow unless explicitly denied".
	DefaultDeny bool
	Rules       []Rule
}

// ACL evaluates targets against the configured rule list.
type ACL struct {
	cfg ACLConfig
}

func NewACL(cfg ACLConfig) *ACL { return &ACL{cfg: cfg} }

// Check returns nil when the target is allowed, otherwise a classified
// StageACL/ReasonTargetDenied error. It never dials anything: the decision
// happens before any connection to the target exists.
func (a *ACL) Check(t Target) *ProxyError {
	decision := ActionAllow
	if a.cfg.DefaultDeny {
		decision = ActionDeny
	}
	for i := range a.cfg.Rules {
		r := &a.cfg.Rules[i]
		if ruleMatches(r, t) {
			decision = r.Action
			break // first matching rule wins
		}
	}
	if decision == ActionDeny {
		return newProxyError(StageACL, ReasonTargetDenied, "target not permitted: "+t.String())
	}
	return nil
}

func ruleMatches(r *Rule, t Target) bool {
	if r.Port != 0 && r.Port != t.Port {
		return false
	}
	if r.CIDR != nil {
		if t.IP == nil || !r.CIDR.Contains(t.IP) {
			return false
		}
		return true
	}
	if r.Host != "" {
		return hostMatches(r.Host, t)
	}
	// Port-only rule matches every host on that port.
	return true
}

// hostMatches performs notation-independent host comparison.
func hostMatches(pattern string, t Target) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	p = strings.TrimPrefix(p, ".")
	// Numeric IP pattern: compare numerically.
	if pip := net.ParseIP(strings.Trim(p, "[]")); pip != nil {
		return t.IP != nil && t.IP.Equal(pip)
	}
	if t.IP != nil {
		return false // hostname pattern never matches an IP target
	}
	if t.Host == p {
		return true
	}
	// Suffix match: pattern "example.com" stored after trimming the leading
	// dot; match host == pattern or host ending in ".pattern".
	return strings.HasSuffix(t.Host, "."+p)
}

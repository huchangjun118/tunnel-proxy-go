package proxy

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// LimitPolicy defines what happens when the tunnel limit is reached.
type LimitPolicy string

const (
	// PolicyReject refuses new tunnels immediately when at capacity.
	PolicyReject LimitPolicy = "reject"
	// PolicyQueue makes new tunnels wait up to QueueTimeout for a slot.
	PolicyQueue LimitPolicy = "queue"
)

// Target is a canonicalized dial destination.
type Target struct {
	Host string // lowercase hostname or normalized IP literal
	Port int    // normalized port number
	IP   net.IP // resolved IP when Host was an IP literal, otherwise nil
}

func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// address returns the dial form used by net.Dial.
func (t Target) address() string {
	if ip := t.IP; ip != nil {
		// net.JoinHostPort brackets IPv6 literals automatically.
		return net.JoinHostPort(ip.String(), strconv.Itoa(t.Port))
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Config holds all proxy configuration knobs.
type Config struct {
	// Listen is the single access address shared by CONNECT and SOCKS clients.
	Listen string

	// Auth configures front-end credential authentication.
	Auth AuthConfig
	// ACL configures destination access control.
	ACL ACLConfig

	// MaxTunnels is the maximum number of concurrently open tunnels.
	MaxTunnels int
	// LimitPolicy chooses reject vs. queue behaviour at capacity.
	LimitPolicy LimitPolicy
	// QueueTimeout bounds how long a queued tunnel may wait for a slot.
	QueueTimeout time.Duration

	// DialTimeout bounds TCP connect time to a target.
	DialTimeout time.Duration
	// HandshakeTimeout bounds the whole front-end handshake phase.
	HandshakeTimeout time.Duration
	// IdleTimeout closes a tunnel with no data transferred for this long.
	IdleTimeout time.Duration
	// MaxLifetime bounds the total lifetime of one tunnel.
	MaxLifetime time.Duration
	// HalfCloseTimeout bounds how long a tunnel stays open draining the
	// reverse direction after one side cleanly half-closes (EOF). A peer
	// that fully closes but whose target keeps the socket open is reaped
	// after this delay without waiting for the full idle timeout.
	HalfCloseTimeout time.Duration

	// BufferSize is the per-direction copy buffer size.
	BufferSize int
}

// DefaultConfig returns a configuration usable on loopback without auth or
// ACL restrictions (tests and local experimentation).
func DefaultConfig() Config {
	return Config{
		Listen:           "127.0.0.1:0",
		LimitPolicy:      PolicyReject,
		QueueTimeout:     5 * time.Second,
		DialTimeout:      5 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		IdleTimeout:      2 * time.Minute,
		HalfCloseTimeout: 5 * time.Second,
		MaxLifetime:      10 * time.Minute,
		BufferSize:       32 * 1024,
	}
}

// Validate checks configuration consistency.
func (c *Config) Validate() error {
	if c.MaxTunnels < 0 {
		return newProxyError(StageHandshake, ReasonProtocolError, "MaxTunnels must be >= 0")
	}
	if c.LimitPolicy != "" && c.LimitPolicy != PolicyReject && c.LimitPolicy != PolicyQueue {
		return newProxyError(StageHandshake, ReasonProtocolError, "invalid LimitPolicy: "+string(c.LimitPolicy))
	}
	for i, r := range c.ACL.Rules {
		if r.Action != ActionAllow && r.Action != ActionDeny {
			return newProxyError(StageACL, ReasonProtocolError,
				"invalid ACL rule action at index "+strconv.Itoa(i))
		}
	}
	return nil
}

// parseTarget canonicalizes the different host/port spellings into a Target
// so that ACL and auth decisions are independent of notation:
//   - hostnames are lower-cased and trimmed;
//   - IP literals (v4, v6, [v6], leading-zero-free forms) are normalized
//     through net.ParseIP and compared numerically;
//   - the port is validated to be in 1..65535.
//
// No DNS lookup happens here; hostname resolution is deferred to dial time so
// that failures are reported in the dial stage.
func parseTarget(host string, port int) (Target, *ProxyError) {
	h := strings.TrimSpace(host)
	h = strings.Trim(h, "[]")
	if h == "" {
		return Target{}, newProxyError(StageHandshake, ReasonTargetInvalid, "empty target host")
	}
	if port < 1 || port > 65535 {
		return Target{}, newProxyError(StageHandshake, ReasonTargetInvalid,
			"target port out of range: "+strconv.Itoa(port))
	}
	if ip := net.ParseIP(h); ip != nil {
		return Target{Host: ip.String(), Port: port, IP: ip}, nil
	}
	// Hostname: lowercase for case-insensitive matching. Reject obvious
	// nonsense (embedded spaces / control characters).
	low := strings.ToLower(h)
	if strings.ContainsAny(low, " \t\r\n") {
		return Target{}, newProxyError(StageHandshake, ReasonTargetInvalid, "illegal character in target host")
	}
	if strings.HasPrefix(low, ".") || strings.HasSuffix(low, ".") || strings.Contains(low, "..") {
		return Target{}, newProxyError(StageHandshake, ReasonTargetInvalid, "malformed target hostname")
	}
	return Target{Host: low, Port: port, IP: nil}, nil
}

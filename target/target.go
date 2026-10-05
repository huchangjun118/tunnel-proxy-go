// Package target defines the normalized target address used by both
// CONNECT and SOCKS frontends. Normalization ensures that authentication,
// ACL checks and dialing are unaffected by textual spelling variants
// (localhost vs 127.0.0.1 vs ::1, IPv6 compression, trailing dots, etc.).
package target

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Target is the canonical representation of a tunnel destination.
type Target struct {
	Host string // canonical host: domain name (lower case) or IP
	Port int    // 1..65535
}

// Canonical returns the canonical "host:port" form used by ACL matching
// and dialing. IPv6 hosts are bracketed.
func (t Target) Canonical() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String is for logging.
func (t Target) String() string { return t.Canonical() }

// LocalhostAliases are host spellings that all normalize to 127.0.0.1.
var LocalhostAliases = map[string]bool{
	"localhost":     true,
	"ip6-localhost": true,
	"ip6-loopback":  true,
}

// loopbackCanonical is the single canonical spelling for loopback.
const loopbackCanonical = "127.0.0.1"

// Parse normalizes a host/port pair. host may be a domain name or an IP
// address in any accepted textual form. No DNS is performed.
func Parse(host string, port int) (Target, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return Target{}, errors.New("target: empty host")
	}
	// Allow bracketed IPv6 literals passed in the host position.
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	h = strings.ToLower(h)

	if port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("target: port %d out of range", port)
	}

	if LocalhostAliases[h] {
		h = loopbackCanonical
	}

	// Normalize numeric IPv4 shorthands like 127.1 (inet_aton style).
	if v4, ok := parseRelaxedIPv4(h); ok {
		h = v4
	}

	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			// Covers ::ffff:1.2.3.4 and short forms like 127.1.
			h = v4.String()
		} else {
			h = ip.String()
		}
		if ip.IsLoopback() {
			h = loopbackCanonical
		}
	} else {
		// Domain name: drop a single trailing dot (FQDN spelling).
		h = strings.TrimSuffix(h, ".")
		if !validDomain(h) {
			return Target{}, fmt.Errorf("target: invalid host %q", host)
		}
	}

	return Target{Host: h, Port: port}, nil
}

// ParseHostPort parses "host:port" or "[v6]:port" and normalizes it.
func ParseHostPort(s string) (Target, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return Target{}, fmt.Errorf("target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Target{}, fmt.Errorf("target: invalid port %q: %w", portStr, err)
	}
	return Parse(host, port)
}

// parseRelaxedIPv4 accepts numeric IPv4 spellings such as "127.1",
// "127.0.1", "2130706433" (inet_aton conventions) and returns the
// canonical dotted-quad form.
func parseRelaxedIPv4(h string) (string, bool) {
	if strings.Count(h, ".") == 0 {
		// Plain integer form.
		if n, err := strconv.ParseUint(h, 10, 32); err == nil {
			return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).String(), true
		}
		return "", false
	}
	parts := strings.Split(h, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return "", false
	}
	var vals [4]uint64
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return "", false
		}
		vals[i] = n
	}
	var b [4]byte
	switch len(parts) {
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return "", false
		}
		b[0] = byte(vals[0])
		b[1] = byte(vals[1] >> 16)
		b[2] = byte(vals[1] >> 8)
		b[3] = byte(vals[1])
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return "", false
		}
		b[0] = byte(vals[0])
		b[1] = byte(vals[1])
		b[2] = byte(vals[2] >> 8)
		b[3] = byte(vals[2])
	case 4:
		for i := 0; i < 4; i++ {
			if vals[i] > 0xff {
				return "", false
			}
			b[i] = byte(vals[i])
		}
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String(), true
}

func validDomain(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, "-") ||
		strings.Contains(h, "..") {
		return false
	}
	return true
}

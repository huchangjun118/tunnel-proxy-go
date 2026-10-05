// Package auth implements credential-based access authentication shared
// by the CONNECT (Proxy-Authorization Basic) and SOCKS5 (RFC 1929
// username/password) frontends. Both frontends feed the same parsed
// credential pair into Check, so the semantics are identical.
package auth

import (
	"crypto/subtle"
)

// Authenticator validates client credentials using constant-time comparison.
type Authenticator struct {
	enabled bool
	creds   map[string]string
}

// New creates an Authenticator.
func New(enabled bool, creds map[string]string) *Authenticator {
	copied := make(map[string]string, len(creds))
	for u, p := range creds {
		copied[u] = p
	}
	return &Authenticator{enabled: enabled, creds: copied}
}

// Result is the outcome of an authentication attempt.
type Result int

const (
	// AuthDisabled means authentication is not configured; everyone passes.
	AuthDisabled Result = iota
	// AuthMissing means credentials were required but not presented.
	AuthMissing
	// AuthInvalid means credentials were presented but did not match.
	AuthInvalid
	// AuthOK means the credentials matched.
	AuthOK
)

// Check validates a credential pair. The result distinguishes "no
// credentials" from "bad credentials", which the frontends map to
// different, auditable rejection responses.
func (a *Authenticator) Check(user, pass string) Result {
	if !a.enabled {
		return AuthDisabled
	}
	if user == "" || pass == "" {
		return AuthMissing
	}
	expected, ok := a.creds[user]
	if !ok {
		// Still touch comparison work to reduce timing side channels.
		subtle.ConstantTimeCompare([]byte(pass), []byte(pass))
		return AuthInvalid
	}
	if subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) != 1 {
		return AuthInvalid
	}
	return AuthOK
}

// Enabled reports whether authentication is required.
func (a *Authenticator) Enabled() bool { return a.enabled }

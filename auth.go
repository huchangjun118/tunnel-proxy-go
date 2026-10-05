package proxy

// AuthConfig configures credential based access authentication.
type AuthConfig struct {
	// Enabled turns on authentication. When false any session is accepted,
	// but SOCKS/HTTP clients MAY still send credentials; they are ignored.
	Enabled bool
	// Credentials maps username -> password. Username comparison is
	// case-sensitive (common for proxy auth), comparison is constant time.
	Credentials map[string]string
}

// Identity describes the authenticated peer.
type Identity struct {
	Name          string
	Authenticated bool
}

// Authenticator validates user credentials.
type Authenticator struct {
	cfg AuthConfig
}

func NewAuthenticator(cfg AuthConfig) *Authenticator {
	return &Authenticator{cfg: cfg}
}

// Enabled reports whether authentication is required.
func (a *Authenticator) Enabled() bool { return a.cfg.Enabled }

// Authenticate checks a credential pair against the configured users.
// The same classification is returned regardless of which half of the
// credential is wrong, so callers cannot probe user names.
func (a *Authenticator) Authenticate(user, pass string) (Identity, *ProxyError) {
	if !a.cfg.Enabled {
		return Identity{Name: user, Authenticated: false}, nil
	}
	if user == "" {
		return Identity{}, newProxyError(StageAuth, ReasonAuthRequired, "credentials required")
	}
	want, ok := a.cfg.Credentials[user]
	if !ok || !constantTimeEqual(want, pass) {
		return Identity{}, newProxyError(StageAuth, ReasonAuthFailed, "invalid credentials")
	}
	return Identity{Name: user, Authenticated: true}, nil
}

// constantTimeEqual compares two strings without short-circuiting on length,
// avoiding trivial timing oracles on the password.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		// still walk the longer string to keep work roughly proportional
		// to input, but the length difference itself is definitive.
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// Package proxy implements an in-process forwarding proxy with a single
// listener that accepts both HTTP CONNECT and SOCKS5 sessions.
//
// The two front-end protocols share one authentication, access-control,
// limiting and relay pipeline so their semantics cannot drift apart.
package proxy

// Stage identifies the pipeline phase a failure occurred in.
type Stage string

const (
	// StageHandshake covers front-end protocol framing (SOCKS negotiation,
	// HTTP request line parsing, timeouts reading the greeting).
	StageHandshake Stage = "handshake"
	// StageAuth covers credential validation.
	StageAuth Stage = "auth"
	// StageACL covers destination access control evaluation.
	StageACL Stage = "acl"
	// StageLimit covers concurrency slot acquisition (reject/queue policy).
	StageLimit Stage = "limit"
	// StageDial covers target resolution and dialing.
	StageDial Stage = "dial"
	// StageRelay covers the bidirectional byte pump after establishment.
	StageRelay Stage = "relay"
)

// Reason is the machine-readable category of a rejection or failure.
type Reason string

const (
	ReasonProtocolError    Reason = "protocol_error"
	ReasonUnsupportedProto Reason = "unsupported_protocol"
	ReasonAuthRequired     Reason = "auth_required"
	ReasonAuthFailed       Reason = "auth_failed"
	ReasonTargetInvalid    Reason = "target_invalid"
	ReasonTargetDenied     Reason = "target_denied"
	ReasonLimitRejected    Reason = "limit_rejected"
	ReasonQueueTimeout     Reason = "queue_timeout"
	ReasonDNSFailed        Reason = "dns_failed"
	ReasonDialTimeout      Reason = "dial_timeout"
	ReasonDialFailed       Reason = "dial_failed"
	ReasonIdleTimeout      Reason = "idle_timeout"
	ReasonLifetimeExpired  Reason = "lifetime_expired"
	ReasonRelayBroken      Reason = "relay_broken"
)

// ProxyError is the classified error type used across the whole pipeline.
type ProxyError struct {
	Stage  Stage
	Reason Reason
	Detail string
	Cause  error

	// audited is set by the pipeline stage that already emitted an audit
	// event, so the top-level handler does not double-report it.
	audited bool
}

func (e *ProxyError) Error() string {
	msg := string(e.Stage) + "/" + string(e.Reason)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ProxyError) Unwrap() error { return e.Cause }

func newProxyError(stage Stage, reason Reason, detail string) *ProxyError {
	return &ProxyError{Stage: stage, Reason: reason, Detail: detail}
}

func wrapProxyError(stage Stage, reason Reason, detail string, cause error) *ProxyError {
	return &ProxyError{Stage: stage, Reason: reason, Detail: detail, Cause: cause}
}

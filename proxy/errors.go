// Package proxy contains the tunnel engine shared by the CONNECT and
// SOCKS5 frontends, plus the two protocol-specific adapters.
package proxy

// Stage identifies at which phase of the pipeline an error happened.
// Keeping the phase explicit makes failures explainable, auditable and
// correctly classified in metrics and frontend replies.
type Stage string

const (
	StageProtocol Stage = "protocol" // malformed request / bad framing
	StageAuth     Stage = "auth"     // missing or invalid credentials
	StageACL      Stage = "acl"      // target not permitted
	StageResolve  Stage = "resolve"  // target name / address unusable
	StageDial     Stage = "dial"     // TCP connect to target failed
	StageLimit    Stage = "limit"    // concurrency limit reached (reject)
	StageQueue    Stage = "queue"    // queued wait timed out / canceled
	StageIO       Stage = "io"       // relay read/write failure
)

// Cause is a machine-readable reason within a stage.
type Cause string

const (
	CauseMalformed       Cause = "malformed_request"
	CauseBadVersion      Cause = "bad_version"
	CauseUnsupportedCmd  Cause = "unsupported_command"
	CauseMissingCreds    Cause = "missing_credentials"
	CauseInvalidCreds    Cause = "invalid_credentials"
	CauseHostDenied      Cause = "host_denied"
	CausePortDenied      Cause = "port_denied"
	CauseInvalidHost     Cause = "invalid_host"
	CauseDialTimeout     Cause = "dial_timeout"
	CauseDialRefused     Cause = "connection_refused"
	CauseDialUnreachable Cause = "network_unreachable"
	CauseLimitReached    Cause = "limit_reached"
	CauseQueueTimeout    Cause = "queue_timeout"
	CauseRelay           Cause = "relay_error"
)

// Error wraps a failure with its pipeline stage and cause category.
type Error struct {
	Stage   Stage
	Cause   Cause
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return string(e.Stage) + "/" + string(e.Cause) + ": " + e.Message
	}
	return string(e.Stage) + "/" + string(e.Cause)
}

// NewError builds a staged error.
func NewError(stage Stage, cause Cause, msg string) *Error {
	return &Error{Stage: stage, Cause: cause, Message: msg}
}

package proxy

import "sync/atomic"

// MetricsSnapshot is a consistent point-in-time view of proxy counters.
type MetricsSnapshot struct {
	ActiveTunnels int64
	TotalTunnels  int64
	BytesUp       int64 // client -> target
	BytesDown     int64 // target -> client
	Rejected      map[Reason]int64
	Errors        map[Stage]int64
}

// Metrics holds concurrency-safe runtime counters.
type Metrics struct {
	active atomic.Int64
	total  atomic.Int64
	up     atomic.Int64
	down   atomic.Int64

	// Rejected is keyed by Reason, Errors by Stage. Maps are preallocated
	// with fixed keys so atomic ops alone keep them consistent; the mutex is
	// only used while copying out the snapshot.
	rejected map[Reason]*atomic.Int64
	errors   map[Stage]*atomic.Int64
}

// NewMetrics constructs zeroed counters with fixed classification keys.
func NewMetrics() *Metrics {
	m := &Metrics{
		rejected: make(map[Reason]*atomic.Int64, len(allReasons)),
		errors:   make(map[Stage]*atomic.Int64, len(allStages)),
	}
	for _, r := range allReasons {
		m.rejected[r] = new(atomic.Int64)
	}
	for _, s := range allStages {
		m.errors[s] = new(atomic.Int64)
	}
	return m
}

var allReasons = []Reason{
	ReasonProtocolError, ReasonUnsupportedProto, ReasonAuthRequired,
	ReasonAuthFailed, ReasonTargetInvalid, ReasonTargetDenied,
	ReasonLimitRejected, ReasonQueueTimeout, ReasonDNSFailed,
	ReasonDialTimeout, ReasonDialFailed, ReasonIdleTimeout,
	ReasonLifetimeExpired, ReasonRelayBroken,
}

var allStages = []Stage{
	StageHandshake, StageAuth, StageACL, StageLimit, StageDial, StageRelay,
}

func (m *Metrics) tunnelOpened() {
	m.active.Add(1)
	m.total.Add(1)
}

func (m *Metrics) tunnelClosed() {
	m.active.Add(-1)
}

func (m *Metrics) addUpstream(n int64) {
	if n > 0 {
		m.up.Add(n)
	}
}

func (m *Metrics) addDownstream(n int64) {
	if n > 0 {
		m.down.Add(n)
	}
}

// recordReject counts a pre-establishment rejection.
func (m *Metrics) recordReject(r Reason) {
	if c := m.rejected[r]; c != nil {
		c.Add(1)
	}
}

// recordError counts any classified failure (including rejections).
func (m *Metrics) recordError(s Stage) {
	if c := m.errors[s]; c != nil {
		c.Add(1)
	}
}

// record is a convenience used by the pipeline.
func (m *Metrics) record(e *ProxyError) {
	if e == nil {
		return
	}
	m.recordError(e.Stage)
	if isRejection(e) {
		m.recordReject(e.Reason)
	}
}

// isRejection reports whether the error represents a session refused before
// the tunnel was established (handshake/auth/acl/limit categories).
func isRejection(e *ProxyError) bool {
	switch e.Stage {
	case StageAuth, StageACL, StageLimit:
		return true
	case StageHandshake:
		return e.Reason == ReasonAuthRequired || e.Reason == ReasonAuthFailed ||
			e.Reason == ReasonTargetInvalid || e.Reason == ReasonUnsupportedProto ||
			e.Reason == ReasonProtocolError
	}
	return false
}

// Snapshot returns a consistent copy safe to read while sessions churn.
func (m *Metrics) Snapshot() MetricsSnapshot {
	snap := MetricsSnapshot{
		ActiveTunnels: m.active.Load(),
		TotalTunnels:  m.total.Load(),
		BytesUp:       m.up.Load(),
		BytesDown:     m.down.Load(),
		Rejected:      make(map[Reason]int64, len(m.rejected)),
		Errors:        make(map[Stage]int64, len(m.errors)),
	}
	for k, v := range m.rejected {
		snap.Rejected[k] = v.Load()
	}
	for k, v := range m.errors {
		snap.Errors[k] = v.Load()
	}
	return snap
}

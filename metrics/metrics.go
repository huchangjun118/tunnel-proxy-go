// Package metrics provides concurrency-safe operational counters:
// active/idle tunnel gauges, cumulative byte counters and rejection /
// error classification counters. All updates are atomic so values stay
// consistent under frequent connect/disconnect churn.
package metrics

import (
	"encoding/json"
	"sync/atomic"
)

// Stats is a point-in-time snapshot of server counters.
type Stats struct {
	ActiveTunnels int64 `json:"active_tunnels"`
	TotalTunnels  int64 `json:"total_tunnels"`

	BytesClientToTarget int64 `json:"bytes_client_to_target"`
	BytesTargetToClient int64 `json:"bytes_target_to_client"`

	RejectedAuth  int64 `json:"rejected_auth"`
	RejectedACL   int64 `json:"rejected_acl"`
	RejectedLimit int64 `json:"rejected_limit"`
	RejectedQueue int64 `json:"rejected_queue"`

	ErrorsResolve  int64 `json:"errors_resolve"`
	ErrorsDial     int64 `json:"errors_dial"`
	ErrorsIO       int64 `json:"errors_io"`
	ErrorsProtocol int64 `json:"errors_protocol"`
}

// Registry stores all counters.
type Registry struct {
	active      atomic.Int64
	total       atomic.Int64
	bytesUp     atomic.Int64
	bytesDown   atomic.Int64
	rejectAuth  atomic.Int64
	rejectACL   atomic.Int64
	rejectLimit atomic.Int64
	rejectQueue atomic.Int64
	errResolve  atomic.Int64
	errDial     atomic.Int64
	errIO       atomic.Int64
	errProtocol atomic.Int64
}

// NewRegistry creates a Registry.
func NewRegistry() *Registry { return &Registry{} }

// TunnelOpened increments the active gauge and lifetime counter.
func (r *Registry) TunnelOpened() {
	r.active.Add(1)
	r.total.Add(1)
}

// TunnelClosed decrements the active gauge.
func (r *Registry) TunnelClosed() {
	if r.active.Add(-1) < 0 {
		r.active.Store(0)
	}
}

// AddBytesClientToTarget adds relayed bytes in the client -> target direction.
func (r *Registry) AddBytesClientToTarget(n int64) {
	if n > 0 {
		r.bytesUp.Add(n)
	}
}

// AddBytesTargetToClient adds relayed bytes in the target -> client direction.
func (r *Registry) AddBytesTargetToClient(n int64) {
	if n > 0 {
		r.bytesDown.Add(n)
	}
}

func (r *Registry) RejectedAuth()  { r.rejectAuth.Add(1) }
func (r *Registry) RejectedACL()   { r.rejectACL.Add(1) }
func (r *Registry) RejectedLimit() { r.rejectLimit.Add(1) }
func (r *Registry) RejectedQueue() { r.rejectQueue.Add(1) }

func (r *Registry) ErrorResolve()  { r.errResolve.Add(1) }
func (r *Registry) ErrorDial()     { r.errDial.Add(1) }
func (r *Registry) ErrorIO()       { r.errIO.Add(1) }
func (r *Registry) ErrorProtocol() { r.errProtocol.Add(1) }

// Snapshot returns a point-in-time copy of all counters.
func (r *Registry) Snapshot() Stats {
	return Stats{
		ActiveTunnels:       r.active.Load(),
		TotalTunnels:        r.total.Load(),
		BytesClientToTarget: r.bytesUp.Load(),
		BytesTargetToClient: r.bytesDown.Load(),
		RejectedAuth:        r.rejectAuth.Load(),
		RejectedACL:         r.rejectACL.Load(),
		RejectedLimit:       r.rejectLimit.Load(),
		RejectedQueue:       r.rejectQueue.Load(),
		ErrorsResolve:       r.errResolve.Load(),
		ErrorsDial:          r.errDial.Load(),
		ErrorsIO:            r.errIO.Load(),
		ErrorsProtocol:      r.errProtocol.Load(),
	}
}

// MarshalJSON renders the current snapshot as JSON.
func (r *Registry) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Snapshot())
}

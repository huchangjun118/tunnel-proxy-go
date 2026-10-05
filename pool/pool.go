// Package pool enforces the maximum number of concurrently running
// tunnels. When capacity is reached callers are either rejected
// immediately (PolicyReject) or queued for up to a bounded time
// (PolicyQueue). Acquire never blocks indefinitely and honors the
// passed context, so a slow client cannot exhaust accept handling.
package pool

import (
	"context"
	"sync/atomic"
	"time"
)

// Policy defines overflow behavior.
type Policy int

const (
	// PolicyReject rejects when at capacity.
	PolicyReject Policy = iota
	// PolicyQueue waits for a free slot up to QueueTimeout.
	PolicyQueue
)

// Pool limits the number of concurrently running tunnels.
type Pool struct {
	max          int
	policy       Policy
	queueTimeout time.Duration
	slots        chan struct{} // nil in unlimited mode
	count        atomic.Int64  // used in unlimited mode
}

// ReleaseFunc releases an acquired slot; safe to call multiple times.
type ReleaseFunc func()

// New creates a Pool. max <= 0 means unlimited.
func New(max int, policy Policy, queueTimeout time.Duration) *Pool {
	p := &Pool{max: max, policy: policy, queueTimeout: queueTimeout}
	if max <= 0 {
		return p
	}
	p.slots = make(chan struct{}, max)
	return p
}

// Acquire tries to occupy a slot. It returns a ReleaseFunc and true on
// success, or nil and false when rejected / timed out / canceled.
func (p *Pool) Acquire(ctx context.Context) (ReleaseFunc, bool) {
	if p.slots == nil {
		p.count.Add(1)
		var done atomic.Bool
		return func() {
			if done.CompareAndSwap(false, true) {
				p.count.Add(-1)
			}
		}, true
	}

	if p.policy == PolicyReject {
		select {
		case p.slots <- struct{}{}:
		default:
			return nil, false
		}
	} else {
		var qctx context.Context
		var cancel context.CancelFunc
		if p.queueTimeout > 0 {
			qctx, cancel = context.WithTimeout(ctx, p.queueTimeout)
		} else {
			qctx, cancel = context.WithCancel(ctx)
		}
		defer cancel()
		select {
		case p.slots <- struct{}{}:
		case <-qctx.Done():
			return nil, false
		}
	}

	var done atomic.Bool
	return func() {
		if done.CompareAndSwap(false, true) {
			<-p.slots
		}
	}, true
}

// Active returns the number of currently occupied slots.
func (p *Pool) Active() int {
	if p.slots == nil {
		return int(p.count.Load())
	}
	return len(p.slots)
}

// Queues reports whether this pool waits when saturated.
func (p *Pool) Queues() bool { return p.policy == PolicyQueue }

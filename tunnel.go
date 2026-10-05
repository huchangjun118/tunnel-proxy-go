package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// TunnelManager enforces the concurrent tunnel limit and queue policy.
type TunnelManager struct {
	cfg Config
	sem chan struct{}
}

func NewTunnelManager(cfg Config) *TunnelManager {
	max := cfg.MaxTunnels
	if max <= 0 {
		max = 1
	}
	return &TunnelManager{
		cfg: cfg,
		sem: make(chan struct{}, max),
	}
}

// Acquire reserves a tunnel slot. With PolicyReject a full pool yields
// ReasonLimitRejected immediately; with PolicyQueue the caller waits until a
// slot is released or ctx (bounded by QueueTimeout / server shutdown) ends.
// The returned release func frees the slot and must be called exactly once.
func (m *TunnelManager) Acquire(ctx context.Context) (func(), *ProxyError) {
	if m.cfg.LimitPolicy == PolicyQueue {
		select {
		case m.sem <- struct{}{}:
			return m.release, nil
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, newProxyError(StageLimit, ReasonQueueTimeout,
					"timed out waiting for a tunnel slot")
			}
			return nil, newProxyError(StageLimit, ReasonQueueTimeout,
				"queue wait cancelled: "+ctx.Err().Error())
		}
	}
	select {
	case m.sem <- struct{}{}:
		return m.release, nil
	default:
		return nil, newProxyError(StageLimit, ReasonLimitRejected,
			"tunnel concurrency limit reached")
	}
}

func (m *TunnelManager) release() {
	select {
	case <-m.sem:
	default:
		// Acquire/release are paired by construction; guard against bugs.
		panic("tunnel: releasing an unacquired slot")
	}
}

type closeReader interface{ CloseRead() error }
type closeWriter interface{ CloseWrite() error }

// deadlineConn keeps a per-direction read deadline fresh on every successful
// read, implementing the single-tunnel idle timeout.
type deadlineConn struct {
	net.Conn
	idle time.Duration
}

func (d deadlineConn) Read(p []byte) (int, error) {
	if d.idle > 0 {
		_ = d.Conn.SetReadDeadline(time.Now().Add(d.idle))
	}
	return d.Conn.Read(p)
}

// relay pumps bytes between the client and the target. It returns once both
// directions have terminated, the tunnel exceeds its total lifetime, or a
// non-benign I/O error occurs. Neither connection is closed here: the caller
// owns both and performs the final close exactly once.
//
// Teardown semantics:
//   - clean EOF on one read side is propagated with CloseWrite to the other
//     side (real TCP half-close); the opposite direction keeps draining until
//     it ends too, or until halfCloseTimeout elapses with no end-of-stream,
//     after which both connections are forcibly closed and the slot released;
//   - a non-benign error in one direction forcibly closes both ends at once
//     so the other direction cannot remain blocked in Read; errors caused
//     solely by this forced wake-up are not counted.
func relay(client, target net.Conn, idleTimeout, maxLifetime, halfCloseTimeout time.Duration, bufSize int, m *Metrics) *ProxyError {
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	halfCloseTimeout = nonZero(halfCloseTimeout)

	var expired atomic.Bool
	lifetime := time.NewTimer(nonZero(maxLifetime))
	stop := make(chan struct{})
	defer close(stop)
	force := func() {
		_ = client.Close()
		_ = target.Close()
	}
	go func() {
		select {
		case <-lifetime.C:
			expired.Store(true)
			force()
		case <-stop:
		}
	}()

	var halfExpired atomic.Bool
	errCh := make(chan *ProxyError, 2)
	go pump(client, target, m.addUpstream, idleTimeout, bufSize, errCh, "client->target")
	go pump(target, client, m.addDownstream, idleTimeout, bufSize, errCh, "target->client")

	e1 := <-errCh
	var e2 *ProxyError
	if e1 != nil {
		// Abnormal end in one direction: abort the other immediately.
		force()
		e2 = <-errCh
	} else {
		// First side ended cleanly with a half-close. Drain the reverse
		// direction, bounded by the half-close grace period.
		drain := time.NewTimer(halfCloseTimeout)
		select {
		case e2 = <-errCh:
			drain.Stop()
		case <-drain.C:
			halfExpired.Store(true)
			force()
			e2 = <-errCh
		}
	}
	lifetime.Stop()

	if expired.Load() {
		return newProxyError(StageRelay, ReasonLifetimeExpired, "tunnel reached max lifetime")
	}
	if halfExpired.Load() {
		return newProxyError(StageRelay, ReasonIdleTimeout,
			"peer half-closed and reverse direction did not end in time")
	}
	if e1 != nil {
		return e1
	}
	return e2
}

func nonZero(d time.Duration) time.Duration {
	if d <= 0 {
		return 24 * time.Hour
	}
	return d
}

// pump copies src -> dst with read-side idle deadlines, byte accounting and
// half-close propagation. It sends exactly one result on errCh: nil for a
// clean EOF, otherwise the classified failure.
func pump(src, dst net.Conn, count func(int64), idle time.Duration, bufSize int, errCh chan<- *ProxyError, dir string) {
	r := deadlineConn{Conn: src, idle: idle}
	buf := make([]byte, bufSize)
	var classified *ProxyError
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				count(int64(nw))
			}
			if ew != nil {
				classified = classifyRelayIO(ew, dir+" write")
				break
			}
			if nr != nw {
				classified = newProxyError(StageRelay, ReasonRelayBroken, dir+" short write")
				break
			}
		}
		if er != nil {
			classified = classifyRelayIO(er, dir+" read")
			break
		}
	}
	// A clean EOF propagates the FIN to the peer's read side. A forcibly
	// aborted read (ErrClosed) is an internal wake-up: do not half-close.
	if classified == nil {
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}
	errCh <- classified
}

func classifyRelayIO(err error, dir string) *ProxyError {
	if errors.Is(err, io.EOF) {
		// Includes wrapped/buffered EOF (e.g. bufio.Reader after the last
		// payload byte): a clean end-of-stream, never a relay failure.
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		// Forcible teardown triggered by the other pump or server shutdown:
		// the originating pump reports the real cause; this side is silent.
		return nil
	}
	if isPeerClosedWrite(err) {
		// The peer fully closed while the opposite direction was finishing:
		// a late write surfaces EPIPE/ECONNRESET. This is a normal outcome of
		// ordered teardown, not a broken tunnel.
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return wrapProxyError(StageRelay, ReasonIdleTimeout, dir+" idle timeout", err)
	}
	return wrapProxyError(StageRelay, ReasonRelayBroken, dir+" failed", err)
}

// isPeerClosedWrite reports whether err is the kernel's "write to a socket
// whose peer has closed" indication (EPIPE/ECONNRESET on POSIX, WSAECONNRESET
// on Windows).
func isPeerClosedWrite(err error) bool {
	return isEPIPE(err) || isECONNRESET(err)
}

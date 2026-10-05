package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/acl"
	"github.com/huchangjun118/tunnel-proxy-go/auth"
	"github.com/huchangjun118/tunnel-proxy-go/metrics"
	"github.com/huchangjun118/tunnel-proxy-go/pool"
	"github.com/huchangjun118/tunnel-proxy-go/target"
)

// Engine performs auth, ACL, pool admission, target dialing and the
// bidirectional relay. Both frontends call the same methods, so the
// semantics of authentication, target resolution, access control and
// connection establishment are identical for CONNECT and SOCKS5.
type Engine struct {
	authn *auth.Authenticator
	acl   *acl.ACL
	pool  *pool.Pool
	reg   *metrics.Registry

	dialTimeout  time.Duration
	idleTimeout  time.Duration
	totalTimeout time.Duration
	bufSize      int
	dialer       Dialer
}

// EngineDeps bundles engine dependencies.
type EngineDeps struct {
	Authenticator *auth.Authenticator
	ACL           *acl.ACL
	Pool          *pool.Pool
	Metrics       *metrics.Registry
	DialTimeout   time.Duration
	IdleTimeout   time.Duration
	TotalTimeout  time.Duration
	BufferBytes   int
	Dialer        Dialer
}

// Dialer dials target addresses (abstracted for tests).
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type stdDialer struct{ d net.Dialer }

func (s stdDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.d.DialContext(ctx, network, addr)
}

// NewEngine constructs an Engine.
func NewEngine(deps EngineDeps) *Engine {
	d := deps.Dialer
	if d == nil {
		d = stdDialer{d: net.Dialer{}}
	}
	bs := deps.BufferBytes
	if bs <= 0 {
		bs = 32 * 1024
	}
	return &Engine{
		authn:        deps.Authenticator,
		acl:          deps.ACL,
		pool:         deps.Pool,
		reg:          deps.Metrics,
		dialTimeout:  deps.DialTimeout,
		idleTimeout:  deps.IdleTimeout,
		totalTimeout: deps.TotalTimeout,
		bufSize:      bs,
		dialer:       d,
	}
}

// Authn exposes the shared authenticator so frontends that must answer
// a sub-negotiation early (SOCKS5 RFC 1929) can apply the exact same
// credential check before reading the tunnel request.
func (e *Engine) Authn() *auth.Authenticator { return e.authn }

// Metrics exposes the registry to the frontends.
func (e *Engine) Metrics() *metrics.Registry { return e.reg }

// Admission is the result of a successful Admit call.
type Admission struct {
	Upstream net.Conn
	release  pool.ReleaseFunc
	cancel   context.CancelFunc
	ctx      context.Context
}

// Admit runs the pre-tunnel pipeline: authentication, access control,
// concurrency admission and target dial. On success it returns the
// upstream connection and a cleanup; the frontend must then write its
// success frame and call ServeTunnel. No upstream socket exists on any
// error path, so rejected/queued/failed requests never touch the target.
func (e *Engine) Admit(client net.Conn, t target.Target, user, pass string) (*Admission, *Error) {
	return e.admit(client.RemoteAddr().String(), t, user, pass, true)
}

// AdmitPreAuthenticated is used by frontends that performed the shared
// credential check during their own handshake (SOCKS5 user/password
// sub-negotiation) and already counted an auth rejection. It runs the
// same pipeline but never double-counts an auth failure.
func (e *Engine) AdmitPreAuthenticated(remote string, t target.Target, user, pass string) (*Admission, *Error) {
	return e.admit(remote, t, user, pass, false)
}

func (e *Engine) admit(remote string, t target.Target, user, pass string, countAuth bool) (*Admission, *Error) {
	// 1. Authentication.
	switch e.authn.Check(user, pass) {
	case auth.AuthMissing:
		if countAuth {
			e.reg.RejectedAuth()
		}
		log.Printf("audit reject remote=%s target=%s stage=auth cause=missing_credentials", remote, t.Canonical())
		return nil, NewError(StageAuth, CauseMissingCreds, "credentials required")
	case auth.AuthInvalid:
		if countAuth {
			e.reg.RejectedAuth()
		}
		log.Printf("audit reject remote=%s user=%q target=%s stage=auth cause=invalid_credentials", remote, user, t.Canonical())
		return nil, NewError(StageAuth, CauseInvalidCreds, "invalid credentials")
	}

	// 2. Access control — before any network attempt.
	hostOK := e.acl.HostAllowed(t.Host)
	portOK := e.acl.PortAllowed(t.Port)
	if !hostOK || !portOK {
		e.reg.RejectedACL()
		cause := CauseHostDenied
		if !portOK && hostOK {
			cause = CausePortDenied
		}
		log.Printf("audit reject remote=%s user=%q target=%s stage=acl cause=%s", remote, user, t.Canonical(), cause)
		return nil, NewError(StageACL, cause, "target "+t.Canonical()+" not allowed")
	}

	// 3. Concurrency admission.
	ctx, cancel := context.WithCancel(context.Background())
	if e.totalTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), e.totalTimeout)
	}
	release, ok := e.pool.Acquire(ctx)
	if !ok {
		cancel()
		// Distinguish a timed-out/canceled queue wait from an immediate
		// capacity rejection by inspecting the configured policy.
		if e.pool.Queues() && ctx.Err() != nil {
			e.reg.RejectedQueue()
			log.Printf("audit reject remote=%s target=%s stage=queue cause=timeout", remote, t.Canonical())
			return nil, NewError(StageQueue, CauseQueueTimeout, "queue wait exceeded tunnel timeout")
		}
		e.reg.RejectedLimit()
		log.Printf("audit reject remote=%s target=%s stage=limit cause=at_capacity", remote, t.Canonical())
		return nil, NewError(StageLimit, CauseLimitReached, "max tunnels reached")
	}

	// 4. Bounded dial.
	dialCtx, dialCancel := ctx, func() {}
	if e.dialTimeout > 0 {
		dialCtx, dialCancel = context.WithTimeout(ctx, e.dialTimeout)
	}
	upstream, err := e.dialer.DialContext(dialCtx, "tcp", t.Canonical())
	dialCancel()
	if err != nil {
		release()
		cancel()
		perr := e.classifyDialError(err)
		log.Printf("audit failure remote=%s target=%s stage=%s cause=%s msg=%q", remote, t.Canonical(), perr.Stage, perr.Cause, perr.Message)
		return nil, perr
	}

	log.Printf("audit accept remote=%s user=%q target=%s", remote, user, t.Canonical())
	return &Admission{
		Upstream: upstream,
		release:  release,
		cancel:   cancel,
		ctx:      ctx,
	}, nil
}

// Fail releases all resources held by a failed admission cleanup; it is
// a no-op helper for frontends that return early after a dial failure.

// Release tears down an admission without serving a tunnel (e.g. the
// client vanished while the success frame was written).
func (a *Admission) Release() {
	if a == nil {
		return
	}
	_ = a.Upstream.Close()
	a.release()
	a.cancel()
}

// ServeTunnel runs the bidirectional relay after the frontend has sent
// its success frame. clientReader is the reader the frontends parsed
// the handshake from (a shared bufio.Reader); any tunnel bytes it
// buffered past the handshake are delivered transparently. It blocks
// until both directions finish and guarantees full resource cleanup.
func (e *Engine) ServeTunnel(adm *Admission, client net.Conn, clientReader io.Reader) {
	downstream := client
	if clientReader != nil {
		// Do NOT prepend buffered bytes separately: clientReader already
		// owns the connection's read path (e.g. the dispatcher's
		// bufio.Reader). Wrapping it again would double-consume buffered
		// data.
		downstream = &readerConn{Conn: client, r: clientReader}
	}

	e.reg.TunnelOpened()
	defer e.reg.TunnelClosed()
	defer adm.cancel()
	defer adm.release()
	defer adm.Upstream.Close()

	e.relay(adm.ctx, downstream, adm.Upstream)
}

// classifyDialError maps dial failures to the resolve/dial stage.
func (e *Engine) classifyDialError(err error) *Error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		e.reg.ErrorResolve()
		return NewError(StageResolve, CauseInvalidHost, dnsErr.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		e.reg.ErrorDial()
		return NewError(StageDial, CauseDialTimeout, "dial timed out")
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		e.reg.ErrorDial()
		switch {
		case errors.Is(opErr.Err, syscall.ECONNREFUSED):
			return NewError(StageDial, CauseDialRefused, opErr.Error())
		case errors.Is(opErr.Err, syscall.ENETUNREACH), errors.Is(opErr.Err, syscall.EHOSTUNREACH):
			return NewError(StageDial, CauseDialUnreachable, opErr.Error())
		}
		return NewError(StageDial, CauseDialRefused, opErr.Error())
	}
	e.reg.ErrorDial()
	return NewError(StageDial, CauseDialRefused, err.Error())
}

// readerConn prepends buffered bytes in front of a net.Conn.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite forwards to the underlying connection so half-close is not
// swallowed by the buffering wrapper.
func (c *readerConn) CloseWrite() error {
	if hc, ok := c.Conn.(halfCloseConn); ok {
		return hc.CloseWrite()
	}
	return c.Conn.Close()
}

// SetReadDeadline / SetWriteDeadline forward to the underlying conn
// (embedding already provides them, but keep the wrapper transparent).

// halfCloseConn is implemented by TCP-like connections supporting
// half-close (shutdown of the write side).
type halfCloseConn interface {
	CloseWrite() error
}

// relay pumps data both ways with end-to-end half-close semantics.
//
// Deadline model:
//   - While neither side has half-closed, reads are bounded by
//     min(now+idle, total) and refreshed after every chunk, so active
//     tunnels never expire and idle ones are reaped.
//   - When the opposite direction sees a clean EOF (peerHalf), this
//     direction switches to a short drain window: pending data is still
//     forwarded (and refreshes the window), but a peer that stays open
//     and silent cannot pin the tunnel.
//   - Clean EOF half-closes the write side toward the peer (FIN); the
//     relay ends when both pumps return. Abnormal errors or the total
//     deadline abort both connections. sync.Once closes each socket
//     exactly once — no leaks, no duplicate closes.
func (e *Engine) relay(ctx context.Context, client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	closeAll := sync.OnceFunc(func() {
		_ = client.Close()
		_ = target.Close()
	})

	halfC2T := make(chan struct{})
	halfT2C := make(chan struct{})
	signalC2T := sync.OnceFunc(func() { close(halfC2T) })
	signalT2C := sync.OnceFunc(func() { close(halfT2C) })

	go func() {
		defer wg.Done()
		e.pump(ctx, target, client, e.reg.AddBytesClientToTarget, closeAll, halfT2C, signalC2T)
	}()
	go func() {
		defer wg.Done()
		e.pump(ctx, client, target, e.reg.AddBytesTargetToClient, closeAll, halfC2T, signalT2C)
	}()
	wg.Wait()
	closeAll()
}

// readResult is one Read outcome delivered over a channel so the pump
// can own all deadline mutations in a single goroutine.
type readResult struct {
	n   int
	err error
}

// pump copies src -> dst. All SetReadDeadline calls happen in this
// goroutine; the blocking Read runs in a helper goroutine, so switching
// from the idle to the drain deadline after peerHalf never races.
func (e *Engine) pump(ctx context.Context, dst, src net.Conn, addBytes func(int64),
	abort func(), peerHalf <-chan struct{}, signalOwnHalf func()) {
	buf := make([]byte, e.bufSize)
	draining := false

	for {
		// Choose the deadline for this read.
		deadline := time.Time{}
		if draining {
			deadline = time.Now().Add(halfCloseDrain)
		} else if e.idleTimeout > 0 {
			deadline = time.Now().Add(e.idleTimeout)
		}
		if dl, ok := ctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
			deadline = dl
		}
		if !deadline.IsZero() {
			_ = src.SetReadDeadline(deadline)
		} else {
			_ = src.SetReadDeadline(time.Time{})
		}

		reads := make(chan readResult, 1)
		go func() {
			n, err := src.Read(buf)
			reads <- readResult{n, err}
		}()

		// If we already know the peer half-closed, just wait for the read
		// under the drain deadline (set above); otherwise also watch for
		// the peerHalf signal so a blocked long idle read is interrupted.
		if draining {
			select {
			case <-ctx.Done():
				abort()
				return
			case res := <-reads:
				if stop := e.handleRead(dst, src, buf, res, addBytes, abort, signalOwnHalf); stop {
					return
				}
			}
			continue
		}

		select {
		case <-peerHalf:
			// Interrupt the in-flight read, then process whatever it
			// returned: a deadline wake-up (n==0, timeout) simply leads
			// to re-entering under the drain deadline; data or EOF that
			// raced the signal is handled normally and never dropped.
			draining = true
			_ = src.SetReadDeadline(time.Now())
			res := <-reads
			if isTimeout(res.err) && res.n == 0 {
				continue
			}
			if stop := e.handleRead(dst, src, buf, res, addBytes, abort, signalOwnHalf); stop {
				return
			}
		case <-ctx.Done():
			abort()
			return
		case res := <-reads:
			if stop := e.handleRead(dst, src, buf, res, addBytes, abort, signalOwnHalf); stop {
				return
			}
		}
	}
}

// handleRead processes one Read outcome: forwards data or maps the error
// to half-close/abort. It reports true when the pump must stop.
func (e *Engine) handleRead(dst, src net.Conn, buf []byte, res readResult,
	addBytes func(int64), abort func(), signalOwnHalf func()) bool {
	n, rerr := res.n, res.err
	if n > 0 {
		data := buf[:n]
		for len(data) > 0 {
			w, werr := dst.Write(data)
			if w > 0 {
				addBytes(int64(w))
				data = data[w:]
			}
			if werr != nil {
				if !isTimeout(werr) && !isClosed(werr) {
					e.reg.ErrorIO()
				}
				abort()
				return true
			}
		}
	}
	if rerr == nil {
		return false
	}
	if rerr == io.EOF || isClosed(rerr) {
		if hc, ok := dst.(halfCloseConn); ok {
			_ = hc.CloseWrite()
		}
		signalOwnHalf()
		return true
	}
	if isTimeout(rerr) {
		// Idle / drain / total timeout: lifecycle reaping, not an error.
		abort()
		return true
	}
	// Genuine abnormal I/O failure.
	e.reg.ErrorIO()
	abort()
	return true
}

// halfCloseDrain bounds silence on the still-open direction after the
// peer cleanly half-closed.
// halfCloseDrain bounds silence on the still-open direction after the
// peer cleanly half-closed. It is deliberately short: post-FIN response
// data on loopback/local networks arrives within milliseconds, while a
// peer that keeps the direction open and silent must not pin resources.
const halfCloseDrain = 500 * time.Millisecond

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

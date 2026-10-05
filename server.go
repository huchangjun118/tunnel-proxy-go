package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// bufferedConn preserves bytes peeked during protocol dispatch.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite/CloseRead are forwarded so half-close propagation works even
// though the connection is wrapped for protocol dispatch buffering.
func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}

func (b *bufferedConn) CloseRead() error {
	if cr, ok := b.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return b.Conn.Close()
}

// AuditEvent describes one finished (or rejected) session for audit sinks.
type AuditEvent struct {
	Stage    Stage
	Reason   Reason
	Detail   string
	Accepted bool
	Identity string
	Target   string
}

// Server is the tunneling proxy server. A single listener serves both HTTP
// CONNECT and SOCKS5; protocol selection is based on the first client byte.
type Server struct {
	cfg     Config
	ln      net.Listener
	auth    *Authenticator
	acl     *ACL
	metrics *Metrics
	tunnels *TunnelManager

	ctx    context.Context
	cancel context.CancelFunc

	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
	active  map[net.Conn]struct{} // front-end connections
	targets map[net.Conn]struct{} // established back-end connections
	auditFn func(AuditEvent)
}

// NewServer builds a server from a validated configuration.
func NewServer(cfg Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:     cfg,
		auth:    NewAuthenticator(cfg.Auth),
		acl:     NewACL(cfg.ACL),
		metrics: NewMetrics(),
		tunnels: NewTunnelManager(cfg),
		ctx:     ctx,
		cancel:  cancel,
		active:  make(map[net.Conn]struct{}),
		targets: make(map[net.Conn]struct{}),
	}, nil
}

// SetAuditHook installs a callback receiving one event per session outcome.
// It must be called before Serve.
func (s *Server) SetAuditHook(fn func(AuditEvent)) { s.auditFn = fn }

// ListenAndServe binds the configured listen address and serves.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts connections on ln until it is closed or the server is shut
// down. It always returns nil on clean shutdown.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.register(c)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.unregister(c)
			s.handleConn(c)
		}()
	}
}

func (s *Server) register(c net.Conn) {
	s.mu.Lock()
	s.active[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) unregister(c net.Conn) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
}

func (s *Server) registerTarget(c net.Conn) {
	s.mu.Lock()
	s.targets[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) unregisterTarget(c net.Conn) {
	s.mu.Lock()
	delete(s.targets, c)
	s.mu.Unlock()
}

// LocalAddr returns the bound listener address, nil before Serve.
func (s *Server) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Close stops accepting, cancels queued work and forcibly closes every active
// tunnel. It is safe to call multiple times.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.cancel()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.mu.Lock()
	for c := range s.active {
		_ = c.Close()
	}
	for c := range s.targets {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// Metrics returns a consistent runtime snapshot.
func (s *Server) Metrics() MetricsSnapshot { return s.metrics.Snapshot() }

// handleConn performs front-end dispatch: 0x05 means SOCKS5, anything else is
// parsed as an HTTP CONNECT request line.
func (s *Server) handleConn(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(nonZero(s.cfg.HandshakeTimeout)))

	br := bufio.NewReader(c)
	bc := &bufferedConn{Conn: c, r: br}
	b, err := br.Peek(1)

	var perr *ProxyError
	switch {
	case err != nil:
		// Client disconnected before sending anything: benign, no audit/metrics.
		return
	case b[0] == socksVer5:
		perr = s.serveSOCKS(s.ctx, bc)
	case b[0] < 0x20 || b[0] == 0x7f:
		// HTTP request lines start with a printable method token. A control
		// character (e.g. SOCKS4's 0x04) can never be an HTTP method, so
		// reject immediately instead of waiting for a request-line newline.
		perr = newProxyError(StageHandshake, ReasonProtocolError,
			"first byte is not a valid HTTP method token or SOCKS5 greeting")
		writeHTTPStatus(bc, httpStatus("HTTP/1.1", http.StatusBadRequest, "Bad Request"))
	default:
		perr = s.serveHTTPConnect(s.ctx, bc)
	}

	if perr != nil {
		// Each front-end handler has already written its own protocol-
		// specific failure frame before returning; here we only observe.
		s.metrics.record(perr)
		if s.auditFn != nil && !perr.audited {
			s.auditFn(AuditEvent{
				Stage: perr.Stage, Reason: perr.Reason, Detail: perr.Detail,
			})
		}
	}
}

// openTarget is the shared post-handshake pipeline used identically by both
// front-end protocols: access control -> concurrency slot -> resolution/dial.
// No target connection exists before ACL and limit checks succeed.
func (s *Server) openTarget(parent context.Context, id Identity, t Target) (net.Conn, func(), *ProxyError) {
	audit := func(e *ProxyError) {
		if e != nil && s.auditFn != nil {
			s.auditFn(AuditEvent{
				Stage: e.Stage, Reason: e.Reason, Detail: e.Detail,
				Identity: id.Name, Target: t.String(),
			})
			e.audited = true
		}
	}
	if perr := s.acl.Check(t); perr != nil {
		audit(perr)
		return nil, nil, perr
	}

	qctx := parent
	if s.cfg.LimitPolicy == PolicyQueue && s.cfg.QueueTimeout > 0 {
		var cancel context.CancelFunc
		qctx, cancel = context.WithTimeout(parent, s.cfg.QueueTimeout)
		defer cancel()
	}
	release, perr := s.tunnels.Acquire(qctx)
	if perr != nil {
		audit(perr)
		return nil, nil, perr
	}

	dst, derr := s.dialTarget(t)
	if derr != nil {
		audit(derr)
		release()
		return nil, nil, derr
	}
	s.registerTarget(dst)
	if s.auditFn != nil {
		s.auditFn(AuditEvent{
			Accepted: true, Identity: id.Name, Target: t.String(),
		})
	}
	releaseAndForget := func() {
		release()
		s.unregisterTarget(dst)
	}
	return dst, releaseAndForget, nil
}

// dialTarget resolves (for hostnames) and connects to the target, mapping
// failures to DNS vs. timeout vs. refused categories.
func (s *Server) dialTarget(t Target) (net.Conn, *ProxyError) {
	timeout := nonZero(s.cfg.DialTimeout)
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	ip := t.IP
	if ip == nil {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, t.Host)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, wrapProxyError(StageDial, ReasonDialTimeout,
					"resolution timed out: "+t.Host, err)
			}
			return nil, wrapProxyError(StageDial, ReasonDNSFailed,
				"cannot resolve "+t.Host, err)
		}
		if len(addrs) == 0 {
			return nil, newProxyError(StageDial, ReasonDNSFailed, "no address for "+t.Host)
		}
		ip = addrs[0].IP
	}

	d := net.Dialer{}
	dst, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(t.Port)))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, wrapProxyError(StageDial, ReasonDialTimeout,
				"connect timed out: "+t.String(), err)
		}
		return nil, wrapProxyError(StageDial, ReasonDialFailed,
			"connect failed: "+t.String(), err)
	}
	return dst, nil
}

// bridge moves an accepted session into the relay phase and accounts it.
func (s *Server) bridge(client, dst net.Conn) *ProxyError {
	// Handshake deadline must not govern long-lived relay traffic.
	_ = client.SetDeadline(time.Time{})
	_ = dst.SetDeadline(time.Time{})

	s.metrics.tunnelOpened()
	defer s.metrics.tunnelClosed()

	// Metrics/audit for relay outcomes are recorded once by the caller.
	return relay(client, dst, s.cfg.IdleTimeout, s.cfg.MaxLifetime,
		s.cfg.HalfCloseTimeout, s.cfg.BufferSize, s.metrics)
}

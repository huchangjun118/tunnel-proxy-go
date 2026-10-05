// Package server wires the CONNECT and SOCKS5 frontends, the shared
// engine, the concurrency pool, metrics and lifecycle together. Both
// protocols are served from one listening address: the first byte of a
// connection disambiguates them (0x05 -> SOCKS5, printable ASCII ->
// HTTP CONNECT).
package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/huchangjun118/tunnel-proxy-go/acl"
	"github.com/huchangjun118/tunnel-proxy-go/auth"
	"github.com/huchangjun118/tunnel-proxy-go/config"
	"github.com/huchangjun118/tunnel-proxy-go/metrics"
	"github.com/huchangjun118/tunnel-proxy-go/pool"
	"github.com/huchangjun118/tunnel-proxy-go/proxy"
)

// Server is the forwarding proxy server.
type Server struct {
	cfg     *config.Config
	ln      net.Listener
	statsLn net.Listener
	httpSrv *http.Server

	engine  *proxy.Engine
	connect *proxy.ConnectFrontend
	socks   *proxy.SocksFrontend
	pool    *pool.Pool
	reg     *metrics.Registry

	connsWg sync.WaitGroup
	closeMu sync.Mutex
	closed  bool
	quit    chan struct{}
}

// Option customizes a Server at construction; primarily useful for
// tests that inject a deterministic dialer.
type Option func(*options)

type options struct{ dialer proxy.Dialer }

// WithDialer overrides the target dialer.
func WithDialer(d proxy.Dialer) Option {
	return func(o *options) { o.dialer = d }
}

// New creates a Server from config.
func New(cfg *config.Config, opts ...Option) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	authn := auth.New(cfg.AuthEnabled, cfg.Credentials)
	aclList, err := acl.New(cfg.AllowedHosts, cfg.AllowedPorts)
	if err != nil {
		return nil, err
	}
	reg := metrics.NewRegistry()
	pl := pool.New(cfg.MaxTunnels, pool.Policy(cfg.Overflow), cfg.QueueTimeout)
	eng := proxy.NewEngine(proxy.EngineDeps{
		Authenticator: authn,
		ACL:           aclList,
		Pool:          pl,
		Metrics:       reg,
		DialTimeout:   cfg.DialTimeout,
		IdleTimeout:   cfg.IdleTimeout,
		TotalTimeout:  cfg.TotalTimeout,
		BufferBytes:   cfg.IOBufferBytes,
		Dialer:        o.dialer,
	})
	return &Server{
		cfg:     cfg,
		engine:  eng,
		connect: proxy.NewConnectFrontend(eng),
		socks:   proxy.NewSocksFrontend(eng),
		pool:    pl,
		reg:     reg,
		quit:    make(chan struct{}),
	}, nil
}

// Listen binds the access endpoint and the optional metrics endpoint.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	s.ln = ln

	if s.cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", s.MetricsHandler)
		mux.HandleFunc("/stats", s.MetricsHandler)
		srv := &http.Server{Handler: mux}
		mln, err := net.Listen("tcp", s.cfg.MetricsAddr)
		if err != nil {
			_ = ln.Close()
			return err
		}
		s.statsLn = mln
		s.httpSrv = srv
		go func() { _ = srv.Serve(mln) }()
	}
	return nil
}

// ListenAndServe binds and serves until Shutdown or an unrecoverable
// accept error.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	return s.Serve(ctx)
}

// Serve accepts connections on an already-listening server.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Shutdown(context.Background())
		case <-s.quit:
		}
	}()

	for {
		c, err := s.ln.Accept()
		if err != nil {
			s.closeMu.Lock()
			closed := s.closed
			s.closeMu.Unlock()
			if closed {
				s.connsWg.Wait()
				return nil
			}
			return err
		}
		s.connsWg.Add(1)
		go s.dispatch(c)
	}
}

// dispatch identifies the protocol from the first byte and routes to the
// matching frontend. The peeked byte is preserved through a shared
// buffered reader, so the frontends never see a truncated handshake and
// tunnel data that arrived together with it is never lost.
func (s *Server) dispatch(c net.Conn) {
	defer s.connsWg.Done()
	defer c.Close()

	br := bufioNewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		// Client connected without sending anything; harmless abort.
		return
	}
	conn := &peekConn{Conn: c, r: br}
	switch {
	case first[0] == 0x05:
		s.socks.Handle(conn)
	case first[0] >= 0x20 && first[0] < 0x7f:
		s.connect.Handle(conn)
	default:
		s.reg.ErrorProtocol()
	}
}

// Shutdown stops accepting, closes the metrics server and waits for
// in-flight tunnels to finish (bounded by idle / drain / total timeouts)
// or the context to expire.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	close(s.quit)
	s.closeMu.Unlock()

	var firstErr error
	if s.ln != nil {
		if err := s.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			firstErr = err
		}
	}
	if s.httpSrv != nil {
		if err := s.httpSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			firstErr = err
		}
	}
	done := make(chan struct{})
	go func() {
		s.connsWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if firstErr == nil {
			firstErr = ctx.Err()
		}
	}
	return firstErr
}

// MetricsHandler serves the stats snapshot as JSON.
func (s *Server) MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.reg)
}

// Addr reports the actual access address (useful with port 0 in tests).
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// MetricsAddr reports the actual metrics listener address.
func (s *Server) MetricsAddr() net.Addr {
	if s.statsLn == nil {
		return nil
	}
	return s.statsLn.Addr()
}

// Stats returns the current metrics snapshot.
func (s *Server) Stats() metrics.Stats { return s.reg.Snapshot() }

// peekConn feeds reads through the dispatcher's bufio.Reader so the
// peeked (and any further buffered) handshake bytes are not lost.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// BufReader exposes the dispatcher's buffered reader so protocol
// frontends do not double-buffer the connection.
func (c *peekConn) BufReader() *bufio.Reader { return c.r }

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

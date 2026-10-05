// Package testutil provides loopback target servers and a wired proxy
// server used by the end-to-end tests. No external services are used.
package testutil

import (
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/config"
	"github.com/huchangjun118/tunnel-proxy-go/server"
)

// EchoServer is a loopback TCP target that echoes everything until the
// client half-closes; on half-close it sends a trailing marker and
// closes, letting tests observe half-close semantics.
type EchoServer struct {
	ln        net.Listener
	Accepted  atomic.Int64
	Active    atomic.Int64
	closeOnce sync.Once
}

// StartEcho listens on 127.0.0.1:0.
func StartEcho(t testing.TB) *EchoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	s := &EchoServer{ln: ln}
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

func (s *EchoServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.Accepted.Add(1)
		s.Active.Add(1)
		go func(c net.Conn) {
			defer s.Active.Add(-1)
			defer c.Close()
			// Echo until EOF, then write a marker so a half-closing
			// client can detect the server observed FIN and replied.
			_, _ = io.Copy(c, c)
		}(c)
	}
}

// Addr returns the listener address.
func (s *EchoServer) Addr() string { return s.ln.Addr().String() }

// Close stops accepting.
func (s *EchoServer) Close() { s.closeOnce.Do(func() { _ = s.ln.Close() }) }

// StartProxy builds and starts a proxy server on a random loopback port.
func StartProxy(t testing.TB, mutate func(*config.Config), opts ...server.Option) *server.Server {
	t.Helper()
	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.MetricsAddr = "" // off unless enabled in tests
	cfg.IdleTimeout = 3 * time.Second
	cfg.TotalTimeout = 10 * time.Second
	cfg.DialTimeout = 2 * time.Second
	if mutate != nil {
		mutate(cfg)
	}
	srv, err := server.New(cfg, opts...)
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(t.Context()) }()
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(3 * time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv
}

// BlockServer accepts connections and holds them open silently until
// closed, used for concurrency-limit and slow-peer tests.
type BlockServer struct {
	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	once  sync.Once
}

func StartBlock(t testing.TB) *BlockServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &BlockServer{ln: ln, conns: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns[c] = struct{}{}
			b.mu.Unlock()
		}
	}()
	t.Cleanup(b.Close)
	return b
}

func (b *BlockServer) Addr() string { return b.ln.Addr().String() }
func (b *BlockServer) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.conns)
}
func (b *BlockServer) Close() {
	b.once.Do(func() { _ = b.ln.Close() })
}

// DeadAddr returns a loopback addr:port with no listener (ECONNREFUSED).
func DeadAddr(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// HalfCloseServer echoes data, then on client half-close (read EOF)
// sends a trailing marker and closes its own write side, enabling tests
// of end-to-end half-close semantics.
type HalfCloseServer struct {
	ln   net.Listener
	once sync.Once
}

func StartHalfClose(t testing.TB) *HalfCloseServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &HalfCloseServer{ln: ln}
	go h.serve()
	t.Cleanup(h.Close)
	return h
}

func (h *HalfCloseServer) serve() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					// Echo reliably before observing EOF.
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					// Client half-closed or gone. Drain until the read
					// side settles, then write the marker reliably and
					// finally half-close.
					marker := []byte("HALF_CLOSE_MARKER")
					_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					for len(marker) > 0 {
						w, werr := c.Write(marker)
						if werr != nil {
							log.Printf("TARGET marker write err: %v", werr)
							return
						}
						marker = marker[w:]
					}
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					return
				}
			}
		}(c)
	}
}

func (h *HalfCloseServer) Addr() string { return h.ln.Addr().String() }
func (h *HalfCloseServer) Close()       { h.once.Do(func() { _ = h.ln.Close() }) }

// StartProxyWithMetrics starts a proxy with the metrics listener
// enabled on a random loopback port.
func StartProxyWithMetrics(t testing.TB) *MetricsProxy {
	t.Helper()
	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.MetricsAddr = "127.0.0.1:0"
	cfg.IdleTimeout = 2 * time.Second
	cfg.TotalTimeout = 10 * time.Second
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(t.Context()) }()
	mp := &MetricsProxy{Server: srv}
	// Resolve metrics address the server actually bound.
	mp.metricsAddr = srv.MetricsAddr()
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(3 * time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return mp
}

// MetricsProxy wraps a server with its resolved metrics address.
type MetricsProxy struct {
	*server.Server
	metricsAddr net.Addr
}

// MetricsURL returns the base URL of the stats endpoint.
func (m *MetricsProxy) MetricsURL() string {
	if m.metricsAddr == nil {
		return ""
	}
	return "http://" + m.metricsAddr.String()
}

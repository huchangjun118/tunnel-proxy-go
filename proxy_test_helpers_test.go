package proxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// startEchoTarget starts a loopback server that echoes each connection's
// data until the peer closes the write side; on EOF it echoes a fixed marker
// and then closes, which lets tests observe half-close propagation.
// startNeverReachedTarget starts a loopback listener that fails the test if a
// connection ever reaches it. Used to prove the proxy refused before dialing.
func startNeverReachedTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("guard listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Errorf("proxy dialed a target it must have refused: %s", c.RemoteAddr())
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func startEchoTarget(t *testing.T) (string, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go echoOnce(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), ln
}

func echoOnce(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			_, _ = c.Write([]byte("echo:" + line))
		}
		if err != nil {
			return
		}
	}
}

// startBlockingTarget accepts connections and never reads or writes; it
// returns a channel producing each accepted conn so tests can inspect state.
func startBlockingTarget(t *testing.T) (string, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	conns := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		go func() {
			for range conns {
			}
		}()
	})
	return ln.Addr().String(), conns
}

func startServer(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, ln.Addr().String()
}

// dialSOCKS performs a SOCKS5 CONNECT through proxyAddr to target using the
// optional credentials. It returns the tunneled client conn.
func dialSOCKS(t *testing.T, proxyAddr, target string, user, pass string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	br := bufio.NewReader(c)

	method := byte(0x00)
	if user != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{0x05, 0x01, method}); err != nil {
		_ = c.Close()
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(br, reply); err != nil {
		_ = c.Close()
		t.Fatalf("method reply: %v", err)
	}
	if reply[0] != 0x05 {
		_ = c.Close()
		t.Fatalf("bad version in method reply: %v", reply)
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := c.Write(auth); err != nil {
			_ = c.Close()
			t.Fatalf("auth write: %v", err)
		}
		a := make([]byte, 2)
		if _, err := io.ReadFull(br, a); err != nil {
			_ = c.Close()
			t.Fatalf("auth reply: %v", err)
		}
		if a[1] != 0x00 {
			_ = c.Close()
			t.Fatalf("socks auth rejected, status=%d", a[1])
		}
	case 0xFF:
		_ = c.Close()
		t.Fatalf("socks: no acceptable auth methods")
	default:
		_ = c.Close()
		t.Fatalf("socks: unexpected method %d", reply[1])
	}

	host, portStr := splitTestTarget(t, target)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		t.Fatalf("connect request: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		_ = c.Close()
		t.Fatalf("reply header: %v", err)
	}
	if head[1] != 0x00 {
		_ = c.Close()
		t.Fatalf("socks connect rejected, code=%d", head[1])
	}
	// skip bound address
	switch head[3] {
	case 0x01:
		if _, err := io.ReadFull(br, make([]byte, 4+2)); err != nil {
			t.Fatalf("skip v4 bnd: %v", err)
		}
	case 0x04:
		if _, err := io.ReadFull(br, make([]byte, 16+2)); err != nil {
			t.Fatalf("skip v6 bnd: %v", err)
		}
	case 0x03:
		l, _ := br.ReadByte()
		if _, err := io.ReadFull(br, make([]byte, int(l)+2)); err != nil {
			t.Fatalf("skip dom bnd: %v", err)
		}
	}
	return &bufferedTestConn{Conn: c, r: br}
}

// dialHTTP performs an HTTP CONNECT through proxyAddr.
func dialHTTP(t *testing.T, proxyAddr, target, user, pass string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if user != "" {
		req += "Proxy-Authorization: Basic " +
			base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		_ = c.Close()
		t.Fatalf("connect write: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := httpReadStatus(br)
	if err != nil {
		_ = c.Close()
		t.Fatalf("read connect response: %v", err)
	}
	if resp != 200 {
		_ = c.Close()
		t.Fatalf("http connect rejected, status=%d", resp)
	}
	return &bufferedTestConn{Conn: c, r: br}
}

// rawHTTP sends the CONNECT request and returns the raw status line so tests
// can assert rejections.
func rawHTTP(t *testing.T, proxyAddr, reqLines string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(reqLines)); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	code, err := httpReadStatus(br)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return code
}

func httpReadStatus(br *bufio.Reader) (int, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	// HTTP/1.1 200 Connection Established
	var proto string
	var code int
	var text string
	if _, err := fmt.Sscanf(line, "%s %d %s", &proto, &code, &text); err != nil {
		return 0, fmt.Errorf("bad status line %q: %w", line, err)
	}
	// drain headers until blank line
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return code, nil
}

type bufferedTestConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedTestConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufferedTestConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func splitTestTarget(t *testing.T, target string) (string, string) {
	t.Helper()
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("bad target %q: %v", target, err)
	}
	return h, p
}

// echoRoundTrip sends one line through the tunnel and asserts the echo.
func echoRoundTrip(t *testing.T, c net.Conn, payload string) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	want := "echo:" + payload
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

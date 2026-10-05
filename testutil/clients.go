package testutil

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// DialCONNECT opens an HTTP CONNECT tunnel through the proxy. user/pass
// empty means no Proxy-Authorization header.
func DialCONNECT(t testing.TB, proxyAddr, targetAddr, user, pass string) (net.Conn, *http.Response) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n"
	if user != "" || pass != "" {
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		t.Fatalf("write connect: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		c.Close()
		t.Fatalf("read connect response: %v", err)
	}
	if resp.StatusCode == http.StatusOK {
		// Wrap connection so buffered bytes are preserved.
		c = &bufferedConn{Conn: c, r: br}
		return c, resp
	}
	return c, resp
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite forwards to the real connection so tests can half-close.
func (c *bufferedConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return c.Conn.Close()
}

// DialSOCKS5 opens a SOCKS5 tunnel. auth=false -> no-auth method.
func DialSOCKS5(t testing.TB, proxyAddr, targetAddr string, user, pass string) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if user == "" && pass == "" {
		// greeting offering no-auth + userpass
		if _, err := c.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			c.Close()
			t.Fatal(err)
		}
		rep := make([]byte, 2)
		if _, err := io.ReadFull(c, rep); err != nil {
			c.Close()
			t.Fatal(err)
		}
		if rep[1] != 0x00 {
			return c, rep[1] // method selection failure code (0xFF)
		}
	} else {
		if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			c.Close()
			t.Fatal(err)
		}
		rep := make([]byte, 2)
		if _, err := io.ReadFull(c, rep); err != nil {
			c.Close()
			t.Fatal(err)
		}
		if rep[1] != 0x02 {
			return c, rep[1]
		}
		ub := []byte(user)
		pb := []byte(pass)
		msg := append([]byte{0x01, byte(len(ub))}, ub...)
		msg = append(msg, byte(len(pb)))
		msg = append(msg, pb...)
		if _, err := c.Write(msg); err != nil {
			c.Close()
			t.Fatal(err)
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(c, ar); err != nil {
			c.Close()
			t.Fatal(err)
		}
		if ar[1] != 0x00 {
			return c, ar[1] // auth sub-negotiation status
		}
	}

	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)
	var req []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = []byte{0x05, 0x01, 0x00, 0x01}
			req = append(req, v4...)
		} else {
			req = []byte{0x05, 0x01, 0x00, 0x04}
			req = append(req, ip.To16()...)
		}
	} else {
		req = []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req = append(req, pb...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		t.Fatal(err)
	}
	rep := head[1]
	if rep != 0x00 {
		return c, rep
	}
	// Drain bound address.
	switch head[3] {
	case 0x01:
		io.CopyN(io.Discard, c, 4+2)
	case 0x04:
		io.CopyN(io.Discard, c, 16+2)
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		io.CopyN(io.Discard, c, int64(l[0])+2)
	}
	return c, rep
}

var _ = url.Parse
var _ = fmt.Sprintf
var _ = strings.TrimSpace

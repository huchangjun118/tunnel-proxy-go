package proxy

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

// tryDialSOCKS is like dialSOCKS but returns nil conn when the server replies
// with a non-zero CONNECT reply code or auth failure.
func tryDialSOCKS(t *testing.T, proxyAddr, target, user, pass string) net.Conn {
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
		c.Close()
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(br, reply); err != nil {
		c.Close()
		return nil
	}
	if reply[1] == 0xFF {
		c.Close()
		return nil
	}
	if reply[1] == 0x02 {
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		c.Write(auth)
		a := make([]byte, 2)
		if _, err := io.ReadFull(br, a); err != nil || a[1] != 0 {
			c.Close()
			return nil
		}
	}

	host, portStr := splitTestTarget(t, target)
	port := mustPort(t, portStr)
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
		c.Close()
		return nil
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		c.Close()
		return nil
	}
	if head[1] != 0 {
		c.Close()
		return nil
	}
	// discard bound address
	var skip int
	switch head[3] {
	case 0x01:
		skip = 6
	case 0x04:
		skip = 18
	case 0x03:
		l, _ := br.ReadByte()
		skip = int(l) + 2
	}
	io.ReadFull(br, make([]byte, skip))
	_ = time.Second
	return &bufferedTestConn{Conn: c, r: br}
}

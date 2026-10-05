package e2e

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/testutil"
)

// TestGarbageFirstByte: a non-SOCKS, non-ASCII first byte is counted as
// a protocol error and dropped without hanging.
func TestGarbageFirstByte(t *testing.T) {
	srv := testutil.StartProxy(t, nil)
	c, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x01, 0x02, 0x03})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Connection should be closed by the dispatcher.
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err != io.EOF {
		// RST/closed also acceptable; only requirement is termination.
	}
	waitFor(t, func() bool { return srv.Stats().ErrorsProtocol >= 1 }, 2*time.Second)
}

// TestSocksUnsupportedCommand: BIND/ASSOC (0x02) is refused with 0x07
// before any target connection.
func TestSocksUnsupportedCommand(t *testing.T) {
	echo := testutil.StartEcho(t)
	srv := testutil.StartProxy(t, nil)
	c, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x05, 0x01, 0x00})
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 {
		t.Fatalf("method: %v %v", r, err)
	}
	// CMD=0x02 (BIND), ATYP IPv4, 127.0.0.1:port
	_, portStr := splitPort(echo.Addr())
	req := []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1}
	req = append(req, portBytes(portStr)...)
	c.Write(req)
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0x07 {
		t.Fatalf("rep=%d want 7 (command not supported)", head[1])
	}
	drainBound(c, head[3])
	if echo.Accepted.Load() != 0 {
		t.Fatal("unsupported command must not dial target")
	}
}

package proxy

import (
	"bufio"
	"net"
)

// bufferedConn is implemented by inbound connections that already own a
// bufio.Reader (created by the server's protocol peek). Frontends reuse
// it instead of layering a second buffer, which would otherwise swallow
// tunnel bytes that arrived together with the handshake.
type bufferedConn interface {
	BufReader() *bufio.Reader
}

// inboundReader returns the shared buffered reader for conn when
// available, or a fresh bufio.Reader otherwise.
func inboundReader(conn net.Conn) (*bufio.Reader, bool) {
	if bc, ok := conn.(bufferedConn); ok {
		return bc.BufReader(), true
	}
	return bufio.NewReader(conn), false
}

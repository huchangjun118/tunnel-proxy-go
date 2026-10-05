package e2e

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func newReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

func readResponse(br *bufio.Reader) (*http.Response, error) {
	return http.ReadResponse(br, &http.Request{Method: "CONNECT"})
}

func splitPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return h, n
}

func portBytes(p int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(p))
	return b
}

func drainBound(c net.Conn, atyp byte) {
	switch atyp {
	case 0x01:
		io.CopyN(io.Discard, c, 6)
	case 0x04:
		io.CopyN(io.Discard, c, 18)
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		io.CopyN(io.Discard, c, int64(l[0])+2)
	}
}

var _ = strings.TrimSpace

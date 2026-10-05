package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/target"
)

// connectHeaderTimeout bounds the time a client may take to finish
// sending the CONNECT request line and headers.
const connectHeaderTimeout = 30 * time.Second

// ConnectFrontend parses HTTP CONNECT requests. The target is carried
// in the request-line authority (host:port) and credentials in the
// Proxy-Authorization: Basic header.
type ConnectFrontend struct {
	engine *Engine
}

// NewConnectFrontend creates the CONNECT frontend.
func NewConnectFrontend(engine *Engine) *ConnectFrontend {
	return &ConnectFrontend{engine: engine}
}

// Handle processes one connection: exactly one CONNECT tunnel, matching
// the one-connection semantics of SOCKS5.
func (f *ConnectFrontend) Handle(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(connectHeaderTimeout))
	br, _ := inboundReader(conn)
	t, user, pass, perr := parseConnect(br)
	_ = conn.SetReadDeadline(time.Time{})

	if perr != nil {
		f.engine.reg.ErrorProtocol()
		writeConnectResponse(conn, http.StatusBadRequest, "Bad Request")
		return
	}

	adm, pErr := f.engine.Admit(conn, t, user, pass)
	if pErr != nil {
		writeConnectError(conn, pErr)
		return
	}

	// Admitted: the target connection exists. Send the success response
	// only now, then enter the tunnel — failure frames and tunnel data
	// can therefore never be interleaved.
	if _, werr := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); werr != nil {
		adm.Release()
		return
	}
	f.engine.ServeTunnel(adm, conn, br)
}

// writeConnectError maps a staged engine error to an HTTP response.
// Responses are only ever sent before the tunnel is established, so
// failure frames can never be confused with tunnel data.
func writeConnectError(conn net.Conn, e *Error) {
	switch e.Stage {
	case StageAuth:
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"tproxy\"\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 0\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		return
	case StageIO:
		// Tunnel already established: nothing safe to write.
		return
	}
	status := http.StatusBadGateway
	switch e.Stage {
	case StageACL:
		status = http.StatusForbidden
	case StageLimit:
		status = http.StatusServiceUnavailable
	case StageQueue:
		status = http.StatusGatewayTimeout
	case StageProtocol:
		status = http.StatusBadRequest
	case StageResolve, StageDial:
		status = http.StatusBadGateway
	}
	writeConnectResponse(conn, status, http.StatusText(status))
}

func writeConnectResponse(conn net.Conn, status int, reason string) {
	if reason == "" {
		reason = "Error"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
		status, reason)
	_, _ = conn.Write([]byte(resp))
}

// parseConnect parses request line, headers and Proxy-Authorization.
func parseConnect(br *bufio.Reader) (t target.Target, user, pass string, err error) {
	req, perr := http.ReadRequest(br)
	if perr != nil {
		return t, "", "", perr
	}
	if !strings.EqualFold(req.Method, "CONNECT") {
		return t, "", "", fmt.Errorf("connect: method %q not supported", req.Method)
	}
	t, err = target.ParseHostPort(req.Host)
	if err != nil {
		return t, "", "", err
	}
	if pa := req.Header.Get("Proxy-Authorization"); pa != "" {
		const prefix = "Basic "
		if len(pa) > len(prefix) && strings.EqualFold(pa[:len(prefix)], prefix) {
			if decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(pa[len(prefix):])); derr == nil {
				if u, p, ok := strings.Cut(string(decoded), ":"); ok {
					user, pass = u, p
				}
			}
		}
	}
	return t, user, pass, nil
}

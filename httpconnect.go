package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// connectRequest is the minimal parsed view of an HTTP CONNECT request.
type connectRequest struct {
	method    string
	authority string
	headers   http.Header
}

// serveHTTPConnect handles one HTTP CONNECT session; the first peeked byte
// lives inside conn's bufio.Reader. Parsing is done by hand rather than
// http.ReadRequest because the latter blocks waiting for a structurally
// complete request: non-HTTP byte streams (e.g. a SOCKS4 probe) must be
// rejected promptly instead of hanging until the handshake deadline.
func (s *Server) serveHTTPConnect(ctx context.Context, conn *bufferedConn) *ProxyError {
	req, perr := readConnectRequest(conn.r)
	if perr != nil {
		writeHTTPStatus(conn, httpStatus("HTTP/1.1", http.StatusBadRequest, "Bad Request"))
		return perr
	}

	if req.method != http.MethodConnect {
		writeHTTPStatus(conn, httpStatus("HTTP/1.1", http.StatusMethodNotAllowed, "Method Not Allowed"))
		return newProxyError(StageHandshake, ReasonUnsupportedProto,
			"only CONNECT is supported, got "+req.method)
	}

	// --- authentication (Proxy-Authorization: Basic) ---
	identity := Identity{}
	if s.auth.Enabled() {
		user, pass, ok := parseProxyBasicAuth(req.headers.Get("Proxy-Authorization"))
		if !ok {
			writeHTTPStatus(conn,
				`HTTP/1.1 407 Proxy Authentication Required`+"\r\n"+
					`Proxy-Authenticate: Basic realm="tunnel-proxy"`+"\r\n"+
					`Content-Length: 0`+"\r\n\r\n")
			return newProxyError(StageAuth, ReasonAuthRequired, "missing proxy credentials")
		}
		id, aerr := s.auth.Authenticate(user, pass)
		if aerr != nil {
			writeHTTPStatus(conn, httpStatus("HTTP/1.1", http.StatusForbidden, "Forbidden"))
			return aerr
		}
		identity = id
	}

	// --- target from the authority-form request target ---
	target, perr := targetFromAuthority(req.authority)
	if perr != nil {
		writeHTTPStatus(conn, httpStatus("HTTP/1.1", http.StatusBadRequest, "Bad Request"))
		return perr
	}

	// --- shared pipeline: ACL, limit, dial ---
	dst, release, perr := s.openTarget(ctx, identity, target)
	if perr != nil {
		writeHTTPStatus(conn, httpStatus("HTTP/1.1", httpStatusFor(perr), httpStatusText(perr)))
		return perr
	}
	defer dst.Close()
	defer release()

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return wrapProxyError(StageHandshake, ReasonProtocolError, "writing 200 reply", err)
	}

	return s.bridge(conn, dst)
}

// readConnectRequest reads a request line plus headers up to the blank line.
// Lines are length-capped so a peer streaming a huge single line cannot grow
// server memory unbounded.
func readConnectRequest(r *bufio.Reader) (*connectRequest, *ProxyError) {
	line, perr := readLine(r, maxRequestLine)
	if perr != nil {
		return nil, perr
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.Split(line, " ")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return nil, newProxyError(StageHandshake, ReasonProtocolError,
			"malformed request line: "+line)
	}
	method := parts[0]
	authority := parts[1]

	headers := make(http.Header)
	for {
		h, herr := readLine(r, maxHeaderLine)
		if herr != nil {
			return nil, herr
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return nil, newProxyError(StageHandshake, ReasonProtocolError, "bad header: "+h)
		}
		headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return &connectRequest{
		method:    method,
		authority: authority,
		headers:   headers,
	}, nil
}

const (
	maxRequestLine = 8 * 1024
	maxHeaderLine  = 16 * 1024
)

// readLine reads until '\n' byte by byte, rejecting lines that exceed max
// bytes before the terminator so a streaming peer cannot grow buffers.
func readLine(r *bufio.Reader, max int) (string, *ProxyError) {
	var sb strings.Builder
	for sb.Len() <= max {
		b, err := r.ReadByte()
		if err != nil {
			return sb.String(), wrapProxyError(StageHandshake, ReasonProtocolError, "reading request line", err)
		}
		sb.WriteByte(b)
		if b == '\n' {
			return sb.String(), nil
		}
	}
	return "", newProxyError(StageHandshake, ReasonProtocolError, "request line too long")
}

// targetFromAuthority parses host:port (or [ip6]:port) into a Target.
func targetFromAuthority(authority string) (Target, *ProxyError) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return Target{}, newProxyError(StageHandshake, ReasonTargetInvalid, "empty CONNECT authority")
	}
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil || portStr == "" {
		return Target{}, newProxyError(StageHandshake, ReasonTargetInvalid,
			"CONNECT target must be host:port: "+authority)
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return Target{}, newProxyError(StageHandshake, ReasonTargetInvalid, "invalid port: "+portStr)
	}
	return parseTarget(host, port)
}

// parseProxyBasicAuth extracts credentials from
// "Basic base64(user:pass)" case-insensitively.
func parseProxyBasicAuth(header string) (string, string, bool) {
	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	return user, pass, true
}

func httpStatus(proto string, code int, text string) string {
	return proto + " " + strconv.Itoa(code) + " " + text + "\r\nContent-Length: 0\r\n\r\n"
}

func writeHTTPStatus(w interface{ Write([]byte) (int, error) }, status string) {
	_, _ = w.Write([]byte(status))
}

// httpStatusFor maps a classified failure to an HTTP status code. Auth cases
// are handled directly (407 vs 403); the rest map here.
func httpStatusFor(e *ProxyError) int {
	switch e.Reason {
	case ReasonAuthFailed:
		return http.StatusForbidden
	case ReasonTargetDenied:
		return http.StatusForbidden
	case ReasonLimitRejected, ReasonQueueTimeout:
		return http.StatusServiceUnavailable
	case ReasonDNSFailed, ReasonDialTimeout, ReasonDialFailed:
		return http.StatusBadGateway
	default:
		return http.StatusBadGateway
	}
}

func httpStatusText(e *ProxyError) string {
	switch e.Reason {
	case ReasonTargetDenied:
		return "Forbidden"
	case ReasonLimitRejected, ReasonQueueTimeout:
		return "Service Unavailable"
	default:
		return "Bad Gateway"
	}
}

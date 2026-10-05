package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
)

// SOCKS5 protocol constants (RFC 1928 / RFC 1929).
const (
	socksVer5 = 0x05

	cmdConnect      = 0x01
	atypIPv4        = 0x01
	atypDomain      = 0x03
	atypIPv6        = 0x04
	methodNoAuth    = 0x00
	methodUserPass  = 0x02
	methodNoneAvail = 0xFF

	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repNotAllowed          = 0x02
	repNetworkUnreachable  = 0x03
	repHostUnreachable     = 0x04
	repConnectionRefused   = 0x05
	repTTLExpired          = 0x06
	repCommandNotSupported = 0x07
	repAddressNotSupported = 0x08
)

// serveSOCKS handles one SOCKS5 session on an already dispatched connection.
// The first 0x05 byte may already be buffered inside conn.
func (s *Server) serveSOCKS(ctx context.Context, conn *bufferedConn) *ProxyError {
	r := conn.r

	// --- method negotiation ---
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return readFailure(err, "socks greeting")
	}
	if hdr[0] != socksVer5 {
		return newProxyError(StageHandshake, ReasonProtocolError, "not a SOCKS5 greeting")
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return readFailure(err, "socks methods")
	}

	clientOfferedUserPass := false
	for _, m := range methods {
		if m == methodUserPass {
			clientOfferedUserPass = true
		}
	}

	var chosen byte
	switch {
	case !s.auth.Enabled() && containsByte(methods, methodNoAuth):
		chosen = methodNoAuth
	case s.auth.Enabled() && clientOfferedUserPass:
		chosen = methodUserPass
	case s.auth.Enabled() && containsByte(methods, methodNoAuth):
		// Auth is required but the client only offered no-auth.
		chosen = methodNoneAvail
	default:
		chosen = methodNoneAvail
	}
	if _, err := conn.Write([]byte{socksVer5, chosen}); err != nil {
		return wrapProxyError(StageHandshake, ReasonProtocolError, "socks method reply", err)
	}
	if chosen == methodNoneAvail {
		if s.auth.Enabled() {
			return newProxyError(StageAuth, ReasonAuthRequired, "SOCKS client offered no acceptable auth method")
		}
		return newProxyError(StageHandshake, ReasonUnsupportedProto, "no acceptable SOCKS method")
	}

	identity := Identity{}
	if chosen == methodUserPass {
		id, perr := s.socksUserPass(r, conn)
		if perr != nil {
			return perr
		}
		identity = id
	}

	// --- CONNECT request ---
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return readFailure(err, "socks request header")
	}
	if head[0] != socksVer5 {
		return newProxyError(StageHandshake, ReasonProtocolError, "bad SOCKS version in request")
	}
	if head[1] != cmdConnect {
		_, _ = conn.Write(socksReply(repCommandNotSupported, nil))
		return newProxyError(StageHandshake, ReasonUnsupportedProto, "only CONNECT is supported")
	}

	var host string
	switch head[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return readFailure(err, "socks ipv4 addr")
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return readFailure(err, "socks ipv6 addr")
		}
		host = net.IP(buf).String()
	case atypDomain:
		l, err := r.ReadByte()
		if err != nil {
			return readFailure(err, "socks domain length")
		}
		buf := make([]byte, int(l))
		if _, err := io.ReadFull(r, buf); err != nil {
			return readFailure(err, "socks domain")
		}
		host = string(buf)
	default:
		_, _ = conn.Write(socksReply(repAddressNotSupported, nil))
		return newProxyError(StageHandshake, ReasonTargetInvalid, "unsupported SOCKS address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return readFailure(err, "socks port")
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	target, perr := parseTarget(host, port)
	if perr != nil {
		_, _ = conn.Write(socksReply(repGeneralFailure, nil))
		return perr
	}

	// --- shared pipeline: ACL, limit, dial ---
	dst, release, perr := s.openTarget(ctx, identity, target)
	if perr != nil {
		_, _ = conn.Write(socksReply(socksReplyCode(perr), nil))
		return perr
	}
	defer dst.Close()
	defer release()

	if _, err := conn.Write(socksReply(repSuccess, dst.LocalAddr())); err != nil {
		return wrapProxyError(StageHandshake, ReasonProtocolError, "socks success reply", err)
	}

	return s.bridge(conn, dst)
}

// socksUserPass runs RFC 1929 username/password subnegotiation.
func (s *Server) socksUserPass(r io.Reader, w io.Writer) (Identity, *ProxyError) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Identity{}, readFailure(err, "socks auth header")
	}
	if hdr[0] != 0x01 {
		return Identity{}, newProxyError(StageHandshake, ReasonProtocolError, "bad user/pass auth version")
	}
	ulen := int(hdr[1])
	user := make([]byte, ulen)
	if _, err := io.ReadFull(r, user); err != nil {
		return Identity{}, readFailure(err, "socks auth user")
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, plenBuf); err != nil {
		return Identity{}, readFailure(err, "socks auth passlen")
	}
	pass := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(r, pass); err != nil {
		return Identity{}, readFailure(err, "socks auth pass")
	}
	id, perr := s.auth.Authenticate(string(user), string(pass))
	if perr != nil {
		_, _ = w.Write([]byte{0x01, 0x01})
		return Identity{}, perr
	}
	if _, err := w.Write([]byte{0x01, 0x00}); err != nil {
		return Identity{}, wrapProxyError(StageAuth, ReasonProtocolError, "socks auth reply", err)
	}
	return id, nil
}

// socksReply builds a SOCKS5 reply using the bound address of the target
// connection (zeroes when addr is nil).
func socksReply(rep byte, bind net.Addr) []byte {
	out := []byte{socksVer5, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if bind != nil {
		if host, portStr, err := net.SplitHostPort(bind.String()); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					out[3] = atypIPv4
					copy(out[4:8], v4)
				} else {
					out = append([]byte{socksVer5, rep, 0x00, atypIPv6},
						append(ip.To16(), 0, 0)...)
					if port, err := strconv.Atoi(portStr); err == nil {
						out[len(out)-2] = byte(port >> 8)
						out[len(out)-1] = byte(port)
					}
					return out
				}
				if port, err := strconv.Atoi(portStr); err == nil {
					out[8] = byte(port >> 8)
					out[9] = byte(port)
				}
			}
		}
	}
	return out
}

// socksReplyCode maps a classified pipeline failure to a SOCKS reply code.
func socksReplyCode(e *ProxyError) byte {
	switch e.Reason {
	case ReasonTargetDenied:
		return repNotAllowed
	case ReasonTargetInvalid:
		return repGeneralFailure
	case ReasonDNSFailed:
		return repHostUnreachable
	case ReasonDialTimeout:
		return repTTLExpired
	case ReasonDialFailed:
		return repConnectionRefused
	case ReasonLimitRejected, ReasonQueueTimeout:
		return repGeneralFailure
	default:
		return repGeneralFailure
	}
}

func containsByte(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}

func readFailure(err error, what string) *ProxyError {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return wrapProxyError(StageHandshake, ReasonProtocolError, "short read: "+what, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return wrapProxyError(StageHandshake, ReasonProtocolError, "handshake timeout: "+what, err)
	}
	return wrapProxyError(StageHandshake, ReasonProtocolError, what+" read failed", err)
}

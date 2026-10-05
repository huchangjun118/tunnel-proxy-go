package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/auth"
	"github.com/huchangjun118/tunnel-proxy-go/target"
)

// SOCKS5 protocol constants (RFC 1928, RFC 1929).
const (
	socks5Ver = 0x05

	authNone     = 0x00
	authUserPass = 0x02
	authNoAccept = 0xFF
	userPassVer  = 0x01
	userPassOK   = 0x00
	userPassFail = 0x01

	cmdConnect   = 0x01
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04
	atypNoAccept = 0x00

	repSuccess         = 0x00
	repGeneral         = 0x01
	repNotAllowed      = 0x02
	repNetUnreach      = 0x03
	repHostUnreach     = 0x04
	repConnRefused     = 0x05
	repTTLExpired      = 0x06
	repCmdUnsupported  = 0x07
	repAddrUnsupported = 0x08
)

// socksHandshakeTimeout bounds the time a client may take to send the
// greeting, auth sub-negotiation and request.
const socksHandshakeTimeout = 30 * time.Second

// SocksFrontend implements SOCKS5 with optional username/password auth.
type SocksFrontend struct {
	engine *Engine
}

// NewSocksFrontend creates the SOCKS5 frontend.
func NewSocksFrontend(engine *Engine) *SocksFrontend {
	return &SocksFrontend{engine: engine}
}

// Handle processes one SOCKS5 connection.
func (f *SocksFrontend) Handle(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
	br, _ := inboundReader(conn)

	user, pass, ok := negotiate(br, conn, f.engine)
	if !ok {
		// Protocol failure or failed sub-negotiation; negotiate already
		// sent the refusal and counted the rejection.
		return
	}

	t, cmd, rerr := readSocksRequest(br)
	if rerr != nil {
		f.engine.reg.ErrorProtocol()
		switch {
		case errors.Is(rerr, errUnsupportedCmd):
			writeSocksReply(conn, repCmdUnsupported, nil)
		case errors.Is(rerr, errUnsupportedAddr):
			writeSocksReply(conn, repAddrUnsupported, nil)
		default:
			writeSocksReply(conn, repGeneral, nil)
		}
		return
	}
	if cmd != cmdConnect {
		f.engine.reg.ErrorProtocol()
		writeSocksReply(conn, repCmdUnsupported, nil)
		return
	}

	_ = conn.SetReadDeadline(time.Time{})

	// Same admission pipeline as CONNECT: auth/ACL/limit/dial happen
	// before any success reply and before tunnel data.
	adm, pErr := f.engine.AdmitPreAuthenticated(conn.RemoteAddr().String(), t, user, pass)
	if pErr != nil {
		writeSocksReply(conn, mapEngineError(pErr), nil)
		return
	}

	// Target connected; report success using the upstream local address.
	writeSocksReply(conn, repSuccess, adm.Upstream.LocalAddr())
	f.engine.ServeTunnel(adm, conn, br)
}

var (
	errUnsupportedCmd  = errors.New("socks: unsupported command")
	errUnsupportedAddr = errors.New("socks: unsupported address type")
)

// negotiate handles method selection and, when required, username/
// password sub-negotiation. Credentials are validated through the same
// auth.Authenticator used by CONNECT, so a wrong password fails the
// sub-negotiation with status 0x01 and is counted as an auth rejection,
// exactly like a 407 on the HTTP side. ok=false means the connection
// must be closed and no reply is still pending.
func negotiate(br *bufio.Reader, conn net.Conn, eng *Engine) (user, pass string, ok bool) {
	// Greeting: VER NMETHODS METHODS...
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	if header[0] != socks5Ver {
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	offers := make(map[byte]bool, nmethods)
	for _, m := range methods {
		offers[m] = true
	}

	if !eng.authn.Enabled() {
		if !offers[authNone] {
			_, _ = conn.Write([]byte{socks5Ver, authNoAccept})
			eng.reg.RejectedAuth()
			return "", "", false
		}
		_, _ = conn.Write([]byte{socks5Ver, authNone})
		return "", "", true
	}

	if !offers[authUserPass] {
		_, _ = conn.Write([]byte{socks5Ver, authNoAccept})
		eng.reg.RejectedAuth()
		return "", "", false
	}
	if _, err := conn.Write([]byte{socks5Ver, authUserPass}); err != nil {
		eng.reg.ErrorProtocol()
		return "", "", false
	}

	// RFC 1929: 0x01 ULEN USER PLEN PASS
	upHeader := make([]byte, 2)
	if _, err := io.ReadFull(br, upHeader); err != nil {
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	if upHeader[0] != userPassVer {
		_, _ = conn.Write([]byte{userPassVer, userPassFail})
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	ubuf := make([]byte, int(upHeader[1]))
	if _, err := io.ReadFull(br, ubuf); err != nil {
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	plenByte := make([]byte, 1)
	if _, err := io.ReadFull(br, plenByte); err != nil {
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	pbuf := make([]byte, int(plenByte[0]))
	if _, err := io.ReadFull(br, pbuf); err != nil {
		eng.reg.ErrorProtocol()
		return "", "", false
	}
	user, pass = string(ubuf), string(pbuf)

	// Validate immediately with the shared authenticator: a rejected
	// SOCKS client never reaches target parsing, ACL or dialing, matching
	// the CONNECT 407 semantics. Engine.Admit will re-check harmlessly.
	res := eng.authn.Check(user, pass)
	if res != auth.AuthOK {
		_, _ = conn.Write([]byte{userPassVer, userPassFail})
		eng.reg.RejectedAuth()
		return "", "", false
	}
	_, _ = conn.Write([]byte{userPassVer, userPassOK})
	return user, pass, true
}

// readSocksRequest reads VER CMD RSV ATYP DST.ADDR DST.PORT.
func readSocksRequest(br *bufio.Reader) (target.Target, byte, error) {
	head := make([]byte, 3)
	if _, err := io.ReadFull(br, head); err != nil {
		return target.Target{}, 0, err
	}
	if head[0] != socks5Ver {
		return target.Target{}, 0, fmt.Errorf("socks: bad version %d", head[0])
	}
	cmd := head[1]

	var host string
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(br, atyp); err != nil {
		return target.Target{}, cmd, err
	}
	switch atyp[0] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return target.Target{}, cmd, err
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return target.Target{}, cmd, err
		}
		host = net.IP(buf).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return target.Target{}, cmd, err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, buf); err != nil {
			return target.Target{}, cmd, err
		}
		host = string(buf)
	default:
		return target.Target{}, cmd, errUnsupportedAddr
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return target.Target{}, cmd, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	if cmd != cmdConnect {
		return target.Target{}, cmd, errUnsupportedCmd
	}
	t, err := target.Parse(host, port)
	if err != nil {
		return target.Target{}, cmd, err
	}
	return t, cmd, nil
}

// writeSocksReply sends VER REP RSV ATYP BND.ADDR BND.PORT. The bound
// address is reported as 0.0.0.0:0; clients do not depend on it.
func writeSocksReply(conn net.Conn, rep byte, bindAddr net.Addr) {
	addr, port := []byte{atypIPv4, 0, 0, 0, 0}, []byte{0, 0}
	if tcp, ok := bindAddr.(*net.TCPAddr); ok {
		if v4 := tcp.IP.To4(); v4 != nil {
			addr = append([]byte{atypIPv4}, v4...)
			pb := make([]byte, 2)
			binary.BigEndian.PutUint16(pb, uint16(tcp.Port))
			port = pb
		}
	}
	_, _ = conn.Write(append([]byte{socks5Ver, rep, 0x00}, append(addr, port...)...))
}

// mapEngineError maps a staged engine error to a SOCKS5 reply code.
func mapEngineError(e *Error) byte {
	switch e.Stage {
	case StageAuth:
		return repNotAllowed
	case StageACL:
		return repNotAllowed
	case StageResolve:
		return repHostUnreach
	case StageDial:
		switch e.Cause {
		case CauseDialTimeout:
			return repTTLExpired
		case CauseDialUnreachable:
			return repNetUnreach
		case CauseDialRefused:
			return repConnRefused
		}
		return repHostUnreach
	case StageLimit, StageQueue:
		return repTTLExpired
	case StageProtocol:
		return repGeneral
	default:
		return repGeneral
	}
}

//go:build !windows

package e2e

import (
	"net"
	"syscall"
)

// setLingerZero enables SO_LINGER with zero timeout so closing the
// socket sends a RST instead of going through FIN_WAIT.
func setLingerZero(c *net.TCPConn) {
	if rc, err := c.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER,
				&syscall.Linger{Onoff: 1, Linger: 0})
		})
	}
}

//go:build windows

package e2e

import "net"

func setLingerZero(c *net.TCPConn) {}

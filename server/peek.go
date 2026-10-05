package server

import (
	"bufio"
	"net"
)

func bufioNewReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

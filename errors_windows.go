//go:build windows

package proxy

import (
	"errors"
	"syscall"
)

func isEPIPE(err error) bool { return false }

func isECONNRESET(err error) bool {
	return errors.Is(err, syscall.WSAECONNRESET)
}

package transport

import (
	"errors"
	"fmt"
)

var (
	ErrNoSourceIP       = errors.New("no source IP configured")
	ErrConnectionClosed = errors.New("connection closed")
	ErrPacketTooLarge   = errors.New("packet exceeds MTU")
	ErrInvalidPacket    = errors.New("invalid packet")
)

// rawSocketError wraps a raw socket error while preserving the original
// error's type (especially syscall.Errno which implements net.Error).
type rawSocketError struct {
	msg string
	err error
}

func (e *rawSocketError) Error() string {
	return fmt.Sprintf("%s: %v", e.msg, e.err)
}

func (e *rawSocketError) Unwrap() error {
	return e.err
}

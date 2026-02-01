package transport

import "errors"

var (
	ErrNoSourceIP       = errors.New("no source IP configured")
	ErrPacketTooLarge   = errors.New("packet too large")
	ErrInvalidPacket    = errors.New("invalid packet")
	ErrRawSocketFailed  = errors.New("raw socket creation failed (need root/CAP_NET_RAW)")
	ErrNotIPv4          = errors.New("not an IPv4 address")
	ErrNotIPv6          = errors.New("not an IPv6 address")
	ErrConnectionClosed = errors.New("connection closed")
)

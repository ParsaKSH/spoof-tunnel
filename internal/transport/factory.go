package transport

import "fmt"

// Supported transport types.
const (
	TransportTCP    = "tcp"
	TransportUDP    = "udp"
	TransportICMP   = "icmp"
	TransportICMPv6 = "icmpv6"
)

// NewSender creates a Sender for the given transport type.
func NewSender(transport string, cfg SenderConfig) (Sender, error) {
	switch transport {
	case TransportTCP:
		return NewTCPSender(cfg)
	case TransportUDP:
		return NewUDPSender(cfg)
	case TransportICMP:
		return NewICMPSender(cfg)
	case TransportICMPv6:
		return NewICMPv6Sender(cfg)
	default:
		return nil, fmt.Errorf("unknown send transport: %q (use tcp, udp, icmp, icmpv6)", transport)
	}
}

// NewReceiver creates a Receiver for the given transport type.
func NewReceiver(transport string, cfg ReceiverConfig) (Receiver, error) {
	switch transport {
	case TransportTCP:
		return NewTCPReceiver(cfg)
	case TransportUDP:
		return NewUDPReceiver(cfg)
	case TransportICMP:
		return NewICMPReceiver(cfg)
	case TransportICMPv6:
		return NewICMPv6Receiver(cfg)
	default:
		return nil, fmt.Errorf("unknown recv transport: %q (use tcp, udp, icmp, icmpv6)", transport)
	}
}

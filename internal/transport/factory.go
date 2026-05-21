package transport

import (
	"fmt"
	"log"
)

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
// If XDP is enabled in config, it tries XDP first and falls back to raw socket.
func NewReceiver(transport string, cfg ReceiverConfig) (Receiver, error) {
	// Try XDP first if enabled
	if cfg.UseXDP && cfg.XDPInterface != "" {
		protoNum := transportToProto(transport)
		log.Printf("[transport] XDP requested on %q (proto=%s→%d)", cfg.XDPInterface, transport, protoNum)
		if protoNum > 0 {
			xdp, err := NewXDPReceiver(cfg.XDPInterface, cfg.PeerSpoofIP, cfg.ListenPort, protoNum)
			if err == nil {
				log.Printf("[transport] ✓ XDP attached to %q (proto=%d, port=%d)", cfg.XDPInterface, protoNum, cfg.ListenPort)
				return xdp, nil
			}
			// XDP failed — log and fall back
			log.Printf("[transport] XDP attach to %q failed: %v", cfg.XDPInterface, err)
			log.Printf("[transport] falling back to raw socket receiver")
		}
	}

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

// transportToProto maps transport names to IP protocol numbers for XDP.
func transportToProto(transport string) uint8 {
	switch transport {
	case TransportTCP:
		return 6
	case TransportUDP:
		return 17
	case TransportICMP:
		return 1
	default:
		return 0 // unsupported for XDP
	}
}

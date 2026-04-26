package relay

import (
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/internal/transport"
)

// LocalConfig configures the local (client) relay.
type LocalConfig struct {
	ListenAddr    string
	RemoteIP      net.IP
	RemotePort    uint16
	RecvPort      uint16
	SpoofIP       net.IP
	SpoofIPs      []net.IP
	SpoofPort     uint16
	PeerSpoofIP   net.IP
	SendTransport string // "tcp", "udp", "icmp", "icmpv6"
	RecvTransport string // "tcp", "udp", "icmp", "icmpv6"
}

type Local struct {
	cfg     LocalConfig
	udpConn *net.UDPConn
	sender  transport.Sender
	recver  transport.Receiver

	lastAppAddr atomic.Pointer[net.UDPAddr]

	up       atomic.Uint64
	down     atomic.Uint64
	upPkts   atomic.Uint64
	downPkts atomic.Uint64

	icmpSuppressed bool
}

func NewLocal(cfg LocalConfig) (*Local, error) {
	if cfg.SendTransport == "" {
		cfg.SendTransport = transport.TransportTCP
	}
	if cfg.RecvTransport == "" {
		cfg.RecvTransport = transport.TransportUDP
	}

	icmpSuppressed := false
	if cfg.RecvTransport == transport.TransportICMP || cfg.RecvTransport == transport.TransportICMPv6 {
		if suppressICMPEchoReply() {
			icmpSuppressed = true
		}
	}

	addr, err := net.ResolveUDPAddr("udp4", cfg.ListenAddr)
	if err != nil {
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	senderCfg := transport.SenderConfig{
		SourcePort: cfg.SpoofPort,
		MTU:        1400,
	}
	if len(cfg.SpoofIPs) > 0 {
		senderCfg.SourceIPs = cfg.SpoofIPs
	} else {
		senderCfg.SourceIP = cfg.SpoofIP
	}

	sender, err := transport.NewSender(cfg.SendTransport, senderCfg)
	if err != nil {
		udpConn.Close()
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	recver, err := transport.NewReceiver(cfg.RecvTransport, transport.ReceiverConfig{
		ListenPort:  cfg.RecvPort,
		PeerSpoofIP: cfg.PeerSpoofIP,
		BufferSize:  4 * 1024 * 1024,
	})
	if err != nil {
		udpConn.Close()
		sender.Close()
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	return &Local{
		cfg:            cfg,
		udpConn:        udpConn,
		sender:         sender,
		recver:         recver,
		icmpSuppressed: icmpSuppressed,
	}, nil
}

func (l *Local) Run() {
	go l.uplinkLoop()
	go l.statsLoop()
	l.downlinkLoop()
}

func (l *Local) uplinkLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}
		l.lastAppAddr.Store(addr)
		if err := l.sender.Send(buf[:n], l.cfg.RemoteIP, l.cfg.RemotePort); err != nil {
			continue
		}
		l.up.Add(uint64(n))
		l.upPkts.Add(1)
	}
}

func (l *Local) downlinkLoop() {
	for {
		data, _, _, err := l.recver.Receive()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}
		appAddr := l.lastAppAddr.Load()
		if appAddr == nil {
			continue
		}
		if _, err := l.udpConn.WriteToUDP(data, appAddr); err != nil {
			continue
		}
		l.down.Add(uint64(len(data)))
		l.downPkts.Add(1)
	}
}

func (l *Local) statsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("[local] stats: up=%d pkts (%s) | down=%d pkts (%s)",
			l.upPkts.Load(), formatBytes(l.up.Load()),
			l.downPkts.Load(), formatBytes(l.down.Load()))
	}
}

func (l *Local) Close() {
	l.udpConn.Close()
	l.sender.Close()
	l.recver.Close()
	if l.icmpSuppressed {
		restoreICMPEchoReply()
	}
}

func (l *Local) Stats() (up, down uint64) {
	return l.up.Load(), l.down.Load()
}

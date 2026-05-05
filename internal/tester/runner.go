package tester

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// TesterConfig holds the configuration for a tester run.
type TesterConfig struct {
	Mode          string  `json:"mode"`           // "sender" or "receiver"
	Protocol      string  `json:"protocol"`       // "tcp" or "icmp"
	DstIP         string  `json:"dst_ip"`         // destination IP (sender mode)
	DstPort       int     `json:"dst_port"`       // destination port (TCP only)
	Timeout       int     `json:"timeout"`        // receiver timeout in seconds
	PacketCount   int     `json:"packet_count"`   // packets per source IP
	MaxPacketLoss float64 `json:"max_packet_loss"` // max allowed loss %
	Concurrency   int     `json:"concurrency"`    // sender concurrency
}

// TesterResult holds the result for a single IP.
type TesterResult struct {
	IP       string  `json:"ip"`
	Received int     `json:"received"`
	Sent     int     `json:"sent"`
	LossPct  float64 `json:"loss_pct"`
	Passed   bool    `json:"passed"`
}

// TesterState represents the overall state.
type TesterState struct {
	Status   string          `json:"status"` // "idle", "running", "done", "error"
	Mode     string          `json:"mode"`
	Error    string          `json:"error,omitempty"`
	Progress int             `json:"progress"` // 0-100
	Results  []TesterResult  `json:"results,omitempty"`
}

// Runner manages a tester execution.
type Runner struct {
	mu       sync.Mutex
	state    TesterState
	cancelCh chan struct{}
}

// NewRunner creates a new tester runner.
func NewRunner() *Runner {
	return &Runner{
		state: TesterState{Status: "idle"},
	}
}

// State returns current state.
func (r *Runner) State() TesterState {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state
	if s.Results == nil {
		s.Results = []TesterResult{}
	}
	return s
}

// Stop cancels a running test.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancelCh != nil {
		close(r.cancelCh)
		r.cancelCh = nil
	}
	if r.state.Status == "running" {
		r.state.Status = "idle"
	}
}

// RunSender starts the sender in background.
func (r *Runner) RunSender(cfg TesterConfig, srcIPs []net.IP) error {
	r.mu.Lock()
	if r.state.Status == "running" {
		r.mu.Unlock()
		return fmt.Errorf("tester already running")
	}
	r.state = TesterState{Status: "running", Mode: "sender"}
	r.cancelCh = make(chan struct{})
	cancelCh := r.cancelCh
	r.mu.Unlock()

	go func() {
		err := r.doSend(cfg, srcIPs, cancelCh)
		r.mu.Lock()
		if err != nil {
			r.state.Status = "error"
			r.state.Error = err.Error()
		} else {
			r.state.Status = "done"
			r.state.Progress = 100
		}
		r.mu.Unlock()
	}()

	return nil
}

// RunReceiver starts the receiver in background.
func (r *Runner) RunReceiver(cfg TesterConfig, srcIPs []net.IP) error {
	r.mu.Lock()
	if r.state.Status == "running" {
		r.mu.Unlock()
		return fmt.Errorf("tester already running")
	}
	r.state = TesterState{Status: "running", Mode: "receiver"}
	r.cancelCh = make(chan struct{})
	cancelCh := r.cancelCh
	r.mu.Unlock()

	go func() {
		err := r.doReceive(cfg, srcIPs, cancelCh)
		r.mu.Lock()
		if err != nil {
			r.state.Status = "error"
			r.state.Error = err.Error()
		} else if r.state.Status == "running" {
			r.state.Status = "done"
			r.state.Progress = 100
		}
		r.mu.Unlock()
	}()

	return nil
}

func (r *Runner) doSend(cfg TesterConfig, srcIPs []net.IP, cancel <-chan struct{}) error {
	dstIP := net.ParseIP(cfg.DstIP).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid dst_ip: %s", cfg.DstIP)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw socket: %w (need root/CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP)

	total := len(srcIPs)
	packetCount := cfg.PacketCount
	if packetCount < 1 {
		packetCount = 10
	}

	log.Printf("[tester-sender] protocol=%s dst=%s sources=%d packets_per_ip=%d",
		cfg.Protocol, dstIP, total, packetCount)

	var sent, errCount int
	for i, srcIP := range srcIPs {
		select {
		case <-cancel:
			return nil
		default:
		}

		for p := 0; p < packetCount; p++ {
			var pkt []byte
			seq := uint16((i*packetCount + p) % 65536)
			switch cfg.Protocol {
			case "tcp":
				pkt = BuildTCPSyn(srcIP, dstIP, cfg.DstPort)
			case "icmp":
				pkt = BuildICMPEcho(srcIP, dstIP, uint16(i+1), seq)
			}

			if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
				errCount++
				continue
			}
			sent++
		}

		r.mu.Lock()
		r.state.Progress = (i + 1) * 100 / total
		r.mu.Unlock()
	}

	log.Printf("[tester-sender] done -- sent: %d, errors: %d", sent, errCount)
	return nil
}

func (r *Runner) doReceive(cfg TesterConfig, srcIPs []net.IP, cancel <-chan struct{}) error {
	srcSet := make(map[string]struct{}, len(srcIPs))
	for _, ip := range srcIPs {
		srcSet[ip.To4().String()] = struct{}{}
	}

	var proto int
	switch cfg.Protocol {
	case "tcp":
		proto = syscall.IPPROTO_TCP
	case "icmp":
		proto = syscall.IPPROTO_ICMP
	default:
		return fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return fmt.Errorf("raw socket: %w (need root/CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	timeout := cfg.Timeout
	if timeout < 1 {
		timeout = 30
	}
	packetCount := cfg.PacketCount
	if packetCount < 1 {
		packetCount = 10
	}
	maxLoss := cfg.MaxPacketLoss

	log.Printf("[tester-receiver] protocol=%s sources=%d packet_count=%d max_loss=%.1f%% timeout=%ds",
		cfg.Protocol, len(srcIPs), packetCount, maxLoss, timeout)

	received := make(map[string]int, len(srcIPs))
	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		select {
		case <-cancel:
			return nil
		default:
		}

		elapsed := time.Since(deadline.Add(-time.Duration(timeout) * time.Second))
		total := time.Duration(timeout) * time.Second
		r.mu.Lock()
		r.state.Progress = int(elapsed * 100 / total)
		r.mu.Unlock()

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		if n < 20 {
			continue
		}

		ihl := int(buf[0]&0x0f) * 4
		if n < ihl {
			continue
		}
		srcIP := net.IP(make([]byte, 4))
		copy(srcIP, buf[12:16])
		srcStr := srcIP.String()

		if _, ok := srcSet[srcStr]; !ok {
			continue
		}
		received[srcStr]++
	}

	// Build results
	var results []TesterResult
	for _, ip := range srcIPs {
		ipStr := ip.To4().String()
		count := received[ipStr]
		lossPct := float64(packetCount-count) / float64(packetCount) * 100.0
		results = append(results, TesterResult{
			IP:       ipStr,
			Received: count,
			Sent:     packetCount,
			LossPct:  lossPct,
			Passed:   lossPct <= maxLoss,
		})
	}

	r.mu.Lock()
	r.state.Results = results
	r.mu.Unlock()

	passed := 0
	for _, res := range results {
		if res.Passed {
			passed++
		}
	}

	log.Printf("[tester-receiver] done -- %d/%d IPs passed (loss <= %.1f%%)",
		passed, len(srcIPs), maxLoss)

	return nil
}

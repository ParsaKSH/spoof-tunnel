package tester

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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
	Status      string         `json:"status"` // "idle", "running", "done", "error"
	Mode        string         `json:"mode"`
	Error       string         `json:"error,omitempty"`
	Progress    int            `json:"progress"` // 0-100
	TotalIPs    int64          `json:"total_ips"`
	PassedCount int            `json:"passed_count"`
	RecvCount   int            `json:"recv_count"`
	Results     []TesterResult `json:"results,omitempty"`
}

// Runner manages a tester execution.
type Runner struct {
	mu          sync.Mutex
	state       TesterState
	cancelCh    chan struct{}
	resultsFile string // temp file holding JSON-lines results
	tmpDir      string

	// Live receiver state — accessible during test for real-time monitoring
	recvMu      sync.RWMutex
	received    map[uint32]int
	recvCfgPkt  int     // packetCount for current run
	recvCfgLoss float64 // maxPacketLoss for current run
}

// NewRunner creates a new tester runner.
func NewRunner() *Runner {
	return &Runner{
		state: TesterState{Status: "idle"},
	}
}

// SetTmpDir sets the directory for temporary result files.
func (r *Runner) SetTmpDir(dir string) {
	r.mu.Lock()
	r.tmpDir = dir
	r.mu.Unlock()
}

func (r *Runner) getTmpDir() string {
	if r.tmpDir != "" {
		return r.tmpDir
	}
	return os.TempDir()
}

// State returns current state (without full results — use Results() for that).
func (r *Runner) State() TesterState {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state

	// If receiver is running, update live recv count
	if s.Status == "running" && s.Mode == "receiver" {
		r.recvMu.RLock()
		s.RecvCount = len(r.received)
		r.recvMu.RUnlock()
	}

	if s.Results == nil {
		s.Results = []TesterResult{}
	}
	return s
}

// LiveResults returns the current received IPs during a running receiver test.
// Returns results for all IPs that have received at least one packet so far.
func (r *Runner) LiveResults() []TesterResult {
	r.recvMu.RLock()
	defer r.recvMu.RUnlock()

	if r.received == nil || len(r.received) == 0 {
		return []TesterResult{}
	}

	pktCount := r.recvCfgPkt
	maxLoss := r.recvCfgLoss
	ipBuf := make(net.IP, 4)

	results := make([]TesterResult, 0, len(r.received))
	for ipU32, count := range r.received {
		binary.BigEndian.PutUint32(ipBuf, ipU32)
		lossPct := float64(pktCount-count) / float64(pktCount) * 100.0
		if lossPct < 0 {
			lossPct = 0
		}
		results = append(results, TesterResult{
			IP:       ipBuf.String(),
			Received: count,
			Sent:     pktCount,
			LossPct:  lossPct,
			Passed:   lossPct <= maxLoss,
		})
	}
	return results
}

// Results reads results from the temp file (post-completion) or returns
// live results if the receiver is still running.
func (r *Runner) Results() ([]TesterResult, error) {
	r.mu.Lock()
	status := r.state.Status
	mode := r.state.Mode
	path := r.resultsFile
	r.mu.Unlock()

	// If receiver is still running, return live results
	if status == "running" && mode == "receiver" {
		return r.LiveResults(), nil
	}

	if path == "" {
		return []TesterResult{}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []TesterResult{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var results []TesterResult
	dec := json.NewDecoder(f)
	for dec.More() {
		var res TesterResult
		if err := dec.Decode(&res); err != nil {
			break
		}
		results = append(results, res)
	}
	return results, nil
}

// PassedIPs returns only the IPs that passed the test.
func (r *Runner) PassedIPs() ([]string, error) {
	results, err := r.Results()
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, res := range results {
		if res.Passed {
			ips = append(ips, res.IP)
		}
	}
	return ips, nil
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

// RunSender starts the sender in background using compact IPRangeSet.
func (r *Runner) RunSender(cfg TesterConfig, ranges *IPRangeSet) error {
	r.mu.Lock()
	if r.state.Status == "running" {
		r.mu.Unlock()
		return fmt.Errorf("tester already running")
	}
	r.state = TesterState{Status: "running", Mode: "sender", TotalIPs: ranges.Total()}
	r.cancelCh = make(chan struct{})
	cancelCh := r.cancelCh
	// Clean old results
	if r.resultsFile != "" {
		os.Remove(r.resultsFile)
		r.resultsFile = ""
	}
	r.mu.Unlock()

	go func() {
		err := r.doSend(cfg, ranges, cancelCh)
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

// RunReceiver starts the receiver in background using compact IPRangeSet.
func (r *Runner) RunReceiver(cfg TesterConfig, ranges *IPRangeSet) error {
	r.mu.Lock()
	if r.state.Status == "running" {
		r.mu.Unlock()
		return fmt.Errorf("tester already running")
	}
	r.state = TesterState{Status: "running", Mode: "receiver", TotalIPs: ranges.Total()}
	r.cancelCh = make(chan struct{})
	cancelCh := r.cancelCh
	// Clean old results
	if r.resultsFile != "" {
		os.Remove(r.resultsFile)
		r.resultsFile = ""
	}
	// Initialize live receiver state
	r.recvMu.Lock()
	r.received = make(map[uint32]int)
	pktCount := cfg.PacketCount
	if pktCount < 1 {
		pktCount = 10
	}
	r.recvCfgPkt = pktCount
	r.recvCfgLoss = cfg.MaxPacketLoss
	r.recvMu.Unlock()

	r.mu.Unlock()

	go func() {
		err := r.doReceive(cfg, ranges, cancelCh)
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

func (r *Runner) doSend(cfg TesterConfig, ranges *IPRangeSet, cancel <-chan struct{}) error {
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

	total := ranges.Total()
	packetCount := cfg.PacketCount
	if packetCount < 1 {
		packetCount = 10
	}

	log.Printf("[tester-sender] protocol=%s dst=%s sources=%d packets_per_ip=%d",
		cfg.Protocol, dstIP, total, packetCount)

	var sent, errCount int
	var idx int
	ranges.IterateIPs(func(srcIP net.IP) bool {
		// Check cancel
		select {
		case <-cancel:
			return false
		default:
		}

		for p := 0; p < packetCount; p++ {
			var pkt []byte
			seq := uint16((idx*packetCount + p) % 65536)
			switch cfg.Protocol {
			case "tcp":
				pkt = BuildTCPSyn(srcIP, dstIP, cfg.DstPort)
			case "icmp":
				pkt = BuildICMPEcho(srcIP, dstIP, uint16(idx+1), seq)
			}

			if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
				errCount++
				continue
			}
			sent++
		}

		idx++
		r.mu.Lock()
		r.state.Progress = int(int64(idx) * 100 / total)
		r.mu.Unlock()
		return true
	})

	log.Printf("[tester-sender] done -- sent: %d, errors: %d", sent, errCount)
	return nil
}

// flushInterimResults writes current received IPs to the results file.
// Called periodically (every 5 min) and at the end of the test.
func (r *Runner) flushInterimResults(packetCount int, maxLoss float64) {
	r.recvMu.RLock()
	if len(r.received) == 0 {
		r.recvMu.RUnlock()
		return
	}

	// Copy received map under read lock
	snapshot := make(map[uint32]int, len(r.received))
	for k, v := range r.received {
		snapshot[k] = v
	}
	r.recvMu.RUnlock()

	tmpDir := r.getTmpDir()
	os.MkdirAll(tmpDir, 0755)
	stablePath := filepath.Join(tmpDir, "tester-results.jsonl")

	f, err := os.Create(stablePath)
	if err != nil {
		log.Printf("[tester-receiver] flush error: %v", err)
		return
	}

	enc := json.NewEncoder(f)
	passedCount := 0
	ipBuf := make(net.IP, 4)
	batch := 0

	for ipU32, count := range snapshot {
		binary.BigEndian.PutUint32(ipBuf, ipU32)
		lossPct := float64(packetCount-count) / float64(packetCount) * 100.0
		if lossPct < 0 {
			lossPct = 0
		}
		passed := lossPct <= maxLoss
		if passed {
			passedCount++
		}

		enc.Encode(TesterResult{
			IP:       ipBuf.String(),
			Received: count,
			Sent:     packetCount,
			LossPct:  lossPct,
			Passed:   passed,
		})
		batch++
		if batch%1000 == 0 {
			f.Sync()
		}
	}
	f.Close()

	r.mu.Lock()
	r.resultsFile = stablePath
	r.state.PassedCount = passedCount
	r.state.RecvCount = len(snapshot)
	r.mu.Unlock()

	log.Printf("[tester-receiver] interim flush -- %d IPs received, %d passed", len(snapshot), passedCount)
}

func (r *Runner) doReceive(cfg TesterConfig, ranges *IPRangeSet, cancel <-chan struct{}) error {
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
		cfg.Protocol, ranges.Total(), packetCount, maxLoss, timeout)

	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	startTime := time.Now()

	// Periodic flush ticker — every 5 minutes
	flushInterval := 5 * time.Minute
	lastFlush := time.Now()

	for time.Now().Before(deadline) {
		select {
		case <-cancel:
			goto buildResults
		default:
		}

		elapsed := time.Since(startTime)
		total := time.Duration(timeout) * time.Second
		r.mu.Lock()
		r.state.Progress = int(elapsed * 100 / total)
		r.mu.Unlock()

		// Periodic flush to disk
		if time.Since(lastFlush) >= flushInterval {
			r.flushInterimResults(packetCount, maxLoss)
			lastFlush = time.Now()
		}

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
		srcIPu32 := binary.BigEndian.Uint32(buf[12:16])

		if !ranges.Contains(srcIPu32) {
			continue
		}

		r.recvMu.Lock()
		r.received[srcIPu32]++
		r.recvMu.Unlock()
	}

buildResults:
	// Final flush — write definitive results to disk
	r.flushInterimResults(packetCount, maxLoss)

	r.recvMu.RLock()
	recvTotal := len(r.received)
	r.recvMu.RUnlock()

	r.mu.Lock()
	passedCount := r.state.PassedCount
	r.mu.Unlock()

	log.Printf("[tester-receiver] done -- %d/%d IPs received packets, %d passed (loss <= %.1f%%)",
		recvTotal, ranges.Total(), passedCount, maxLoss)

	// Clear the live received map to free memory
	r.recvMu.Lock()
	r.received = nil
	r.recvMu.Unlock()

	return nil
}

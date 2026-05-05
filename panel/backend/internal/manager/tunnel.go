package manager

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/panel/internal/db"
	"gorm.io/gorm"
)

// TunnelStatus represents the tunnel process status
type TunnelStatus string

const (
	StatusStopped  TunnelStatus = "stopped"
	StatusRunning  TunnelStatus = "running"
	StatusStarting TunnelStatus = "starting"
	StatusError    TunnelStatus = "error"
)

// Instance represents a single running tunnel process
type Instance struct {
	ID        uint
	cmd       *exec.Cmd
	status    TunnelStatus
	error     string
	mu        sync.Mutex
	logLines  []string
	logMu     sync.RWMutex
	logCh     chan string
	maxLogs   int
	startTime time.Time
}

func newInstance(id uint) *Instance {
	return &Instance{
		ID:       id,
		status:   StatusStopped,
		logLines: make([]string, 0, 1000),
		logCh:    make(chan string, 100),
		maxLogs:  1000,
	}
}

// Manager manages multiple tunnel instances
type Manager struct {
	db         *gorm.DB
	binaryPath string
	configDir  string
	instances  map[uint]*Instance
	mu         sync.RWMutex
}

// NewManager creates a new multi-instance tunnel manager
func NewManager(database *gorm.DB, binaryPath, configDir string) *Manager {
	return &Manager{
		db:         database,
		binaryPath: binaryPath,
		configDir:  configDir,
		instances:  make(map[uint]*Instance),
	}
}

// getInstance returns or creates an Instance tracker for the given ID
func (m *Manager) getInstance(id uint) *Instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.instances[id]
	if !ok {
		inst = newInstance(id)
		m.instances[id] = inst
	}
	return inst
}

// InstanceStatus returns current status for an instance
func (m *Manager) InstanceStatus(id uint) (TunnelStatus, string) {
	inst := m.getInstance(id)
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.status, inst.error
}

// StartInstance starts a tunnel instance
func (m *Manager) StartInstance(id uint) error {
	inst := m.getInstance(id)
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.status == StatusRunning {
		return fmt.Errorf("instance %d already running", id)
	}

	// Load config from DB
	var cfg db.TunnelInstance
	if err := m.db.First(&cfg, id).Error; err != nil {
		return fmt.Errorf("instance %d not found: %w", id, err)
	}

	// Generate config file
	configPath, err := m.generateConfig(cfg)
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	// Write spoof IP file if needed
	if cfg.SpoofIPList != "" {
		spoofPath := m.spoofIPFilePath(id)
		os.MkdirAll(filepath.Dir(spoofPath), 0755)
		if err := os.WriteFile(spoofPath, []byte(cfg.SpoofIPList+"\n"), 0644); err != nil {
			return fmt.Errorf("write spoof IPs: %w", err)
		}
	}

	inst.status = StatusStarting

	// Start the binary
	inst.cmd = exec.Command(m.binaryPath, "run", "--config", configPath)
	inst.cmd.Env = append(os.Environ(), "GODEBUG=madvdontneed=1")

	stdout, err := inst.cmd.StdoutPipe()
	if err != nil {
		inst.status = StatusError
		inst.error = err.Error()
		return err
	}
	stderr, err := inst.cmd.StderrPipe()
	if err != nil {
		inst.status = StatusError
		inst.error = err.Error()
		return err
	}

	if err := inst.cmd.Start(); err != nil {
		inst.status = StatusError
		inst.error = err.Error()
		return err
	}

	inst.status = StatusRunning
	inst.error = ""
	inst.startTime = time.Now()

	// Clear old logs
	inst.logMu.Lock()
	inst.logLines = make([]string, 0, 1000)
	inst.logMu.Unlock()

	go streamLogs(inst, stdout)
	go streamLogs(inst, stderr)

	go func() {
		err := inst.cmd.Wait()
		inst.mu.Lock()
		if inst.status == StatusRunning {
			inst.status = StatusStopped
			if err != nil {
				inst.status = StatusError
				inst.error = err.Error()
			}
		}
		inst.mu.Unlock()
	}()

	log.Printf("[manager] started instance %d (%s)", id, cfg.Name)
	return nil
}

// StopInstance stops a tunnel instance
func (m *Manager) StopInstance(id uint) error {
	inst := m.getInstance(id)
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.cmd == nil || inst.cmd.Process == nil {
		inst.status = StatusStopped
		return nil
	}

	inst.status = StatusStopped
	log.Printf("[manager] stopping instance %d", id)
	return inst.cmd.Process.Kill()
}

// RestartInstance restarts a tunnel instance
func (m *Manager) RestartInstance(id uint) error {
	m.StopInstance(id)
	time.Sleep(500 * time.Millisecond)
	return m.StartInstance(id)
}

// InstanceUptime returns uptime for an instance
func (m *Manager) InstanceUptime(id uint) time.Duration {
	inst := m.getInstance(id)
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.status != StatusRunning {
		return 0
	}
	return time.Since(inst.startTime)
}

// InstanceLogs returns recent log lines for an instance
func (m *Manager) InstanceLogs(id uint, n int) []string {
	inst := m.getInstance(id)
	inst.logMu.RLock()
	defer inst.logMu.RUnlock()

	if n <= 0 || n > len(inst.logLines) {
		n = len(inst.logLines)
	}
	start := len(inst.logLines) - n
	result := make([]string, n)
	copy(result, inst.logLines[start:])
	return result
}

// InstanceLogChannel returns the log channel for WebSocket streaming
func (m *Manager) InstanceLogChannel(id uint) <-chan string {
	inst := m.getInstance(id)
	return inst.logCh
}

// RemoveInstance cleans up instance state after deletion
func (m *Manager) RemoveInstance(id uint) {
	m.StopInstance(id)
	m.mu.Lock()
	delete(m.instances, id)
	m.mu.Unlock()

	// Clean up files
	os.Remove(m.configFilePath(id))
	os.Remove(m.spoofIPFilePath(id))
}

// StopAll stops all running instances
func (m *Manager) StopAll() {
	m.mu.RLock()
	ids := make([]uint, 0, len(m.instances))
	for id := range m.instances {
		ids = append(ids, id)
	}
	m.mu.RUnlock()

	for _, id := range ids {
		m.StopInstance(id)
	}
}

// AllStatuses returns status for all known instances
func (m *Manager) AllStatuses() map[uint]TunnelStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[uint]TunnelStatus, len(m.instances))
	for id, inst := range m.instances {
		inst.mu.Lock()
		result[id] = inst.status
		inst.mu.Unlock()
	}
	return result
}

// ── Legacy compatibility ──

// Status returns the status of the first instance (for backward compat)
func (m *Manager) Status() (TunnelStatus, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, inst := range m.instances {
		inst.mu.Lock()
		s, e := inst.status, inst.error
		inst.mu.Unlock()
		return s, e
	}
	return StatusStopped, ""
}

// Uptime returns the uptime of the first instance
func (m *Manager) Uptime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, inst := range m.instances {
		inst.mu.Lock()
		if inst.status != StatusRunning {
			inst.mu.Unlock()
			return 0
		}
		d := time.Since(inst.startTime)
		inst.mu.Unlock()
		return d
	}
	return 0
}

// GetLogs returns logs from the first instance
func (m *Manager) GetLogs(n int) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id := range m.instances {
		return m.InstanceLogs(id, n)
	}
	return nil
}

// LogChannel returns log channel from the first instance
func (m *Manager) LogChannel() <-chan string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id := range m.instances {
		return m.InstanceLogChannel(id)
	}
	ch := make(chan string)
	close(ch)
	return ch
}

// BinaryPath returns the path to the spoof binary
func (m *Manager) BinaryPath() string {
	return m.binaryPath
}

// ── Internal ──

func (m *Manager) configFilePath(id uint) string {
	return filepath.Join(m.configDir, fmt.Sprintf("tunnel-config-%d.json", id))
}

func (m *Manager) spoofIPFilePath(id uint) string {
	return filepath.Join(m.configDir, fmt.Sprintf("spoof-ips-%d.txt", id))
}

func (m *Manager) generateConfig(cfg db.TunnelInstance) (string, error) {
	tunnelCfg := map[string]interface{}{
		"mode":           cfg.Mode,
		"send_transport": cfg.SendTransport,
		"recv_transport": cfg.RecvTransport,
		"spoof_ip":       cfg.SpoofIP,
		"spoof_port":     cfg.SpoofPort,
		"peer_spoof_ip":  cfg.PeerSpoofIP,
	}

	// If inline spoof IPs exist, write them to a file and reference it
	if strings.TrimSpace(cfg.SpoofIPList) != "" {
		spoofPath := m.spoofIPFilePath(cfg.ID)
		tunnelCfg["spoof_ip_file"] = spoofPath
	}

	switch cfg.Mode {
	case "local":
		tunnelCfg["listen"] = cfg.ListenAddr
		tunnelCfg["remote"] = cfg.RemoteAddr
		tunnelCfg["remote_port"] = cfg.RemotePort
		tunnelCfg["recv_port"] = cfg.RecvPort
	case "remote":
		tunnelCfg["listen_port"] = cfg.ListenPort
		tunnelCfg["forward"] = cfg.ForwardAddr
		tunnelCfg["client_ip"] = cfg.ClientIP
		tunnelCfg["client_port"] = cfg.ClientPort
	}

	data, err := json.MarshalIndent(tunnelCfg, "", "  ")
	if err != nil {
		return "", err
	}

	configPath := m.configFilePath(cfg.ID)
	os.MkdirAll(filepath.Dir(configPath), 0755)

	log.Printf("[manager] writing config for instance %d to %s", cfg.ID, configPath)
	return configPath, os.WriteFile(configPath, data, 0600)
}

func streamLogs(inst *Instance, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 4096)

	for scanner.Scan() {
		line := scanner.Text()

		inst.logMu.Lock()
		inst.logLines = append(inst.logLines, line)
		if len(inst.logLines) > inst.maxLogs {
			inst.logLines = inst.logLines[len(inst.logLines)-inst.maxLogs:]
		}
		inst.logMu.Unlock()

		select {
		case inst.logCh <- line:
		default:
		}
	}
}

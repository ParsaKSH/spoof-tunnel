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

// Manager manages the spoof-tunnel process
type Manager struct {
	db         *gorm.DB
	binaryPath string
	configPath string

	cmd    *exec.Cmd
	status TunnelStatus
	error  string
	mu     sync.Mutex

	// Log streaming
	logLines []string
	logMu    sync.RWMutex
	logCh    chan string
	maxLogs  int

	// Stats
	startTime time.Time
}

// NewManager creates a new tunnel manager
func NewManager(database *gorm.DB, binaryPath, configDir string) *Manager {
	return &Manager{
		db:         database,
		binaryPath: binaryPath,
		configPath: filepath.Join(configDir, "tunnel-config.json"),
		status:     StatusStopped,
		logLines:   make([]string, 0, 1000),
		logCh:      make(chan string, 100),
		maxLogs:    1000,
	}
}

// Status returns current tunnel status
func (m *Manager) Status() (TunnelStatus, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status, m.error
}

// Start starts the tunnel process
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status == StatusRunning {
		return fmt.Errorf("tunnel already running")
	}

	// Generate config from DB
	if err := m.generateConfig(); err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	m.status = StatusStarting

	// Start the binary with "run --config" subcommand
	m.cmd = exec.Command(m.binaryPath, "run", "--config", m.configPath)
	m.cmd.Env = append(os.Environ(), "GODEBUG=madvdontneed=1")

	// Capture stdout and stderr
	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		m.status = StatusError
		m.error = err.Error()
		return err
	}
	stderr, err := m.cmd.StderrPipe()
	if err != nil {
		m.status = StatusError
		m.error = err.Error()
		return err
	}

	if err := m.cmd.Start(); err != nil {
		m.status = StatusError
		m.error = err.Error()
		return err
	}

	m.status = StatusRunning
	m.error = ""
	m.startTime = time.Now()

	// Stream logs
	go m.streamLogs(stdout)
	go m.streamLogs(stderr)

	// Wait for process to exit
	go func() {
		err := m.cmd.Wait()
		m.mu.Lock()
		if m.status == StatusRunning {
			m.status = StatusStopped
			if err != nil {
				m.status = StatusError
				m.error = err.Error()
			}
		}
		m.mu.Unlock()
	}()

	return nil
}

// Stop stops the tunnel process
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd == nil || m.cmd.Process == nil {
		m.status = StatusStopped
		return nil
	}

	m.status = StatusStopped
	return m.cmd.Process.Kill()
}

// Restart restarts the tunnel
func (m *Manager) Restart() error {
	m.Stop()
	time.Sleep(500 * time.Millisecond)
	return m.Start()
}

// Uptime returns tunnel uptime
func (m *Manager) Uptime() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != StatusRunning {
		return 0
	}
	return time.Since(m.startTime)
}

// GetLogs returns recent log lines
func (m *Manager) GetLogs(n int) []string {
	m.logMu.RLock()
	defer m.logMu.RUnlock()

	if n <= 0 || n > len(m.logLines) {
		n = len(m.logLines)
	}
	start := len(m.logLines) - n
	result := make([]string, n)
	copy(result, m.logLines[start:])
	return result
}

// LogChannel returns the log channel for WebSocket streaming
func (m *Manager) LogChannel() <-chan string {
	return m.logCh
}

func (m *Manager) streamLogs(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 4096)

	for scanner.Scan() {
		line := scanner.Text()

		m.logMu.Lock()
		m.logLines = append(m.logLines, line)
		if len(m.logLines) > m.maxLogs {
			m.logLines = m.logLines[len(m.logLines)-m.maxLogs:]
		}
		m.logMu.Unlock()

		// Non-blocking send to channel
		select {
		case m.logCh <- line:
		default:
		}
	}
}

// generateConfig builds a config.json matching the new core format
func (m *Manager) generateConfig() error {
	var cfg db.ServerConfig
	if err := m.db.First(&cfg).Error; err != nil {
		return err
	}

	tunnelCfg := map[string]interface{}{
		"mode":           cfg.Mode,
		"send_transport": cfg.SendTransport,
		"recv_transport": cfg.RecvTransport,
		"spoof_ip":       cfg.SpoofIP,
		"spoof_port":     cfg.SpoofPort,
		"peer_spoof_ip":  cfg.PeerSpoofIP,
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
		return err
	}

	dir := filepath.Dir(m.configPath)
	os.MkdirAll(dir, 0755)

	log.Printf("[manager] writing config to %s", m.configPath)
	return os.WriteFile(m.configPath, data, 0600)
}

// BinaryPath returns the path to the spoof binary
func (m *Manager) BinaryPath() string {
	return m.binaryPath
}

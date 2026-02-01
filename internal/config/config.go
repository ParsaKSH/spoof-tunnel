package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Mode represents the operating mode of the tunnel
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

// TransportType represents the transport protocol
type TransportType string

const (
	TransportUDP  TransportType = "udp"
	TransportICMP TransportType = "icmp"
	TransportRAW  TransportType = "raw"
)

// ICMPMode represents the ICMP packet type to use
type ICMPMode string

const (
	ICMPModeEcho  ICMPMode = "echo"
	ICMPModeReply ICMPMode = "reply"
)

// LogLevel represents logging verbosity
type LogLevel string

const (
	LogDebug LogLevel = "debug"
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// Config holds all configuration for the tunnel
type Config struct {
	Mode        Mode              `json:"mode"`
	Transport   TransportConfig   `json:"transport"`
	Listen      ListenConfig      `json:"listen"`
	Server      ServerConfig      `json:"server"`
	Spoof       SpoofConfig       `json:"spoof"`
	Crypto      CryptoConfig      `json:"crypto"`
	Performance PerformanceConfig `json:"performance"`
	Reliability ReliabilityConfig `json:"reliability"`
	FEC         FECConfig         `json:"fec"`
	Keepalive   KeepaliveConfig   `json:"keepalive"`
	Logging     LoggingConfig     `json:"logging"`
}

// TransportConfig configures the transport layer
type TransportConfig struct {
	Type           TransportType `json:"type"`
	ICMPMode       ICMPMode      `json:"icmp_mode"`
	ProtocolNumber int           `json:"protocol_number"` // Custom IP protocol number (1-255), used when type is "raw"
}

// ListenConfig configures the listening address
type ListenConfig struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// ServerConfig configures the remote server (client mode only)
type ServerConfig struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// SpoofConfig configures IP spoofing
type SpoofConfig struct {
	SourceIP      string `json:"source_ip"`
	SourceIPv6    string `json:"source_ipv6"`
	PeerSpoofIP   string `json:"peer_spoof_ip"`
	PeerSpoofIPv6 string `json:"peer_spoof_ipv6"`
	// ClientRealIP is the actual IP of the client (server mode only)
	// Server sends packets to this IP
	ClientRealIP   string `json:"client_real_ip"`
	ClientRealIPv6 string `json:"client_real_ipv6"`
}

// CryptoConfig configures encryption keys
type CryptoConfig struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
}

// PerformanceConfig configures performance tuning
type PerformanceConfig struct {
	BufferSize     int `json:"buffer_size"`
	MTU            int `json:"mtu"`
	SessionTimeout int `json:"session_timeout"`
	Workers        int `json:"workers"`
	ReadBuffer     int `json:"read_buffer"`
	WriteBuffer    int `json:"write_buffer"`
	SendRateLimit  int `json:"send_rate_limit"` // packets per second, 0 = default (1000)
}

// LoggingConfig configures logging
type LoggingConfig struct {
	Level LogLevel `json:"level"`
	File  string   `json:"file"`
}

// ReliabilityConfig configures reliable delivery
type ReliabilityConfig struct {
	Enabled             bool `json:"enabled"`
	WindowSize          int  `json:"window_size"`           // Max in-flight packets
	RetransmitTimeoutMs int  `json:"retransmit_timeout_ms"` // Initial retransmit timeout
	MaxRetries          int  `json:"max_retries"`           // Max retransmit attempts
	AckIntervalMs       int  `json:"ack_interval_ms"`       // How often to send ACKs
}

// FECConfig configures Forward Error Correction
type FECConfig struct {
	Enabled      bool `json:"enabled"`
	DataShards   int  `json:"data_shards"`   // Number of data shards (original packets)
	ParityShards int  `json:"parity_shards"` // Number of parity shards (redundant packets)
}

// KeepaliveConfig configures session keepalive
type KeepaliveConfig struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"` // PING interval
	TimeoutSeconds  int  `json:"timeout_seconds"`  // Session timeout without response
}

// Load reads and parses configuration from a JSON file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// setDefaults applies default values for unset fields
func (c *Config) setDefaults() error {
	// Transport defaults
	if c.Transport.Type == "" {
		c.Transport.Type = TransportUDP
	}
	if c.Transport.ICMPMode == "" {
		c.Transport.ICMPMode = ICMPModeEcho
	}

	// Listen defaults
	if c.Listen.Address == "" {
		c.Listen.Address = "127.0.0.1"
	}
	if c.Listen.Port == 0 {
		if c.Mode == ModeClient {
			c.Listen.Port = 1080
		} else {
			c.Listen.Port = 8080
		}
	}

	// Performance defaults
	if c.Performance.BufferSize == 0 {
		c.Performance.BufferSize = 65535
	}
	if c.Performance.MTU == 0 {
		c.Performance.MTU = 1400
	}
	if c.Performance.SessionTimeout == 0 {
		c.Performance.SessionTimeout = 600 // 10 minutes
	}
	if c.Performance.Workers == 0 {
		c.Performance.Workers = 4
	}
	if c.Performance.ReadBuffer == 0 {
		c.Performance.ReadBuffer = 4 * 1024 * 1024
	}
	if c.Performance.WriteBuffer == 0 {
		c.Performance.WriteBuffer = 4 * 1024 * 1024
	}

	// Reliability defaults - enabled by default for UDP/ICMP
	if c.Reliability.WindowSize == 0 {
		c.Reliability.WindowSize = 128
	}
	if c.Reliability.RetransmitTimeoutMs == 0 {
		c.Reliability.RetransmitTimeoutMs = 300
	}
	if c.Reliability.MaxRetries == 0 {
		c.Reliability.MaxRetries = 5
	}
	if c.Reliability.AckIntervalMs == 0 {
		c.Reliability.AckIntervalMs = 50
	}

	// FEC defaults - disabled by default
	if c.FEC.Enabled {
		if c.FEC.DataShards == 0 {
			c.FEC.DataShards = 10
		}
		if c.FEC.ParityShards == 0 {
			c.FEC.ParityShards = 3
		}
	}

	// Keepalive defaults - enabled by default
	if c.Keepalive.IntervalSeconds == 0 {
		c.Keepalive.IntervalSeconds = 30
	}
	if c.Keepalive.TimeoutSeconds == 0 {
		c.Keepalive.TimeoutSeconds = 120
	}

	// Logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = LogInfo
	}

	return nil
}

// Validate checks that the configuration is valid
func (c *Config) Validate() error {
	var errs []string

	// Mode validation
	if c.Mode != ModeClient && c.Mode != ModeServer {
		errs = append(errs, fmt.Sprintf("invalid mode: %s (must be 'client' or 'server')", c.Mode))
	}

	// Transport validation
	if c.Transport.Type != TransportUDP && c.Transport.Type != TransportICMP && c.Transport.Type != TransportRAW {
		errs = append(errs, fmt.Sprintf("invalid transport type: %s (must be 'udp', 'icmp', or 'raw')", c.Transport.Type))
	}
	if c.Transport.Type == TransportICMP {
		if c.Transport.ICMPMode != ICMPModeEcho && c.Transport.ICMPMode != ICMPModeReply {
			errs = append(errs, fmt.Sprintf("invalid icmp_mode: %s", c.Transport.ICMPMode))
		}
	}
	if c.Transport.Type == TransportRAW {
		if c.Transport.ProtocolNumber < 1 || c.Transport.ProtocolNumber > 255 {
			errs = append(errs, fmt.Sprintf("invalid protocol_number: %d (must be 1-255)", c.Transport.ProtocolNumber))
		}
	}

	// Listen validation
	if net.ParseIP(c.Listen.Address) == nil {
		errs = append(errs, fmt.Sprintf("invalid listen address: %s", c.Listen.Address))
	}
	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		errs = append(errs, fmt.Sprintf("invalid listen port: %d", c.Listen.Port))
	}

	// Server validation (client mode only)
	if c.Mode == ModeClient {
		if c.Server.Address == "" {
			errs = append(errs, "server address is required in client mode")
		}
		if c.Server.Port < 1 || c.Server.Port > 65535 {
			errs = append(errs, fmt.Sprintf("invalid server port: %d", c.Server.Port))
		}
	}

	// Spoof validation
	if c.Spoof.SourceIP != "" && net.ParseIP(c.Spoof.SourceIP) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof source_ip: %s", c.Spoof.SourceIP))
	}
	if c.Spoof.SourceIPv6 != "" && net.ParseIP(c.Spoof.SourceIPv6) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof source_ipv6: %s", c.Spoof.SourceIPv6))
	}
	if c.Spoof.PeerSpoofIP != "" && net.ParseIP(c.Spoof.PeerSpoofIP) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof peer_spoof_ip: %s", c.Spoof.PeerSpoofIP))
	}
	if c.Spoof.PeerSpoofIPv6 != "" && net.ParseIP(c.Spoof.PeerSpoofIPv6) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof peer_spoof_ipv6: %s", c.Spoof.PeerSpoofIPv6))
	}

	// At least one spoof IP required
	if c.Spoof.SourceIP == "" && c.Spoof.SourceIPv6 == "" {
		errs = append(errs, "at least one spoof source IP (IPv4 or IPv6) is required")
	}

	// Server mode: client_real_ip is required
	if c.Mode == ModeServer {
		if c.Spoof.ClientRealIP == "" && c.Spoof.ClientRealIPv6 == "" {
			errs = append(errs, "client_real_ip is required in server mode (where to send packets)")
		}
		if c.Spoof.ClientRealIP != "" && net.ParseIP(c.Spoof.ClientRealIP) == nil {
			errs = append(errs, fmt.Sprintf("invalid client_real_ip: %s", c.Spoof.ClientRealIP))
		}
		if c.Spoof.ClientRealIPv6 != "" && net.ParseIP(c.Spoof.ClientRealIPv6) == nil {
			errs = append(errs, fmt.Sprintf("invalid client_real_ipv6: %s", c.Spoof.ClientRealIPv6))
		}
	}

	// Crypto validation
	if c.Crypto.PrivateKey == "" {
		errs = append(errs, "crypto.private_key is required (generate with: ./spoof generate-keys)")
	}
	if c.Crypto.PeerPublicKey == "" {
		errs = append(errs, "crypto.peer_public_key is required")
	}

	// FEC validation
	if c.FEC.Enabled {
		if c.FEC.DataShards < 1 {
			errs = append(errs, "fec.data_shards must be at least 1")
		}
		if c.FEC.ParityShards < 1 {
			errs = append(errs, "fec.parity_shards must be at least 1")
		}
		// Reed-Solomon limit: data + parity <= 256
		if c.FEC.DataShards+c.FEC.ParityShards > 256 {
			errs = append(errs, fmt.Sprintf("fec.data_shards + fec.parity_shards must be <= 256 (got %d)", c.FEC.DataShards+c.FEC.ParityShards))
		}
	}

	// Logging validation
	validLevels := map[LogLevel]bool{LogDebug: true, LogInfo: true, LogWarn: true, LogError: true}
	if !validLevels[c.Logging.Level] {
		errs = append(errs, fmt.Sprintf("invalid log level: %s", c.Logging.Level))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config errors:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}

// GetListenAddr returns the formatted listen address
func (c *Config) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Listen.Address, c.Listen.Port)
}

// GetServerAddr returns the formatted server address
func (c *Config) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Address, c.Server.Port)
}

// IsIPv6 returns true if the primary spoof IP is IPv6
func (c *Config) IsIPv6() bool {
	if c.Spoof.SourceIP != "" {
		ip := net.ParseIP(c.Spoof.SourceIP)
		return ip != nil && ip.To4() == nil
	}
	return c.Spoof.SourceIPv6 != ""
}

// GetSourceIP returns the appropriate source IP based on IP version
func (c *Config) GetSourceIP(ipv6 bool) string {
	if ipv6 {
		return c.Spoof.SourceIPv6
	}
	return c.Spoof.SourceIP
}

// GetPeerSpoofIP returns the appropriate peer spoof IP based on IP version
func (c *Config) GetPeerSpoofIP(ipv6 bool) string {
	if ipv6 {
		return c.Spoof.PeerSpoofIPv6
	}
	return c.Spoof.PeerSpoofIP
}

// GetClientRealIP returns the appropriate client real IP based on IP version
func (c *Config) GetClientRealIP(ipv6 bool) string {
	if ipv6 {
		return c.Spoof.ClientRealIPv6
	}
	return c.Spoof.ClientRealIP
}

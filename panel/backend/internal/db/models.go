package db

import (
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// User represents an admin user
type User struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// ServerConfig holds the tunnel configuration (single row)
type ServerConfig struct {
	ID                 uint      `gorm:"primarykey" json:"id"`
	Mode               string    `gorm:"default:client" json:"mode"`
	TransportType      string    `gorm:"default:syn_udp" json:"transport_type"`
	ServerAddress      string    `json:"server_address"`
	ServerPort         int       `gorm:"default:8080" json:"server_port"`
	ListenPort         int       `gorm:"default:8080" json:"listen_port"`
	SpoofSourceIP      string    `json:"spoof_source_ip"`
	SpoofPeerIP        string    `json:"spoof_peer_ip"`
	ClientRealIP       string    `json:"client_real_ip"`
	PrivateKey         string    `json:"private_key"`
	PeerPublicKey      string    `json:"peer_public_key"`
	RelayForward       string    `json:"relay_forward"`
	RelayPort          int       `json:"relay_port"`
	MTU                int       `gorm:"default:1400" json:"mtu"`
	BufferSize         int       `gorm:"default:65535" json:"buffer_size"`
	SessionTimeout     int       `gorm:"default:600" json:"session_timeout"`
	Workers            int       `gorm:"default:4" json:"workers"`
	ReliabilityEnabled bool      `gorm:"default:false" json:"reliability_enabled"`
	FECEnabled         bool      `gorm:"default:false" json:"fec_enabled"`
	LogLevel           string    `gorm:"default:info" json:"log_level"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// Inbound represents a tunnel inbound configuration
type Inbound struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	Type       string    `gorm:"not null" json:"type"` // socks, relay, forward
	Listen     string    `gorm:"not null" json:"listen"`
	Target     string    `json:"target,omitempty"`
	RemotePort int       `json:"remote_port,omitempty"`
	Enabled    bool      `gorm:"default:true" json:"enabled"`
	Remark     string    `json:"remark"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TrafficStat stores traffic snapshots
type TrafficStat struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	BytesSent     int64     `gorm:"default:0" json:"bytes_sent"`
	BytesReceived int64     `gorm:"default:0" json:"bytes_received"`
	RecordedAt    time.Time `gorm:"autoCreateTime" json:"recorded_at"`
}

// Setting stores key-value settings
type Setting struct {
	Key   string `gorm:"primarykey" json:"key"`
	Value string `json:"value"`
}

// InitDB opens the SQLite database and runs migrations
func InitDB(dbPath string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate all models
	if err := db.AutoMigrate(
		&User{},
		&ServerConfig{},
		&Inbound{},
		&TrafficStat{},
		&Setting{},
	); err != nil {
		return nil, err
	}

	// Create default server config if none exists
	var count int64
	db.Model(&ServerConfig{}).Count(&count)
	if count == 0 {
		db.Create(&ServerConfig{
			ID:            1,
			Mode:          "client",
			TransportType: "syn_udp",
			ServerPort:    8080,
			ListenPort:    8080,
			MTU:           1400,
			BufferSize:    65535,
			SessionTimeout: 600,
			Workers:       4,
			LogLevel:      "info",
		})
	}

	return db, nil
}

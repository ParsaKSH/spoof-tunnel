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
	ID            uint      `gorm:"primarykey" json:"id"`
	Mode          string    `gorm:"default:local" json:"mode"`               // "local" or "remote"
	SendTransport string    `gorm:"default:tcp" json:"send_transport"`       // "tcp", "udp", "icmp", "icmpv6"
	RecvTransport string    `gorm:"default:udp" json:"recv_transport"`       // "tcp", "udp", "icmp", "icmpv6"

	// Local mode
	ListenAddr    string    `gorm:"default:127.0.0.1:5000" json:"listen_addr"`
	RemoteAddr    string    `json:"remote_addr"`
	RemotePort    int       `gorm:"default:8090" json:"remote_port"`
	RecvPort      int       `gorm:"default:5001" json:"recv_port"`

	// Remote mode
	ListenPort    int       `gorm:"default:8090" json:"listen_port"`
	ForwardAddr   string    `gorm:"default:127.0.0.1:51820" json:"forward_addr"`
	ClientIP      string    `json:"client_ip"`
	ClientPort    int       `gorm:"default:5001" json:"client_port"`

	// Spoof
	SpoofIP       string    `json:"spoof_ip"`
	SpoofPort     int       `gorm:"default:443" json:"spoof_port"`
	PeerSpoofIP   string    `json:"peer_spoof_ip"`

	UpdatedAt     time.Time `json:"updated_at"`
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
			Mode:          "local",
			SendTransport: "tcp",
			RecvTransport: "udp",
			ListenAddr:    "127.0.0.1:5000",
			RemotePort:    8090,
			RecvPort:      5001,
			ListenPort:    8090,
			ForwardAddr:   "127.0.0.1:51820",
			ClientPort:    5001,
			SpoofPort:     443,
		})
	}

	return db, nil
}

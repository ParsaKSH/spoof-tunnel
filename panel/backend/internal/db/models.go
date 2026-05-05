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

// TunnelInstance represents a single tunnel configuration + runtime
type TunnelInstance struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	Name          string    `gorm:"not null" json:"name"`
	Enabled       bool      `gorm:"default:false" json:"enabled"`
	Mode          string    `gorm:"default:local" json:"mode"`
	SendTransport string    `gorm:"default:tcp" json:"send_transport"`
	RecvTransport string    `gorm:"default:udp" json:"recv_transport"`

	// Local mode
	ListenAddr string `gorm:"default:127.0.0.1:5000" json:"listen_addr"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `gorm:"default:8090" json:"remote_port"`
	RecvPort   int    `gorm:"default:5001" json:"recv_port"`

	// Remote mode
	ListenPort  int    `gorm:"default:8090" json:"listen_port"`
	ForwardAddr string `gorm:"default:127.0.0.1:51820" json:"forward_addr"`
	ClientIP    string `json:"client_ip"`
	ClientPort  int    `gorm:"default:5001" json:"client_port"`

	// Spoof
	SpoofIP     string `json:"spoof_ip"`
	SpoofPort   int    `gorm:"default:443" json:"spoof_port"`
	PeerSpoofIP string `json:"peer_spoof_ip"`
	SpoofIPList string `gorm:"type:text" json:"spoof_ip_list"` // inline IPs, newline-separated

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
		&TunnelInstance{},
		&TrafficStat{},
		&Setting{},
	); err != nil {
		return nil, err
	}

	// Migrate old ServerConfig → TunnelInstance (one-time)
	migrateOldConfig(db)

	return db, nil
}

// migrateOldConfig converts legacy single ServerConfig to TunnelInstance
func migrateOldConfig(database *gorm.DB) {
	// Check if old server_configs table exists
	if !database.Migrator().HasTable("server_configs") {
		return
	}

	// Check if we already migrated
	var count int64
	database.Model(&TunnelInstance{}).Count(&count)
	if count > 0 {
		return
	}

	// Read old config
	type OldConfig struct {
		ID            uint
		Mode          string
		SendTransport string
		RecvTransport string
		ListenAddr    string
		RemoteAddr    string
		RemotePort    int
		RecvPort      int
		ListenPort    int
		ForwardAddr   string
		ClientIP      string
		ClientPort    int
		SpoofIP       string
		SpoofPort     int
		PeerSpoofIP   string
	}

	var old OldConfig
	if err := database.Table("server_configs").First(&old).Error; err != nil {
		return
	}

	// Create TunnelInstance from old config
	instance := TunnelInstance{
		Name:          "Default Tunnel",
		Enabled:       false,
		Mode:          old.Mode,
		SendTransport: old.SendTransport,
		RecvTransport: old.RecvTransport,
		ListenAddr:    old.ListenAddr,
		RemoteAddr:    old.RemoteAddr,
		RemotePort:    old.RemotePort,
		RecvPort:      old.RecvPort,
		ListenPort:    old.ListenPort,
		ForwardAddr:   old.ForwardAddr,
		ClientIP:      old.ClientIP,
		ClientPort:    old.ClientPort,
		SpoofIP:       old.SpoofIP,
		SpoofPort:     old.SpoofPort,
		PeerSpoofIP:   old.PeerSpoofIP,
	}
	database.Create(&instance)
}

package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ParsaKSH/spoof-tunnel/panel/internal/api"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/auth"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/db"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/manager"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

//go:embed all:web
var webFS embed.FS

func main() {
	port := flag.Int("port", 0, "panel port (0 = auto from DB or random)")
	setup := flag.Bool("setup", false, "run initial setup with random credentials")
	setupUser := flag.String("setup-user", "", "setup: admin username")
	setupPass := flag.String("setup-pass", "", "setup: admin password")
	setupPort := flag.Int("setup-port", 0, "setup: panel port")
	flag.Parse()

	// Determine data directory
	dataDir := "/etc/spoof-panel"
	if os.Getenv("SPOOF_DATA_DIR") != "" {
		dataDir = os.Getenv("SPOOF_DATA_DIR")
	}
	os.MkdirAll(dataDir, 0755)

	dbPath := filepath.Join(dataDir, "panel.db")
	log.Printf("Database: %s", dbPath)

	// Init database
	database, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	// Handle setup mode
	if *setup || *setupUser != "" {
		runSetup(database, *setupUser, *setupPass, *setupPort)
		return
	}

	// Determine spoof binary path
	binaryPath := filepath.Join(dataDir, "spoof")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		if p, err := exec.LookPath("spoof"); err == nil {
			binaryPath = p
		}
	}

	// Create tunnel manager
	mgr := manager.NewManager(database, binaryPath, dataDir)

	// Create API server
	srv := api.NewServer(database, mgr)

	// Serve embedded frontend
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embedded web: %v", err)
	}

	// Custom file server that avoids 301 redirect issues
	serveFile := func(c *gin.Context, filePath string) bool {
		f, err := webRoot.Open(filePath)
		if err != nil {
			return false
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil || stat.IsDir() {
			return false
		}

		// Detect content type from extension
		ext := filepath.Ext(filePath)
		contentType := ""
		switch ext {
		case ".html":
			contentType = "text/html; charset=utf-8"
		case ".css":
			contentType = "text/css; charset=utf-8"
		case ".js":
			contentType = "application/javascript; charset=utf-8"
		case ".json":
			contentType = "application/json"
		case ".png":
			contentType = "image/png"
		case ".svg":
			contentType = "image/svg+xml"
		case ".ico":
			contentType = "image/x-icon"
		case ".woff2":
			contentType = "font/woff2"
		case ".woff":
			contentType = "font/woff"
		case ".txt":
			contentType = "text/plain"
		case ".map":
			contentType = "application/json"
		default:
			contentType = "application/octet-stream"
		}

		data, err := io.ReadAll(f)
		if err != nil {
			return false
		}

		c.Data(http.StatusOK, contentType, data)
		return true
	}

	// Serve static files and SPA fallback
	srv.Router().NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		if path != "/" {
			filePath := path[1:] // remove leading /

			// Try exact file
			if serveFile(c, filePath) {
				return
			}

			// Try as directory with index.html
			if serveFile(c, filePath+"/index.html") {
				return
			}

			// Try stripping trailing slash
			cleaned := strings.TrimSuffix(filePath, "/")
			if cleaned != filePath {
				if serveFile(c, cleaned) {
					return
				}
				if serveFile(c, cleaned+"/index.html") {
					return
				}
			}
		}

		// SPA fallback - serve index.html
		serveFile(c, "index.html")
	})

	// Determine port
	listenPort := *port
	if listenPort == 0 {
		var setting db.Setting
		if err := database.Where("key = ?", "panel_port").First(&setting).Error; err == nil {
			fmt.Sscanf(setting.Value, "%d", &listenPort)
		}
	}
	if listenPort == 0 {
		listenPort = auth.GenerateRandomPort()
		database.Create(&db.Setting{Key: "panel_port", Value: fmt.Sprintf("%d", listenPort)})
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		mgr.Stop()
		os.Exit(0)
	}()

	addr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	log.Printf("╔══════════════════════════════════════╗")
	log.Printf("║      Spoof Panel v3.0.0              ║")
	log.Printf("║      http://0.0.0.0:%-17d║", listenPort)
	log.Printf("╚══════════════════════════════════════╝")

	if err := srv.Router().Run(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runSetup(database *gorm.DB, username, password string, port int) {
	if username == "" {
		username = auth.GenerateRandomString(8)
	}
	if password == "" {
		password = auth.GenerateRandomString(12)
	}
	if port == 0 {
		port = auth.GenerateRandomPort()
	}

	hash, _ := auth.HashPassword(password)
	database.Create(&db.User{
		Username:     username,
		PasswordHash: hash,
	})

	database.Create(&db.Setting{Key: "panel_port", Value: fmt.Sprintf("%d", port)})

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║      Spoof Panel — Setup Complete    ║")
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Printf("║  Port:     %-26d║\n", port)
	fmt.Printf("║  Username: %-26s║\n", username)
	fmt.Printf("║  Password: %-26s║\n", password)
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Printf("║  URL: http://YOUR_IP:%-16d║\n", port)
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println()
}

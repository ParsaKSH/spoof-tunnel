package api

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/panel/internal/auth"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// ── Auth Handlers ──

func (s *Server) handleAuthCheck(c *gin.Context) {
	var count int64
	s.db.Model(&db.User{}).Count(&count)
	c.JSON(http.StatusOK, gin.H{"needs_setup": count == 0})
}

func (s *Server) handleSetup(c *gin.Context) {
	var count int64
	s.db.Model(&db.User{}).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "already set up"})
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}

	user := db.User{
		Username:     req.Username,
		PasswordHash: hash,
	}
	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	token, _ := auth.GenerateToken(user.ID, user.Username)
	c.JSON(http.StatusOK, gin.H{"token": token, "username": user.Username})
}

func (s *Server) handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	if err := s.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !auth.CheckPassword(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Update last login
	s.db.Model(&user).Update("last_login", time.Now())

	token, err := auth.GenerateToken(user.ID, user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token, "username": user.Username})
}

func (s *Server) handleMe(c *gin.Context) {
	userID := c.GetUint("user_id")
	var user db.User
	s.db.First(&user, userID)
	c.JSON(http.StatusOK, user)
}

// ── Dashboard ──

func (s *Server) handleDashboard(c *gin.Context) {
	status, errMsg := s.manager.Status()
	uptime := s.manager.Uptime()

	c.JSON(http.StatusOK, gin.H{
		"tunnel_status": status,
		"tunnel_error":  errMsg,
		"uptime":        uptime.Seconds(),
	})
}

func (s *Server) handleSystem(c *gin.Context) {
	hostname, _ := os.Hostname()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.JSON(http.StatusOK, gin.H{
		"hostname":    hostname,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"cpus":        runtime.NumCPU(),
		"goroutines":  runtime.NumGoroutine(),
		"memory_mb":   m.Alloc / 1024 / 1024,
		"go_version":  runtime.Version(),
	})
}

// ── Config Handlers ──

func (s *Server) handleGetConfig(c *gin.Context) {
	var cfg db.ServerConfig
	s.db.First(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func (s *Server) handleUpdateConfig(c *gin.Context) {
	var cfg db.ServerConfig
	s.db.First(&cfg)

	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg.ID = 1
	s.db.Save(&cfg)
	c.JSON(http.StatusOK, cfg)
}

// ── Tunnel Control ──

func (s *Server) handleTunnelStart(c *gin.Context) {
	if err := s.manager.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "started"})
}

func (s *Server) handleTunnelStop(c *gin.Context) {
	if err := s.manager.Stop(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

func (s *Server) handleTunnelRestart(c *gin.Context) {
	if err := s.manager.Restart(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "restarted"})
}

func (s *Server) handleTunnelStatus(c *gin.Context) {
	status, errMsg := s.manager.Status()
	c.JSON(http.StatusOK, gin.H{
		"status": status,
		"error":  errMsg,
		"uptime": s.manager.Uptime().Seconds(),
	})
}

// WebSocket log streaming
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) handleTunnelLogs(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send existing logs
	for _, line := range s.manager.GetLogs(100) {
		conn.WriteMessage(websocket.TextMessage, []byte(line))
	}

	// Stream new logs
	logCh := s.manager.LogChannel()
	for {
		select {
		case line, ok := <-logCh:
			if !ok {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				return
			}
		}
	}
}

// ── Settings ──

func (s *Server) handleChangePassword(c *gin.Context) {
	userID := c.GetUint("user_id")
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	s.db.First(&user, userID)

	if !auth.CheckPassword(req.OldPassword, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong password"})
		return
	}

	hash, _ := auth.HashPassword(req.NewPassword)
	s.db.Model(&user).Update("password_hash", hash)

	// Generate new token
	token, _ := auth.GenerateToken(user.ID, user.Username)
	c.JSON(http.StatusOK, gin.H{"ok": true, "token": token})
}

// ── Helpers ──

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

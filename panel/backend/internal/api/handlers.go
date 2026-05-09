package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/internal/tester"
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
	var instances []db.TunnelInstance
	s.db.Find(&instances)

	type instanceInfo struct {
		ID     uint   `json:"id"`
		Name   string `json:"name"`
		Mode   string `json:"mode"`
		Status string `json:"status"`
		Uptime float64 `json:"uptime"`
		Error  string `json:"error,omitempty"`
	}

	var items []instanceInfo
	var running, stopped, errored int

	for _, inst := range instances {
		status, errMsg := s.manager.InstanceStatus(inst.ID)
		uptime := s.manager.InstanceUptime(inst.ID)
		items = append(items, instanceInfo{
			ID:     inst.ID,
			Name:   inst.Name,
			Mode:   inst.Mode,
			Status: string(status),
			Uptime: uptime.Seconds(),
			Error:  errMsg,
		})
		switch status {
		case "running":
			running++
		case "error":
			errored++
		default:
			stopped++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"instances":     items,
		"total":         len(instances),
		"running_count": running,
		"stopped_count": stopped,
		"error_count":   errored,
	})
}

func (s *Server) handleSystem(c *gin.Context) {
	hostname, _ := os.Hostname()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.JSON(http.StatusOK, gin.H{
		"hostname":   hostname,
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       runtime.NumCPU(),
		"goroutines": runtime.NumGoroutine(),
		"memory_mb":  m.Alloc / 1024 / 1024,
		"go_version": runtime.Version(),
	})
}

// ── Instance CRUD ──

func (s *Server) handleListInstances(c *gin.Context) {
	var instances []db.TunnelInstance
	s.db.Order("id asc").Find(&instances)

	type instanceWithStatus struct {
		db.TunnelInstance
		Status string  `json:"status"`
		Uptime float64 `json:"uptime"`
		Error  string  `json:"status_error,omitempty"`
	}

	var result []instanceWithStatus
	for _, inst := range instances {
		status, errMsg := s.manager.InstanceStatus(inst.ID)
		uptime := s.manager.InstanceUptime(inst.ID)
		result = append(result, instanceWithStatus{
			TunnelInstance: inst,
			Status:        string(status),
			Uptime:        uptime.Seconds(),
			Error:         errMsg,
		})
	}

	if result == nil {
		result = []instanceWithStatus{}
	}

	c.JSON(http.StatusOK, result)
}

func (s *Server) handleCreateInstance(c *gin.Context) {
	var inst db.TunnelInstance
	if err := c.ShouldBindJSON(&inst); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if inst.Name == "" {
		inst.Name = "Tunnel"
	}
	if inst.Mode == "" {
		inst.Mode = "local"
	}
	if inst.SendTransport == "" {
		inst.SendTransport = "tcp"
	}
	if inst.RecvTransport == "" {
		inst.RecvTransport = "udp"
	}
	if inst.SpoofPort == 0 {
		inst.SpoofPort = 443
	}
	if inst.ListenAddr == "" {
		inst.ListenAddr = "127.0.0.1:5000"
	}
	if inst.RemotePort == 0 {
		inst.RemotePort = 8090
	}
	if inst.RecvPort == 0 {
		inst.RecvPort = 5001
	}
	if inst.ListenPort == 0 {
		inst.ListenPort = 8090
	}
	if inst.ForwardAddr == "" {
		inst.ForwardAddr = "127.0.0.1:51820"
	}
	if inst.ClientPort == 0 {
		inst.ClientPort = 5001
	}

	inst.ID = 0 // auto-increment
	if err := s.db.Create(&inst).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, inst)
}

func (s *Server) handleGetInstance(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}

	var inst db.TunnelInstance
	if err := s.db.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
		return
	}

	status, errMsg := s.manager.InstanceStatus(id)
	uptime := s.manager.InstanceUptime(id)

	c.JSON(http.StatusOK, gin.H{
		"instance": inst,
		"status":   string(status),
		"uptime":   uptime.Seconds(),
		"error":    errMsg,
	})
}

func (s *Server) handleUpdateInstance(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}

	var existing db.TunnelInstance
	if err := s.db.First(&existing, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
		return
	}

	if err := c.ShouldBindJSON(&existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing.ID = id
	s.db.Save(&existing)
	c.JSON(http.StatusOK, existing)
}

func (s *Server) handleDeleteInstance(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}

	// Stop if running
	s.manager.RemoveInstance(id)

	if err := s.db.Delete(&db.TunnelInstance{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Instance Control ──

func (s *Server) handleInstanceStart(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}
	if err := s.manager.StartInstance(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "started"})
}

func (s *Server) handleInstanceStop(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}
	if err := s.manager.StopInstance(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

func (s *Server) handleInstanceRestart(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}
	if err := s.manager.RestartInstance(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "restarted"})
}

func (s *Server) handleInstanceStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}
	status, errMsg := s.manager.InstanceStatus(id)
	c.JSON(http.StatusOK, gin.H{
		"status": string(status),
		"error":  errMsg,
		"uptime": s.manager.InstanceUptime(id).Seconds(),
	})
}

// WebSocket log streaming per instance
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) handleInstanceLogs(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send existing logs
	for _, line := range s.manager.InstanceLogs(id, 100) {
		conn.WriteMessage(websocket.TextMessage, []byte(line))
	}

	// Subscribe for new logs
	subID, logCh := s.manager.SubscribeLogs(id)
	defer s.manager.UnsubscribeLogs(id, subID)

	// Detect client disconnect via a read goroutine
	done := make(chan struct{})
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				close(done)
				return
			}
		}
	}()

	// Stream new logs
	for {
		select {
		case line, ok := <-logCh:
			if !ok {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

// ── Instance Spoof IPs ──

func (s *Server) handleGetInstanceSpoofIPs(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}

	var inst db.TunnelInstance
	if err := s.db.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
		return
	}

	content := strings.TrimSpace(inst.SpoofIPList)
	count := 0
	if content != "" {
		count = len(strings.Split(content, "\n"))
	}

	c.JSON(http.StatusOK, gin.H{"content": content, "count": count})
}

func (s *Server) handleSetInstanceSpoofIPs(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		return
	}

	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	content := strings.TrimSpace(req.Content)
	if err := s.db.Model(&db.TunnelInstance{}).Where("id = ?", id).Update("spoof_ip_list", content).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	count := 0
	if content != "" {
		count = len(strings.Split(content, "\n"))
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "count": count})
}

// ── Tester Handlers ──

func (s *Server) handleTesterStart(c *gin.Context) {
	var req struct {
		Mode          string  `json:"mode" binding:"required"`
		Protocol      string  `json:"protocol" binding:"required"`
		IPList        string  `json:"ip_list" binding:"required"`
		DstIP         string  `json:"dst_ip"`
		DstPort       int     `json:"dst_port"`
		Timeout       int     `json:"timeout"`
		PacketCount   int     `json:"packet_count"`
		MaxPacketLoss float64 `json:"max_packet_loss"`
		Concurrency   int     `json:"concurrency"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ranges, err := tester.ParseIPRangesFromString(req.IPList)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP list: " + err.Error()})
		return
	}

	if ranges.Total() == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP list is empty"})
		return
	}

	cfg := tester.TesterConfig{
		Mode:          req.Mode,
		Protocol:      req.Protocol,
		DstIP:         req.DstIP,
		DstPort:       req.DstPort,
		Timeout:       req.Timeout,
		PacketCount:   req.PacketCount,
		MaxPacketLoss: req.MaxPacketLoss,
		Concurrency:   req.Concurrency,
	}

	switch req.Mode {
	case "sender":
		if err := s.tester.RunSender(cfg, ranges); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	case "receiver":
		if err := s.tester.RunReceiver(cfg, ranges); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'sender' or 'receiver'"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "started", "ip_count": ranges.Total()})
}

func (s *Server) handleTesterStatus(c *gin.Context) {
	state := s.tester.State()
	// Load results: live during running receiver, from disk when done
	if state.Status == "done" || (state.Status == "running" && state.Mode == "receiver") {
		results, err := s.tester.Results()
		if err == nil {
			state.Results = results
		}
	}
	c.JSON(http.StatusOK, state)
}

func (s *Server) handleTesterStop(c *gin.Context) {
	s.tester.Stop()
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

func (s *Server) handleTesterResults(c *gin.Context) {
	state := s.tester.State()
	results, _ := s.tester.Results()
	c.JSON(http.StatusOK, gin.H{
		"status":  state.Status,
		"results": results,
	})
}

func (s *Server) handleTesterDownload(c *gin.Context) {
	passedIPs, err := s.tester.PassedIPs()
	if err != nil || len(passedIPs) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no results"})
		return
	}

	content := strings.Join(passedIPs, "\n") + "\n"
	c.Header("Content-Disposition", "attachment; filename=spoof-ips.txt")
	c.Data(http.StatusOK, "text/plain", []byte(content))
}

func (s *Server) handleTesterUpload(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read file: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"content": string(data)})
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

func parseID(c *gin.Context) (uint, error) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, err
	}
	return uint(id), nil
}

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

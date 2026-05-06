package api

import (
	"net/http"
	"strings"

	"github.com/ParsaKSH/spoof-tunnel/internal/tester"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/auth"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/manager"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Server is the API server
type Server struct {
	db      *gorm.DB
	manager *manager.Manager
	tester  *tester.Runner
	router  *gin.Engine
	webPath string
}

// NewServer creates a new API server
func NewServer(database *gorm.DB, mgr *manager.Manager, webPath string) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// CORS
	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	s := &Server{
		db:      database,
		manager: mgr,
		tester:  tester.NewRunner(),
		router:  r,
		webPath: webPath,
	}

	s.setupRoutes()
	return s
}

// Router returns the gin router
func (s *Server) Router() *gin.Engine {
	return s.router
}

// WebPath returns the configured web path
func (s *Server) WebPath() string {
	return s.webPath
}

func (s *Server) setupRoutes() {
	api := s.router.Group(s.webPath + "/api")
	{
		// Auth (no middleware)
		api.POST("/auth/login", s.handleLogin)
		api.POST("/auth/setup", s.handleSetup)
		api.GET("/auth/check", s.handleAuthCheck)

		// Protected routes
		protected := api.Group("")
		protected.Use(s.authMiddleware())
		{
			protected.GET("/auth/me", s.handleMe)

			// Dashboard
			protected.GET("/dashboard", s.handleDashboard)
			protected.GET("/system", s.handleSystem)

			// Tunnel Instances CRUD
			protected.GET("/instances", s.handleListInstances)
			protected.POST("/instances", s.handleCreateInstance)
			protected.GET("/instances/:id", s.handleGetInstance)
			protected.PUT("/instances/:id", s.handleUpdateInstance)
			protected.DELETE("/instances/:id", s.handleDeleteInstance)

			// Tunnel Instance Control
			protected.POST("/instances/:id/start", s.handleInstanceStart)
			protected.POST("/instances/:id/stop", s.handleInstanceStop)
			protected.POST("/instances/:id/restart", s.handleInstanceRestart)
			protected.GET("/instances/:id/status", s.handleInstanceStatus)
			protected.GET("/instances/:id/logs", s.handleInstanceLogs)

			// Instance Spoof IPs
			protected.GET("/instances/:id/spoof-ips", s.handleGetInstanceSpoofIPs)
			protected.PUT("/instances/:id/spoof-ips", s.handleSetInstanceSpoofIPs)

			// Tester
			protected.POST("/tester/start", s.handleTesterStart)
			protected.GET("/tester/status", s.handleTesterStatus)
			protected.POST("/tester/stop", s.handleTesterStop)
			protected.GET("/tester/results", s.handleTesterResults)
			protected.GET("/tester/download", s.handleTesterDownload)
			protected.POST("/tester/upload", s.handleTesterUpload)

			// Settings
			protected.PUT("/settings/password", s.handleChangePassword)
		}
	}
}

// authMiddleware validates JWT tokens
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string

		// Check Authorization header first
		header := c.GetHeader("Authorization")
		if header != "" {
			tokenStr = strings.TrimPrefix(header, "Bearer ")
		} else {
			// Fallback to query param (used by WebSocket)
			tokenStr = c.Query("token")
		}

		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no token"})
			return
		}

		claims, err := auth.ValidateToken(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}

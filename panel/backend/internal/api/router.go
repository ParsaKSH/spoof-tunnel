package api

import (
	"net/http"
	"strings"

	"github.com/ParsaKSH/spooftunnel/panel/internal/auth"
	"github.com/ParsaKSH/spooftunnel/panel/internal/manager"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Server is the API server
type Server struct {
	db      *gorm.DB
	manager *manager.Manager
	router  *gin.Engine
}

// NewServer creates a new API server
func NewServer(database *gorm.DB, mgr *manager.Manager) *Server {
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
		router:  r,
	}

	s.setupRoutes()
	return s
}

// Router returns the gin router
func (s *Server) Router() *gin.Engine {
	return s.router
}

func (s *Server) setupRoutes() {
	api := s.router.Group("/api")
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

			// Inbounds
			protected.GET("/inbounds", s.handleListInbounds)
			protected.POST("/inbounds", s.handleCreateInbound)
			protected.PUT("/inbounds/:id", s.handleUpdateInbound)
			protected.DELETE("/inbounds/:id", s.handleDeleteInbound)

			// Config
			protected.GET("/config", s.handleGetConfig)
			protected.PUT("/config", s.handleUpdateConfig)

			// Tunnel control
			protected.POST("/tunnel/start", s.handleTunnelStart)
			protected.POST("/tunnel/stop", s.handleTunnelStop)
			protected.POST("/tunnel/restart", s.handleTunnelRestart)
			protected.GET("/tunnel/status", s.handleTunnelStatus)
			protected.GET("/tunnel/logs", s.handleTunnelLogs)

			// Settings
			protected.PUT("/settings/password", s.handleChangePassword)
		}
	}
}

// authMiddleware validates JWT tokens
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no token"})
			return
		}

		tokenStr := strings.TrimPrefix(header, "Bearer ")
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

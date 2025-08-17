package http

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"time"
)

func NewRouter(h *Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(RequestID())
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/healthz", h.Healthz)

	rl := RateLimit(LimiterDeps{R: h.Redis, Limit: h.RateLimitPerMin, Window: time.Minute})

	api := r.Group("/api/auth")
	{
		api.POST("/register", rl, h.Register)
		api.POST("/login", rl, h.Login)
		api.POST("/refresh", h.Refresh)
		api.POST("/logout", h.Logout)
		api.GET("/me", AuthJWT(h.JWTSecret), h.Me)
	}

	return r
}

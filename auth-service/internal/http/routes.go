package http

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"time"
)

func NewRouter(h *Handler) *gin.Engine {
	r := gin.New()

	r.Use(gin.Recovery(), RequestID(), Prometheus())
	r.Use(AccessLog())
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/healthz", h.Healthz)
	r.GET("/.well-known/jwks.json", h.JWKS) // <-- JWKS

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	rl := RateLimit(&LimiterDeps{R: h.Redis, Limit: h.RateLimitPerMin, Window: time.Minute})

	api := r.Group("/api/auth")
	{
		api.GET("/google/login", h.GoogleLogin)
		api.GET("/google/callback", h.GoogleCallback)

		api.POST("/register", rl, h.Register)
		api.GET("/verify", h.VerifyEmail)
		api.POST("/login", rl, h.Login)
		api.POST("/refresh", h.Refresh)
		api.POST("/logout", h.Logout)
		api.POST("/forgot-password", h.ForgotPassword)
		api.POST("/reset-password", h.ResetPassword)
		api.GET("/me", AuthJWT(h.Keys), h.Me)
	}

	return r
}

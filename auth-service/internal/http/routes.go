package http

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	gintrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gin-gonic/gin"
	"time"
)

func NewRouter(h *Handler) *gin.Engine {
	r := gin.New()
	r.Use(gintrace.Middleware("auth-service"))

	r.Use(gin.Recovery(), RequestID(), Prometheus())
	r.Use(AccessLog())
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/healthz", h.Healthz)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

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

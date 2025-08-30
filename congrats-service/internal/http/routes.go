package http

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/tazhibayda/congrats-service/internal/security"
	"net/http"
	"time"
)

func NewRouter(h *Handler, jwks *security.Fetcher) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	rl := NewRateLimiter(10, time.Minute)

	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api := r.Group("/api/congrats")
	{
		api.POST("/threads", AuthJWT(jwks), h.CreateThread)                      // создать ссылку
		api.POST("/threads/:slug/submit", RateLimitSubmit(rl), h.SubmitGreeting) // публичный submit
		api.GET("/threads/:slug/view", AuthJWT(jwks), h.ViewGreetings)           // владелец смотрит
	}
	return r
}

package http

import "github.com/gin-gonic/gin"

func NewRouter(h *Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(RequestID())

	r.GET("/healthz", h.Healthz)

	// базовые заглушки на будущее (пока НЕ реализуем)
	// r.POST("/api/auth/register", h.Register)
	// r.POST("/api/auth/login", h.Login)

	return r
}

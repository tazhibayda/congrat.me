package http

import "github.com/gin-gonic/gin"

func NewRouter(h *Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(RequestID())

	r.GET("/healthz", h.Healthz)

	api := r.Group("/api/auth")
	{
		api.POST("/register", h.Register)
		api.POST("/login", h.Login)
		api.POST("/refresh", h.Refresh)
		api.POST("/logout", h.Logout)
		api.GET("/me", AuthJWT(h.JWTSecret), h.Me)
	}

	return r
}

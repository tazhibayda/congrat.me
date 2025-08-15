package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/auth-service/internal/repo"
)

type Handler struct {
	Store *repo.Store
}

func NewHandler(store *repo.Store) *Handler { return &Handler{Store: store} }

func (h *Handler) Healthz(c *gin.Context) {
	if err := h.Store.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "degraded", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

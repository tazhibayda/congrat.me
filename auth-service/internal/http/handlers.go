package http

import (
	"github.com/tazhibayda/auth-service/internal/domain"
	"github.com/tazhibayda/auth-service/internal/security"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/auth-service/internal/repo"
)

type Handler struct {
	Store           *repo.Store
	JWTSecret       string
	RefreshTTL      time.Duration
	Redis           *repo.Redis
	RateLimitPerMin int
}

func NewHandler(store *repo.Store, jwtSecret string, refreshDays int, rds *repo.Redis, rlPerMin int) *Handler {
	return &Handler{
		Store:           store,
		JWTSecret:       jwtSecret,
		RefreshTTL:      time.Duration(refreshDays) * 24 * time.Hour,
		Redis:           rds,
		RateLimitPerMin: rlPerMin,
	}
}

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (h *Handler) Register(c *gin.Context) {
	var in registerReq
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !strings.Contains(email, "@") || len(in.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email or weak password"})
		return
	}
	if u, _ := h.Store.FindUserByEmail(c.Request.Context(), email); u != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}
	hash, err := security.HashPassword(in.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}
	u := &domain.User{Email: email, PasswordHash: hash, Name: strings.TrimSpace(in.Name)}
	if err := h.Store.CreateUser(c.Request.Context(), u); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}
	c.Status(http.StatusCreated)
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type loginResp struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func (h *Handler) Login(c *gin.Context) {
	var in loginReq
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	u, err := h.Store.FindUserByEmail(c.Request.Context(), email)
	if err != nil || u == nil || !security.CheckPassword(u.PasswordHash, in.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	tok, err := security.MakeAccess(h.JWTSecret, u.ID.String(), u.Email, 15*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}

	ref, err := security.NewRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh gen"})
		return
	}
	if err := h.Store.SaveRefresh(c.Request.Context(), u.ID, ref, h.RefreshTTL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh save"})
		return
	}
	c.JSON(http.StatusOK, loginResp{Access: tok, Refresh: ref})
}

type refreshReq struct {
	Refresh string `json:"refresh"`
}

func (h *Handler) Refresh(c *gin.Context) {
	var in refreshReq
	if err := c.ShouldBindJSON(&in); err != nil || in.Refresh == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	rt, err := h.Store.FindValidRefresh(c.Request.Context(), in.Refresh)
	if err != nil || rt == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh"})
		return
	}
	// выдаём новый access; (ротацию refresh можно добавить позже)
	// найдём пользователя (по rt.UserID удобней иметь метод FindUserByID; на первое время можно хранить email в токене refresh, но оставим по userID):
	u, err := h.Store.FindUserByID(c.Request.Context(), rt.UserID)
	if err != nil || u == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	tok, err := security.MakeAccess(h.JWTSecret, u.ID.String(), u.Email, 15*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}

	// (опционально) ротация: сгенерировать новый refresh, сохранить и вернуть его вместо старого (и пометить старый как revoked)
	c.JSON(http.StatusOK, gin.H{"access": tok})
}

type logoutReq struct {
	Refresh string `json:"refresh"`
}

func (h *Handler) Logout(c *gin.Context) {
	var in logoutReq
	if err := c.ShouldBindJSON(&in); err != nil || in.Refresh == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if err := h.Store.RevokeRefresh(c.Request.Context(), in.Refresh); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke failed"})
		return
	}
	c.Status(http.StatusNoContent)
}

// Me returns the authenticated user's details
func (h *Handler) Me(c *gin.Context) {
	au, _ := c.Get(authUserKey)
	userCtx := au.(AuthUser)

	u, err := h.Store.FindUserByEmail(c.Request.Context(), userCtx.Email)
	if err != nil || u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": u.ID, "email": u.Email, "name": u.Name, "created_at": u.CreatedAt,
	})
}

func (h *Handler) Healthz(c *gin.Context) {
	if err := h.Store.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "degraded", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

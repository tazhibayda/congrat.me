package http

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/auth-service/internal/domain"
	"github.com/tazhibayda/auth-service/internal/helper"
	"github.com/tazhibayda/auth-service/internal/queue"
	"github.com/tazhibayda/auth-service/internal/repo"
	"github.com/tazhibayda/auth-service/internal/security"
	"go.uber.org/zap"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"net/http"
	"strings"

	"time"
)

type Handler struct {
	Store           *repo.Store
	JWTSecret       string
	RefreshTTL      time.Duration
	Redis           *repo.Redis
	RateLimitPerMin int
	Events          *queue.Publisher
}

func NewHandler(store *repo.Store, jwtSecret string, refreshDays int, rds *repo.Redis, rlPerMin int, pub *queue.Publisher) *Handler {
	return &Handler{
		Store:           store,
		JWTSecret:       jwtSecret,
		RefreshTTL:      time.Duration(refreshDays) * 24 * time.Hour,
		Redis:           rds,
		RateLimitPerMin: rlPerMin,
		Events:          pub,
	}
}

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// Register godoc
// @Summary Register user
// @Tags auth
// @Accept json
// @Produce json
// @Param payload body registerReq true "register"
// @Success 201
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.register")
	defer span.Finish()
	vSpan, _ := tracer.StartSpanFromContext(ctx, "auth.register.validate")
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
	vSpan.Finish()
	fSpan, _ := tracer.StartSpanFromContext(ctx, "auth.register.find_user")
	fSpan.Finish()
	if u, _ := h.Store.FindUserByEmail(c.Request.Context(), email); u != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}

	hSpan, _ := tracer.StartSpanFromContext(ctx, "auth.register.hash_password")
	hash, err := security.HashPassword(in.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}
	hSpan.Finish()

	iSpan, _ := tracer.StartSpanFromContext(ctx, "auth.register.insert_user")
	u := &domain.User{Email: email, PasswordHash: hash, Name: strings.TrimSpace(in.Name)}
	if err := h.Store.CreateUser(c.Request.Context(), u); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}
	iSpan.Finish()

	rid := c.GetString("X-Request-ID")
	go func(parent tracer.Span) {
		pubSpan := tracer.StartSpan("auth.register.publish", tracer.ChildOf(parent.Context()))
		_ = h.Events.Publish(context.Background(), "auth.events", "user.registered",
			queue.UserRegistered{UserID: u.ID, Email: u.Email, Name: u.Name}, rid)
		pubSpan.Finish()
	}(span)

	Logger(c).Info("user_registered", zap.String("email_hash", helper.Hash8(u.Email)))
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

// Login godoc
// @Summary Login
// @Tags auth
// @Accept json
// @Produce json
// @Param payload body loginReq true "login"
// @Success 200 {object} loginResp
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.login")
	defer span.Finish()
	span.SetTag("route", "/api/auth/login")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	var in loginReq
	if err := c.ShouldBindJSON(&in); err != nil {
		span.SetTag("error", "invalid json")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	u, err := h.Store.FindUserByEmail(c.Request.Context(), email)
	if err != nil || u == nil || !security.CheckPassword(u.PasswordHash, in.Password) {
		span.SetTag("error", "invalid credentials")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	accSpan, _ := tracer.StartSpanFromContext(ctx, "auth.login.issue_access")
	tok, err := security.MakeAccess(h.JWTSecret, u.ID.String(), u.Email, 15*time.Minute)
	if err != nil {
		accSpan.SetTag("error", err)
		accSpan.Finish()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	accSpan.Finish()

	refSpan, _ := tracer.StartSpanFromContext(ctx, "auth.login.issue_refresh")
	ref, err := security.NewRefreshToken()
	if err != nil {
		refSpan.SetTag("error", err)
		refSpan.Finish()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh gen"})
		return
	}
	refSpan.Finish()

	saveSpan, _ := tracer.StartSpanFromContext(ctx, "auth.login.save_refresh")
	if err := h.Store.SaveRefresh(c.Request.Context(), u.ID, ref, h.RefreshTTL); err != nil {
		saveSpan.SetTag("error", err)
		saveSpan.Finish()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh save"})
		return
	}
	saveSpan.Finish()

	if h.Events != nil {
		rid := c.GetString("X-Request-ID")
		parent := span // для связи в трейсе
		go func() {
			pubSpan := tracer.StartSpan("auth.login.publish", tracer.ChildOf(parent.Context()))
			_ = h.Events.Publish(context.Background(), "auth.events", "user.loggedin",
				queue.UserLoggedIn{UserID: u.ID, Email: u.Email}, rid)
			pubSpan.Finish()
		}()
	}

	span.SetTag("user_id", u.ID)
	c.JSON(http.StatusOK, loginResp{Access: tok, Refresh: ref})
}

type refreshReq struct {
	Refresh string `json:"refresh"`
}

func (h *Handler) Refresh(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.refresh")
	defer span.Finish()
	span.SetTag("route", "/api/auth/refresh")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	refSpan, _ := tracer.StartSpanFromContext(ctx, "auth.refresh.request")
	var in refreshReq
	if err := c.ShouldBindJSON(&in); err != nil || in.Refresh == "" {
		refSpan.SetTag("error", "invalid json")
		refSpan.Finish()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	refSpan.Finish()

	valSpan, _ := tracer.StartSpanFromContext(ctx, "auth.refresh.validate")
	rt, err := h.Store.FindValidRefresh(c.Request.Context(), in.Refresh)
	if err != nil || rt == nil {
		valSpan.SetTag("error", "invalid refresh")
		valSpan.Finish()
		span.SetTag("error", "invalid refresh")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh"})
		return
	}
	valSpan.Finish()
	// выдаём новый access; (ротацию refresh можно добавить позже)
	// найдём пользователя (по rt.UserID удобней иметь метод FindUserByID; на первое время можно хранить email в токене refresh, но оставим по userID):
	uSpan, _ := tracer.StartSpanFromContext(ctx, "auth.refresh.find_user")
	u, err := h.Store.FindUserByID(c.Request.Context(), rt.UserID)
	if err != nil || u == nil {
		uSpan.SetTag("error", "user not found")
		uSpan.Finish()
		span.SetTag("error", "user not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	uSpan.Finish()

	aSpan, _ := tracer.StartSpanFromContext(ctx, "auth.refresh.issue_access")
	tok, err := security.MakeAccess(h.JWTSecret, u.ID.String(), u.Email, 15*time.Minute)
	if err != nil {
		aSpan.SetTag("error", err)
		aSpan.Finish()
		span.SetTag("error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	aSpan.Finish()

	// (опционально) ротация: сгенерировать новый refresh, сохранить и вернуть его вместо старого (и пометить старый как revoked)
	span.SetTag("user_id", u.ID)
	c.JSON(http.StatusOK, gin.H{"access": tok})
}

type logoutReq struct {
	Refresh string `json:"refresh"`
}

func (h *Handler) Logout(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.logout")
	defer span.Finish()
	span.SetTag("route", "/api/auth/logout")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	logoutSpan, _ := tracer.StartSpanFromContext(ctx, "auth.logout.request")
	var in logoutReq
	if err := c.ShouldBindJSON(&in); err != nil || in.Refresh == "" {
		logoutSpan.SetTag("error", "invalid json")
		logoutSpan.Finish()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	logoutSpan.Finish()

	rSpan, _ := tracer.StartSpanFromContext(ctx, "auth.logout.validate")
	if err := h.Store.RevokeRefresh(c.Request.Context(), in.Refresh); err != nil {
		rSpan.SetTag("error", err)
		rSpan.Finish()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke failed"})
		return
	}
	rSpan.Finish()

	span.SetTag("user", "logout")
	c.Status(http.StatusNoContent)
}

// Me godoc
// @Summary Current user
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]any
// @Failure 401 {object} map[string]string
// @Router /api/auth/me [get]
func (h *Handler) Me(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.me")
	defer span.Finish()
	span.SetTag("route", "/api/auth/me")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	au, _ := c.Get(authUserKey)
	userCtx := au.(AuthUser)
	span.SetTag("user_id", userCtx.UID)

	uSpan, _ := tracer.StartSpanFromContext(ctx, "auth.me.find_user")
	u, err := h.Store.FindUserByEmail(c.Request.Context(), userCtx.Email)
	if err != nil || u == nil {
		uSpan.SetTag("error", "user not found")
		uSpan.Finish()
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	uSpan.Finish()

	span.SetTag("user", u.Email)
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

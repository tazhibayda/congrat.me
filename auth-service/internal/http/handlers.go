package http

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/auth-service/internal/domain"
	"github.com/tazhibayda/auth-service/internal/helper"
	"github.com/tazhibayda/auth-service/internal/oauth"
	"github.com/tazhibayda/auth-service/internal/queue"
	"github.com/tazhibayda/auth-service/internal/repo"
	"github.com/tazhibayda/auth-service/internal/security"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/zap"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"net/http"
	"strings"

	"time"
)

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}
type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type loginResp struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}
type refreshReq struct {
	Refresh string `json:"refresh"`
}
type logoutReq struct {
	Refresh string `json:"refresh"`
}
type forgotReq struct {
	Email string `json:"email"`
}
type resetReq struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type Handler struct {
	Store                    *repo.Store
	JWTSecret                string
	RefreshTTL               time.Duration
	Redis                    *repo.Redis
	RateLimitPerMin          int
	Events                   queue.Publisher
	Google                   *oauth.GoogleOAuth
	GoogleClientIDFromConfig string
	Keys                     *security.KeyManager
}

func NewHandler(store *repo.Store, jwtSecret string, refreshDays int, rds *repo.Redis, rlPerMin int, pub queue.Publisher, keys *security.KeyManager) *Handler {
	return &Handler{
		Store:           store,
		JWTSecret:       jwtSecret,
		RefreshTTL:      time.Duration(refreshDays) * 24 * time.Hour,
		Redis:           rds,
		RateLimitPerMin: rlPerMin,
		Events:          pub,
		Keys:            keys,
	}
}

func (h *Handler) SetGoogleClientID(clientID string) {
	// устанавливаем clientID для Google OAuth
	h.GoogleClientIDFromConfig = clientID
}

//// Auth (local)

// Register godoc
// @Summary     Register user (local)
// @Tags        auth
// @Accept      json
// @Produce     json
// @Param       payload body     registerReq true "register payload"
// @Success     201     {object} map[string]any "dev: verify_token_dev (only in dev)"
// @Failure     400     {object} map[string]any
// @Failure     409     {object} map[string]any "email already exists"
// @Router      /api/auth/register [post]
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
	u := &domain.User{Email: email, PasswordHash: hash, Name: strings.TrimSpace(in.Name), Provider: "local", Verified: false}
	if err := h.Store.CreateUser(c.Request.Context(), u); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}
	iSpan.Finish()

	rid := c.GetString("X-Request-ID")
	pub := h.Events
	go func(parent tracer.Span) {
		pubSpan := tracer.StartSpan("auth.register.publish", tracer.ChildOf(parent.Context()))
		_ = pub.Publish(context.Background(), "auth.events", "user.registered",
			queue.UserRegistered{UserID: u.ID, Email: u.Email, Name: u.Name}, rid)
		pubSpan.Finish()
	}(span)

	Logger(c).Info("user_registered", zap.String("email_hash", helper.Hash8(u.Email)))
	vt, _ := security.NewOpaqueToken()
	_ = h.Store.CreateEmailToken(c.Request.Context(), repo.EmailToken{
		UserID: u.ID, Token: vt, Purpose: "verify", ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	})

	// (опц.) Паблишим событие в RabbitMQ для notify-service

	go pub.Publish(c.Request.Context(), "auth.events", "email.verify.requested",
		map[string]any{"user_id": u.ID, "email": u.Email, "token": vt}, rid)

	Logger(c).Info("email_verify_token_issued_dev",
		zap.String("user_id", u.ID.String()),
		zap.String("email_hash", helper.Hash8(u.Email)),
	)
	c.JSON(http.StatusCreated, gin.H{"verify_token_dev": vt})
	return
}

// Login godoc
// @Summary     Login (local)
// @Tags        auth
// @Accept      json
// @Produce     json
// @Param       payload body     loginReq true "login payload"
// @Success     200     {object} loginResp
// @Failure     400     {object} map[string]any
// @Failure     401     {object} map[string]any
// @Router      /api/auth/login [post]
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
	tok, err := security.MakeAccessRS256(h.Keys, u.ID.String(), u.Email, 15*time.Minute)
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

	familyID, _ := security.NewID()
	jti, _ := security.NewID()

	saveSpan, _ := tracer.StartSpanFromContext(ctx, "auth.login.save_refresh")

	if err := h.Store.SaveRefresh(c.Request.Context(), repo.RefreshToken{
		UserID:    u.ID,
		TokenHash: repo.HashToken(ref),
		FamilyID:  familyID,
		ParentJTI: "",
		JTI:       jti,
		ExpiresAt: time.Now().Add(h.RefreshTTL).UTC(),
		Revoked:   false,
		UA:        c.Request.UserAgent(),
		IP:        c.ClientIP(),
	}); err != nil {
		saveSpan.SetTag("error", err)
		saveSpan.Finish()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh save"})
		return
	}
	saveSpan.Finish()

	rid := c.GetString("X-Request-ID")
	parent := span // для связи в трейсе
	pub := h.Events
	go func() {
		pubSpan := tracer.StartSpan("auth.login.publish", tracer.ChildOf(parent.Context()))
		_ = pub.Publish(context.Background(), "auth.events", "user.loggedin",
			queue.UserLoggedIn{UserID: u.ID, Email: u.Email}, rid)
		pubSpan.Finish()
	}()

	span.SetTag("user_id", u.ID)
	c.JSON(http.StatusOK, loginResp{Access: tok, Refresh: ref})
}

// Refresh godoc
// @Summary     Rotate refresh & issue new access
// @Description Always rotates refresh token (rotation & reuse detection).
// @Tags        auth
// @Accept      json
// @Produce     json
// @Param       payload body     refreshReq true "refresh payload"
// @Success     200     {object} map[string]string "access, refresh"
// @Failure     400     {object} map[string]any
// @Failure     401     {object} map[string]any "invalid or reused refresh"
// @Router      /api/auth/refresh [post]
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
	rt, err := h.Store.FindByPlain(c.Request.Context(), in.Refresh)
	if err != nil || rt == nil {
		valSpan.SetTag("error", "invalid refresh")
		valSpan.Finish()
		span.SetTag("error", "invalid refresh")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh"})
		return
	}
	valSpan.Finish()
	// выдаём новый access; (ротацию refresh можно добавить позже)
	now := time.Now().UTC()

	// 3.1 reuse: токен уже был заменён (или иным образом ревокнут) → блокируем всю семью
	if rt.Revoked {
		if rt.ReplacedByJTI != "" {
			// reuse detected → revoke family
			reuSpan, _ := tracer.StartSpanFromContext(ctx, "auth.refresh.reuse_detected")
			_ = h.Store.RevokeFamily(ctx, rt.FamilyID)
			reuSpan.Finish()
		}
		span.SetTag("error", "session invalidated (revoked)")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalidated, please re-login"})
		return
	}

	// 3.2 expired
	if now.After(rt.ExpiresAt) {
		span.SetTag("error", "expired refresh")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "expired refresh"})
		return
	}

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
	tok, err := security.MakeAccessRS256(h.Keys, u.ID.String(), u.Email, 15*time.Minute)
	if err != nil {
		aSpan.SetTag("error", err)
		aSpan.Finish()
		span.SetTag("error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	aSpan.Finish()

	rotSpan, rotCtx := tracer.StartSpanFromContext(ctx, "auth.refresh.rotate")
	newJTI, _ := security.NewID()
	newRef, _ := security.NewRefreshToken()
	newRec := repo.RefreshToken{
		UserID:    rt.UserID,
		TokenHash: repo.HashToken(newRef),
		FamilyID:  rt.FamilyID,
		ParentJTI: rt.JTI,
		JTI:       newJTI,
		ExpiresAt: now.Add(h.RefreshTTL).UTC(),
		Revoked:   false,
		UA:        c.Request.UserAgent(),
		IP:        c.ClientIP(),
	}
	if err := h.Store.SaveRefresh(rotCtx, newRec); err != nil {
		rotSpan.SetTag("error", err)
		rotSpan.Finish()
		span.SetTag("error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh save error"})
		return
	}
	// Старый пометить как заменённый (rotation)
	if err := h.Store.MarkRotated(rotCtx, rt.JTI, newJTI); err != nil {
		rotSpan.SetTag("error", err)
		rotSpan.Finish()
		span.SetTag("error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh rotate error"})
		return
	}
	rotSpan.Finish()

	// (опционально) ротация: сгенерировать новый refresh, сохранить и вернуть его вместо старого (и пометить старый как revoked)
	span.SetTag("user_id", u.ID.Hex())
	c.JSON(http.StatusOK, gin.H{"access": tok, "refresh": newRef})
}

// Logout godoc
// @Summary     Logout (revoke refresh)
// @Tags        auth
// @Accept      json
// @Param       payload body     logoutReq true "logout payload"
// @Success     204
// @Failure     400 {object} map[string]any
// @Router      /api/auth/logout [post]
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
// @Summary     Current user profile
// @Tags        auth
// @Security    BearerAuth
// @Produce     json
// @Success     200 {object} map[string]any "id, email, name, created_at"
// @Failure     401 {object} map[string]any
// @Router      /api/auth/me [get]
func (h *Handler) Me(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.me")
	defer span.Finish()
	span.SetTag("route", "/api/auth/me")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	au, ok := c.Get(authUserKey) // тот же ключ, что и в middleware
	if !ok || au == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userCtx, ok := au.(AuthUser)
	if !ok || userCtx.UID == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	span.SetTag("user_id", userCtx.UID)

	uSpan, _ := tracer.StartSpanFromContext(ctx, "auth.me.find_user")
	u, err := h.Store.FindUserByEmail(c.Request.Context(), strings.ToLower(userCtx.Email))
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

////OAuth (Google)

// GoogleLogin godoc
// @Summary     Google OAuth2 Login (redirect)
// @Tags        oauth
// @Success     302
// @Router      /api/auth/google/login [get]
func (h *Handler) GoogleLogin(c *gin.Context) {
	span, _ := tracer.StartSpanFromContext(c.Request.Context(), "oauth.google.login")
	defer span.Finish()
	span.SetTag("route", "/api/auth/google/login")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}
	// state можно привязать к req_id или сессии
	state := h.Google.MakeState(c.GetString("X-Request-ID"))
	url := h.Google.AuthURL(state)
	Logger(c).Info("oauth_google_login_redirect",
		zap.String("req_id", c.GetString("X-Request-ID")),
	)
	c.Redirect(http.StatusFound, url)
}

// GoogleCallback godoc
// @Summary     Google OAuth2 Callback
// @Tags        oauth
// @Produce     json
// @Param       state query string true "state"
// @Param       code  query string true "code"
// @Success     200   {object} map[string]string "access, refresh, provider"
// @Failure     400   {object} map[string]any
// @Failure     401   {object} map[string]any
// @Router      /api/auth/google/callback [get]
func (h *Handler) GoogleCallback(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "oauth.google.callback")
	defer span.Finish()
	span.SetTag("route", "/api/auth/google/callback")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	st := c.Query("state")
	if !h.Google.VerifyState(st) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad state"})
		span.SetTag("error", "bad state")
		Logger(c).Warn("oauth_google_bad_state")
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		span.SetTag("error", "missing code")
		Logger(c).Warn("oauth_google_missing_state")
		return
	}

	gu, err := h.Google.ExchangeAndVerify(ctx, code, h.GoogleClientID()) // см. ниже accessor
	exSpan, _ := tracer.StartSpanFromContext(ctx, "oauth.google.exchange")
	if err != nil {
		exSpan.SetTag("error", err)
		exSpan.Finish()
		Logger(c).Warn("oauth_google_exchange_failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "oauth exchange failed"})
		return
	}
	exSpan.SetTag("email_hash", helper.Hash8(gu.Email))
	exSpan.Finish()

	// найти юзера
	findSpan, _ := tracer.StartSpanFromContext(ctx, "user.find_by_provider")
	u, err := h.Store.FindUserByProviderID(ctx, "google", gu.Sub)
	if err != nil {
		findSpan.SetTag("error", err)
		findSpan.Finish()
		Logger(c).Error("db_find_provider_error", zap.Error(err))
		c.JSON(500, gin.H{"error": "db error"})
		return
	}
	findSpan.Finish()

	if u == nil {
		// попытка по email, если уже есть локальная регистрация — привязываем

		byEmailSpan, _ := tracer.StartSpanFromContext(ctx, "user.find_by_email")
		ex, err := h.Store.FindUserByEmail(ctx, strings.ToLower(gu.Email))
		if err != nil {
			byEmailSpan.SetTag("error", err)
			byEmailSpan.Finish()
			Logger(c).Error("db_find_email_error", zap.Error(err))
			c.JSON(500, gin.H{"error": "db error"})
			return
		}
		byEmailSpan.Finish()

		if ex != nil {
			updSpan, _ := tracer.StartSpanFromContext(ctx, "user.attach_google")
			// апдейтим провайдера (можно сделать отдельным методом UpdateUserProvider)
			ex.Provider = "google"
			ex.ExternalID = gu.Sub
			ex.Verified = ex.Verified || gu.EmailVerified
			// простой апдейт:
			_, err := h.Store.DB.Collection("users").UpdateByID(ctx, ex.ID, bson.M{
				"$set": bson.M{"provider": "google", "external_id": gu.Sub, "verified": ex.Verified},
			})
			if err != nil {
				updSpan.SetTag("error", err)
				updSpan.Finish()
				Logger(c).Error("db_update_error", zap.Error(err))
				c.JSON(500, gin.H{"error": "db error"})
				return
			}
			updSpan.Finish()
			u = ex
		} else {
			crtSpan, _ := tracer.StartSpanFromContext(ctx, "user.create_oauth")
			// создаём нового OAuth-пользователя
			u = &domain.User{
				Email:      strings.ToLower(gu.Email),
				Name:       gu.Name,
				Provider:   "google",
				ExternalID: gu.Sub,
				Verified:   gu.EmailVerified,
			}
			if err := h.Store.CreateOAuthUser(ctx, u); err != nil {
				crtSpan.SetTag("error", err)
				crtSpan.Finish()
				Logger(c).Warn("db_create_oauth_conflict", zap.Error(err))
				c.JSON(409, gin.H{"error": "email already exists"})
				return
			}
			crtSpan.Finish()
		}
	}

	tSpan, _ := tracer.StartSpanFromContext(ctx, "auth.issue_tokens")
	// выдаём наши access (RS256 + kid) и refresh (с ротацией дальше по нашему флоу)
	access, err := security.MakeAccessRS256(h.Keys, u.ID.String(), u.Email, 15*time.Minute)
	if err != nil {
		tSpan.SetTag("error", err)
		tSpan.Finish()
		Logger(c).Error("issue_access_error", zap.Error(err))
		c.JSON(500, gin.H{"error": "token error"})
		return
	}

	familyID, _ := security.NewID()
	jti, _ := security.NewID()
	ref, _ := security.NewRefreshToken()
	if err := h.Store.SaveRefresh(ctx, repo.RefreshToken{
		UserID:    u.ID,
		TokenHash: repo.HashToken(ref),
		FamilyID:  familyID,
		JTI:       jti,
		ExpiresAt: time.Now().Add(h.RefreshTTL).UTC(),
		UA:        c.Request.UserAgent(),
		IP:        c.ClientIP(),
	}); err != nil {
		tSpan.SetTag("error", err)
		tSpan.Finish()
		Logger(c).Error("save_refresh_error", zap.Error(err))
		c.JSON(500, gin.H{"error": "refresh save"})
		return
	}
	tSpan.Finish()

	// (опц.) публикуем событие user.loggedin (provider=google)

	parent := span
	rid := c.GetString("X-Request-ID")
	pub := h.Events
	go func() {
		pubSpan := tracer.StartSpan("auth.loggedin.publish", tracer.ChildOf(parent.Context()))
		_ = pub.Publish(context.Background(), "auth.events", "user.loggedin",
			queue.UserLoggedIn{UserID: u.ID, Email: u.Email}, rid)
		pubSpan.Finish()
	}()

	// Вернём JSON, чтобы было удобно тестировать из Postman (а не только через редирект на фронт)
	span.SetTag("user_id", u.ID)
	span.SetTag("email_hash", helper.Hash8(u.Email))
	Logger(c).Info("oauth_google_success",
		zap.String("user_id", u.ID.String()),
		zap.String("email_hash", helper.Hash8(u.Email)),
	)
	c.JSON(200, gin.H{"access": access, "refresh": ref, "provider": "google"})
}

// маленький аксессор, чтобы не тащить cfg в Handler напрямую
func (h *Handler) GoogleClientID() string { return h.GoogleClientIDFromConfig } // или храни в Handler строкой

//// VerifyEmail Forgot/Reset Password

// VerifyEmail godoc
// @Summary     Verify email
// @Tags        email
// @Produce     json
// @Param       token query string true "verification token"
// @Success     200   {object} map[string]string "status: verified"
// @Failure     400   {object} map[string]any
// @Router      /api/auth/verify [get]
func (h *Handler) VerifyEmail(c *gin.Context) {

	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.email.verify")
	defer span.Finish()
	span.SetTag("route", "/api/auth/verify")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	t := c.Query("token")
	if t == "" {
		span.SetTag("error", "missing token")
		Logger(c).Warn("verify_missing_token")
		c.JSON(400, gin.H{"error": "missing token"})
		return
	}
	et, err := h.Store.UseEmailToken(c.Request.Context(), t, "verify")
	if err != nil {
		span.SetTag("error", err)
		Logger(c).Warn("verify_invalid_or_used", zap.Error(err))
		c.JSON(400, gin.H{"error": "invalid or used token"})
		return
	}

	// пометить пользователя verified
	updSpan, _ := tracer.StartSpanFromContext(ctx, "user.mark_verified")
	_, err = h.Store.DB.Collection("users").UpdateByID(c.Request.Context(), et.UserID, bson.M{"$set": bson.M{"verified": true}})
	if err != nil {
		updSpan.SetTag("error", err)
		updSpan.Finish()
		Logger(c).Error("verify_update_user_error", zap.Error(err))
		c.JSON(500, gin.H{"error": "db error"})
		return
	}
	updSpan.Finish()

	// (опц.) событие

	parent := span
	rid := c.GetString("X-Request-ID")
	pub := h.Events
	go func() {
		pubSpan := tracer.StartSpan("email.verified.publish", tracer.ChildOf(parent.Context()))
		_ = pub.Publish(context.Background(), "auth.events", "email.verified", map[string]any{"user_id": et.UserID}, rid)
		pubSpan.Finish()
	}()

	Logger(c).Info("email_verified", zap.String("user_id", et.UserID.String()))
	c.JSON(200, gin.H{"status": "verified"})
}

// ForgotPassword godoc
// @Summary     Request password reset
// @Tags        password
// @Accept      json
// @Produce     json
// @Param       payload body     forgotReq true "forgot payload"
// @Success     200     {object} map[string]any "status; dev: reset_token_dev"
// @Failure     400     {object} map[string]any
// @Router      /api/auth/forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	span, _ := tracer.StartSpanFromContext(c.Request.Context(), "auth.password.forgot")
	defer span.Finish()
	span.SetTag("route", "/api/auth/forgot-password")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	var in forgotReq
	if err := c.ShouldBindJSON(&in); err != nil || !strings.Contains(in.Email, "@") {
		span.SetTag("error", "invalid email")
		Logger(c).Warn("forgot_invalid_email")
		c.JSON(400, gin.H{"error": "invalid email"})
		return
	}
	// Найти пользователя (не раскрываем наличие e-mail в ответе)
	u, _ := h.Store.FindUserByEmail(c.Request.Context(), strings.ToLower(in.Email))
	if u != nil && u.Provider == "local" { // для OAuth-пользователей reset не шлём
		rt, _ := security.NewOpaqueToken()
		if err := h.Store.CreateEmailToken(c.Request.Context(), repo.EmailToken{
			UserID: u.ID, Token: rt, Purpose: "reset", ExpiresAt: time.Now().Add(30 * time.Minute).UTC(),
		}); err != nil {
			span.SetTag("error", err)
			Logger(c).Error("reset_token_create_error", zap.Error(err))
		}

		parent := span
		rid := c.GetString("X-Request-ID")
		pub := h.Events
		go func() {
			pubSpan := tracer.StartSpan("password.reset.requested.publish", tracer.ChildOf(parent.Context()))
			_ = pub.Publish(context.Background(), "auth.events", "password.reset.requested",
				map[string]any{"user_id": u.ID, "email": u.Email, "token": rt}, rid)
			pubSpan.Finish()
		}()

		// dev: выдадим токен в ответ, чтобы не настраивать smtp прямо сейчас
		Logger(c).Info("password_reset_token_issued_dev", zap.String("user_id", u.ID.String()), zap.String("email_hash", helper.Hash8(u.Email)))
		c.JSON(200, gin.H{"status": "ok", "reset_token_dev": rt})
		return
	}
	c.JSON(200, gin.H{"status": "ok"}) // одинаковый ответ, чтобы не палить, существует ли email
}

// ResetPassword godoc
// @Summary     Reset password with token
// @Tags        password
// @Accept      json
// @Produce     json
// @Param       payload body     resetReq true "reset payload"
// @Success     200     {object} map[string]string "status: password_updated"
// @Failure     400     {object} map[string]any
// @Failure     500     {object} map[string]any
// @Router      /api/auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	span, ctx := tracer.StartSpanFromContext(c.Request.Context(), "auth.password.reset")
	defer span.Finish()
	span.SetTag("route", "/api/auth/reset-password")
	if rid := c.GetString("X-Request-ID"); rid != "" {
		span.SetTag("req_id", rid)
	}

	var in resetReq
	if err := c.ShouldBindJSON(&in); err != nil || len(in.NewPassword) < 8 {
		span.SetTag("error", "invalid payload")
		Logger(c).Warn("reset_invalid_payload")
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	et, err := h.Store.UseEmailToken(c.Request.Context(), in.Token, "reset")
	if err != nil {
		span.SetTag("error", err)
		Logger(c).Warn("reset_invalid_or_used", zap.Error(err))
		c.JSON(400, gin.H{"error": "invalid or used token"})
		return
	}

	// Обновить пароль
	hpSpan, _ := tracer.StartSpanFromContext(ctx, "auth.password.hash")
	hash, err := security.HashPassword(in.NewPassword)
	if err != nil {
		hpSpan.SetTag("error", err)
		hpSpan.Finish()
		Logger(c).Error("hash_failed", zap.Error(err))
		c.JSON(500, gin.H{"error": "hash failed"})
		return
	}
	hpSpan.Finish()

	upSpan, _ := tracer.StartSpanFromContext(ctx, "user.update_password")
	_, err = h.Store.DB.Collection("users").UpdateByID(c.Request.Context(), et.UserID, bson.M{
		"$set": bson.M{"password_hash": hash},
	})
	if err != nil {
		upSpan.SetTag("error", err)
		upSpan.Finish()
		Logger(c).Error("update_password_error", zap.Error(err))
		c.JSON(500, gin.H{"error": "db error"})
		return
	}
	upSpan.Finish()

	// Ревокация всех refresh-семей пользователя (обнулить активные сессии)
	rvSpan, _ := tracer.StartSpanFromContext(ctx, "auth.refresh.revoke_all")
	_, _ = h.Store.DB.Collection("refresh_tokens").UpdateMany(
		c.Request.Context(),
		bson.M{"user_id": et.UserID, "revoked": false},
		bson.M{"$set": bson.M{"revoked": true, "revoked_reason": "password_reset"}},
	)
	rvSpan.Finish()

	parent := span
	rid := c.GetString("X-Request-ID")
	pub := h.Events
	go func() {
		pubSpan := tracer.StartSpan("password.reset.done.publish", tracer.ChildOf(parent.Context()))
		_ = pub.Publish(context.Background(), "auth.events", "password.reset.done",
			map[string]any{"user_id": et.UserID}, rid)
		pubSpan.Finish()
	}()

	Logger(c).Info("password_updated", zap.String("user_id", et.UserID.String()))
	c.JSON(200, gin.H{"status": "password_updated"})
}

// JWKS godoc
// @Summary     JWKS (public keys)
// @Tags        system
// @Produce     json
// @Success     200 {object} map[string]any "JWKS"
// @Router      /.well-known/jwks.json [get]
func (h *Handler) JWKS(c *gin.Context) {
	c.JSON(200, h.Keys.JWKS())
}

// Healthz godoc
// @Summary     Health check
// @Tags        system
// @Success     200 {string} string "ok"
// @Router      /healthz [get]
func (h *Handler) Healthz(c *gin.Context) {
	if err := h.Store.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "degraded", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

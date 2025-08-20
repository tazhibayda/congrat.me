package http

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tazhibayda/auth-service/internal/log"
	"github.com/tazhibayda/auth-service/internal/metrics"
	"github.com/tazhibayda/auth-service/internal/repo"
	"github.com/tazhibayda/auth-service/internal/security"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var authUserKey = "authUser" // ключ в контексте

type AuthUser struct{ UID, Email string }

func AuthJWT(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		token := strings.TrimSpace(h[len("Bearer "):])
		claims, err := security.ParseAccess(jwtSecret, token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set(authUserKey, AuthUser{UID: claims.UID, Email: claims.Email})
		c.Next()
	}
}

type LimiterDeps struct {
	R      *repo.Redis
	Limit  int           // запросов
	Window time.Duration // обычно 1 мин
}

func RateLimit(dep LimiterDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		route := c.FullPath() // /api/auth/login или /api/auth/register
		if route == "" {
			route = c.Request.URL.Path
		}
		key := "rate:" + route + ":" + ip

		ctx := c.Request.Context()
		// INCR + EXPIRE(60s) если ключ новый
		val, err := dep.R.C.Incr(ctx, key).Result()
		if err != nil {
			// на сбое Redis не валим запрос, просто пропускаем
			c.Next()
			return
		}
		if val == 1 {
			dep.R.C.Expire(ctx, key, dep.Window)
		}
		if int(val) > dep.Limit {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

func Prometheus() gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics.InFlight.Inc()
		start := time.Now()
		c.Next()
		metrics.InFlight.Dec()

		route := c.FullPath()
		if route == "" {
			route = c.Request.URL.Path
		}
		metrics.RequestsTotal.WithLabelValues(route, c.Request.Method, strconv.Itoa(c.Writer.Status())).Inc()
		metrics.ReqDuration.WithLabelValues(route, c.Request.Method).Observe(time.Since(start).Seconds())
	}
}

const reqIDHeader = "X-Request-ID"
const loggerKey = "logger"

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader(reqIDHeader)
		if rid == "" {
			rid = uuid.NewString() // go get github.com/google/uuid (если еще не добавили)
		}
		c.Set(reqIDHeader, rid)
		c.Writer.Header().Set(reqIDHeader, rid)
		c.Next()
	}
}

func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetString(reqIDHeader)
		ctx := c.Request.Context()
		ctxLogger := log.WithDD(ctx, log.L, zap.String("req_id", rid))
		c.Set(loggerKey, ctxLogger)

		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = c.Request.URL.Path
		}

		uid := c.GetString("uid") // если AuthJWT уже положил

		log.L.Info("http",
			zap.String("method", c.Request.Method),
			zap.String("route", route),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("ip", c.ClientIP()),
			zap.String("uid", uid),
			zap.String("ua", c.Request.UserAgent()),
		)
	}
}

func Logger(c *gin.Context) *zap.Logger {
	if v, ok := c.Get(loggerKey); ok {
		if l, ok2 := v.(*zap.Logger); ok2 {
			return l
		}
	}
	return log.L
}

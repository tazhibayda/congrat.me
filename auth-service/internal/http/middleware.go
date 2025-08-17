package http

import (
	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/auth-service/internal/repo"
	"github.com/tazhibayda/auth-service/internal/security"
	"net/http"
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

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

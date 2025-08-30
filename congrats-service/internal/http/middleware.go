package http

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/congrats-service/internal/security"
)

type bucket struct {
	tokens  int
	updated time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // максимальное кол-во за окно
	window  time.Duration // окно
}

func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	return &RateLimiter{buckets: make(map[string]*bucket), rate: rate, window: window}
}

func (rl *RateLimiter) Allow(ip string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok || now.Sub(b.updated) > rl.window {
		rl.buckets[ip] = &bucket{tokens: 1, updated: now}
		return true
	}
	if b.tokens < rl.rate {
		b.tokens++
		b.updated = now
		return true
	}
	return false
}

func ClientIP(c *gin.Context) string {
	// базово: берем c.ClientIP(); можно учесть X-Forwarded-For за прокси/ingress
	ip := c.ClientIP()
	if ip == "" {
		ip = "unknown"
	}
	host, _, err := net.SplitHostPort(ip)
	if err == nil && host != "" {
		return host
	}
	return ip
}

func RateLimitSubmit(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := ClientIP(c)
		if !rl.Allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			return
		}
		c.Next()
	}
}

func AuthJWT(f *security.Fetcher) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer"})
			return
		}
		tok := strings.TrimSpace(h[len("Bearer "):])
		claims, err := f.ParseAndVerify(c.Request.Context(), tok)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		uid := claims.UID
		if uid == "" && claims.Subject != "" {
			uid = claims.Subject
		}
		uid = normalizeUID(uid)
		if uid == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "no uid"})
			return
		}

		c.Set("uid", uid)
		c.Set("email", claims.Email)
		c.Next()
	}
}

func normalizeUID(s string) string {
	s = strings.TrimSpace(s)
	// формат ObjectID("...") → достанем то, что внутри
	if strings.HasPrefix(s, "ObjectID(\"") && strings.HasSuffix(s, "\")") {
		str := s[len("ObjectID(\"") : len(s)-len("\")")]
		return str
	}
	return s
}

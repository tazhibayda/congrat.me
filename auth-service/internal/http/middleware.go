package http

import (
	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/auth-service/internal/security"
	"net/http"
	"strings"
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

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

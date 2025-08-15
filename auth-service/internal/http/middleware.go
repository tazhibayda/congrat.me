package http

import "github.com/gin-gonic/gin"

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

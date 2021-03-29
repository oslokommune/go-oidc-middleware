package wrappers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Gin adds Gin support to the authentication middleware
//goland:noinspection GoUnusedExportedFunction
func Gin(handler http.HandlerFunc) gin.HandlerFunc {
	return func(context *gin.Context) {
		handler.ServeHTTP(context.Writer, context.Request)
	}
}

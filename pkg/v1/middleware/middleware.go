package middleware

import (
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
)

func NewAuthenticationMiddleware(discoveryURL url.URL) *jwtmiddleware.JWTMiddleware {
	discoveryDocument := newDiscoveryDocument(discoveryURL)

	err := discoveryDocument.Initialize()
	if err != nil {
		panic(err)
	}

	middleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: createValidationKeyGetter(discoveryDocument),
		ErrorHandler:        nil,
		Extractor:           jwtmiddleware.FromAuthHeader,
		Debug:               false,
		SigningMethod:       jwt.SigningMethodRS256,
	})

	return middleware
}

func NewGinAuthenticationMiddleware(discoveryURL url.URL) gin.HandlerFunc {
	middleware := NewAuthenticationMiddleware(discoveryURL)

	return func(c *gin.Context) {
		err := middleware.CheckJWT(c.Writer, c.Request)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		} else {
			c.Next()
		}
	}
}

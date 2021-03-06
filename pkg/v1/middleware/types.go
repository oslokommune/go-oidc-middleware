package middleware

import (
	"github.com/sirupsen/logrus"
	"io"
	"net/url"

	"github.com/dgrijalva/jwt-go"
)

type JSONWebKeyResponse struct {
	Keys []JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type DiscoveryDocument struct {
	DiscoveryURL          url.URL
	Algorithms            []string `json:"id_token_signing_alg_values_supported"`
	IntrospectionEndpoint string
	Issuer                string `json:"issuer"`
	JWKSURL               string `json:"jwks_uri"`
	KeyResponse           *JSONWebKeyResponse
}

type User struct {
	Claims jwt.MapClaims
}

type NewJWTValidationMiddlewareOptions struct {
	Out      io.Writer
	LogLevel logrus.Level

	DiscoveryURL *url.URL
}

type NewGinIntrospectionValidationMiddlewareOptions struct {
	Out      io.Writer
	LogLevel logrus.Level

	DiscoveryURL *url.URL
	ClientID     string
	ClientSecret string
}

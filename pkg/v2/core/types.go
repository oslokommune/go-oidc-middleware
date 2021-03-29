package core

import (
	"errors"
	"net/url"
)

// ErrNotAuthenticated represents an invalid authentication request
var ErrNotAuthenticated = errors.New("not authenticated")

// Validator represents a token validation process
type Validator interface {
	// Ready indicates whether the validator has all the required information to perform a validation
	Ready() bool
	// Validate validates a token and returns an error if the token isn't valid
	Validate(token string) error
}

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
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	Issuer                string   `json:"issuer"`
	JWKSURL               string   `json:"jwks_uri"`
	KeyResponse           *JSONWebKeyResponse
}

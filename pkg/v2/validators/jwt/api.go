package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/oslokommune/go-oidc-middleware/pkg/v2/core"
)

func New(jwkResponse core.JSONWebKeyResponse, issuer, audience string) core.Validator {
	checker := createValidationKeyGetter(jwkResponse, issuer, audience)

	return &jwtValidator{
		active:  true,
		checker: checker,
	}
}

func (j jwtValidator) Validate(rawToken string) error {
	_, err := jwt.Parse(rawToken, j.checker)
	if err != nil {
		return err
	}

	return nil
}

func (j jwtValidator) Ready() bool {
	return j.active
}

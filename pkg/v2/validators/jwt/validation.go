package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/oslokommune/go-oidc-middleware/pkg/v2/core"
)

func getPemCert(JWKSResponse core.JSONWebKeyResponse, token *jwt.Token) (string, error) {
	cert := ""

	for k := range JWKSResponse.Keys {
		if token.Header["kid"] == JWKSResponse.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + JWKSResponse.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")

		return cert, err
	}

	return cert, nil
}

func createValidationKeyGetter(keyResponse core.JSONWebKeyResponse, issuer, audience string) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("converting claims")
		}

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method: %s", token.Method.Alg())
		}

		checkAud := claims.VerifyAudience(audience, true)
		if !checkAud {
			return token, fmt.Errorf("invalid audience: %s", claims["aud"].(string))
		}

		checkIss := claims.VerifyIssuer(issuer, true)
		if !checkIss {
			return token, fmt.Errorf("invalid issuer: %s", claims["iss"].(string))
		}

		checkTime := claims.VerifyIssuedAt(time.Now().Unix(), true)
		if !checkTime {
			return token, fmt.Errorf("invalid issued at: %f", claims["iat"].(float64))
		}

		cert, err := getPemCert(keyResponse, token)
		if err != nil {
			panic(err.Error())
		}

		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))

		return result, nil
	}
}

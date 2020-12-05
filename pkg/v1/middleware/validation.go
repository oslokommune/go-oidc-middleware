package middleware

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func getPemCert(JWKSResponse *JSONWebKeyResponse, token *jwt.Token) (string, error) {
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

func createValidationKeyGetter(doc *DiscoveryDocument) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		//checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(, true)
		//if !checkAud {
		//	return token, errors.New("invalid audience")
		//}

		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(doc.Issuer, true)
		if !checkIss {
			return token, errors.New("invalid issuer")
		}

		checkTime := token.Claims.(jwt.MapClaims).VerifyIssuedAt(time.Now().Unix(), true)
		if !checkTime {
			return token, errors.New("invalid issued at")
		}

		cert, err := getPemCert(doc.KeyResponse, token)
		if err != nil {
			panic(err.Error())
		}

		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))

		return result, nil
	}
}

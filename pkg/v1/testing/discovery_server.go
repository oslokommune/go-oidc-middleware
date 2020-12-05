package testing

import (
	"encoding/json"
	"fmt"
	"github.com/oslokommune/go-oidc-middleware/pkg/v1/middleware"
	"net/http"
	"net/http/httptest"
	"net/url"
)

func createJWKResponse(secret *TestingSecret) *middleware.JSONWebKeyResponse {
	key := middleware.JSONWebKey{
		Kty: secret.Kty,
		Kid: secret.Kid,
		Use: secret.Use,
		Alg: secret.Alg,
		N:   secret.N,
		E:   secret.E,
		X5c: []string{secret.PublicKey},
	}

	response := middleware.JSONWebKeyResponse{
		Keys: make([]middleware.JSONWebKey, 1),
	}

	response.Keys[0] = key

	return &response
}

func createDiscoveryDocumentHandler(options *TestTokenOptions) func(w http.ResponseWriter, r *http.Request) {
	discoveryDocument := TestDiscoveryDocument{
		Issuer: options.Issuer,
	}

	jwkResponse := createJWKResponse(options.Secret)

	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Add("Content-Type", "application/json")

		switch request.URL.Path {
		case "/":
			if discoveryDocument.JwksURI == "" {
				jwksURLRaw := fmt.Sprintf("http://%s/certs", request.Host)
				jwksURL, _ := url.Parse(jwksURLRaw)
				jwksURL.Path = "certs"

				discoveryDocument.JwksURI = jwksURL.String()
			}

			result, _ := json.Marshal(discoveryDocument)

			_, _ = writer.Write(result)
		case "/certs":
			result, _ := json.Marshal(jwkResponse)

			_, _ = writer.Write(result)
		}
	}
}

func CreateTestDiscoveryServer(options *TestTokenOptions) *httptest.Server {
	discoveryDocumentHandler := createDiscoveryDocumentHandler(options)

	testServer := httptest.NewServer(http.HandlerFunc(discoveryDocumentHandler))

	return testServer
}

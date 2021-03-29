package testing

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//goland:noinspection GoUnusedExportedFunction
func CreateTestDiscoveryServer(options *TestTokenOptions) *httptest.Server {
	discoveryDocumentHandler := createDiscoveryDocumentHandler(options)

	testServer := httptest.NewServer(http.HandlerFunc(discoveryDocumentHandler))

	return testServer
}

//goland:noinspection GoUnusedExportedFunction
func NewTestTokenOptions() *TestTokenOptions {
	return &TestTokenOptions{
		Secret:   newTestingSecret(),
		Username: "xxx102030",
		Issuer:   "authenticationprovider",
	}
}

//goland:noinspection GoUnusedExportedFunction
func NewTestToken(options *TestTokenOptions) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"preferred_username": options.Username,
		"exp":                time.Now().Add(time.Hour * time.Duration(1)).Unix(),
		"iat":                time.Now().Unix(),
		"iss":                options.Issuer,
	})

	token.Header["kid"] = options.Secret.Kid

	block, _ := pem.Decode([]byte(options.Secret.PrivateKey))
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error parsing private key")
	}

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error signing token: ", err)
	}

	return tokenString
}

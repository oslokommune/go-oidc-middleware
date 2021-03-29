package introspection

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

type introspectionHandler struct {
	validCredentials string
	validToken       string
}

func (i introspectionHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", i.validCredentials) {
		writer.WriteHeader(http.StatusUnauthorized)

		return
	}

	payload, _ := io.ReadAll(request.Body)
	defer func() {
		_ = request.Body.Close()
	}()

	values, _ := url.ParseQuery(string(payload))

	if values.Get("token") != i.validToken {
		writer.WriteHeader(http.StatusUnauthorized)

		return
	}

	writer.WriteHeader(http.StatusOK)
}

func TestName(t *testing.T) {
	testCases := []struct {
		name string

		expectedClientID     string
		expectedClientSecret string
		expectedToken        string

		givenClientID     string
		givenClientSecret string
		givenToken        string

		expectErr error
	}{
		{
			name: "Should return an error with bad credentials",

			expectedClientID:     "someid",
			expectedClientSecret: "somesecret",
			expectedToken:        "sometoken",

			givenClientID:     "naughtyid",
			givenClientSecret: "somesecret",
			givenToken:        "sometoken",

			expectErr: errors.New("validating status code"),
		},
		{
			name: "Should return an error with a bad token",

			expectedClientID:     "someid",
			expectedClientSecret: "somesecret",
			expectedToken:        "sometoken",

			givenClientID:     "someid",
			givenClientSecret: "somesecret",
			givenToken:        "naughtytoken",

			expectErr: errors.New("validating status code"),
		},
		{
			name: "Should return zero errors when given valid data",

			expectedClientID:     "someid",
			expectedClientSecret: "somesecret",
			expectedToken:        "sometoken",

			givenClientID:     "someid",
			givenClientSecret: "somesecret",
			givenToken:        "sometoken",

			expectErr: nil,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(introspectionHandler{
				validCredentials: bearerToken(tc.expectedClientID, tc.expectedClientSecret),
				validToken:       tc.expectedToken,
			})

			validator := New(tc.givenClientID, tc.givenClientSecret, server.URL)

			err := validator.Validate(tc.givenToken)
			assert.Equal(t, tc.expectErr, err)
		})
	}
}

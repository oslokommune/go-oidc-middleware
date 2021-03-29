package userinfo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oslokommune/go-oidc-middleware/pkg/v2/core"
	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	testCases := []struct {
		name string

		expectedToken string

		givenToken string

		expectErr error
	}{
		{
			name: "Should return not authenticated error with bad token",

			expectedToken: "sometoken",
			givenToken:    "invalidtoken",
			expectErr:     core.ErrNotAuthenticated,
		},
		{
			name: "Should return zero errors when given valid data",

			expectedToken: "sometoken",
			givenToken:    "sometoken",
			expectErr:     nil,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(userinfoHandler{
				validToken: tc.expectedToken,
			})

			validator := New(server.URL)

			err := validator.Validate(tc.givenToken)
			assert.Equal(t, tc.expectErr, err)
		})
	}
}

type userinfoHandler struct {
	validToken string
}

func (i userinfoHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	potentialToken, _ := request.Cookie("access_token")

	if potentialToken.Value != i.validToken {
		writer.WriteHeader(http.StatusUnauthorized)

		return
	}

	writer.WriteHeader(http.StatusOK)
}

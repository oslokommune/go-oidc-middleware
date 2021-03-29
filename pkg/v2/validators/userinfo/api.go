package userinfo

import (
	"fmt"
	"net/http"

	"github.com/oslokommune/go-oidc-middleware/pkg/v2/core"
)

func New(userinfoEndpoint string) core.Validator {
	return &userinfoValidator{
		client:   http.Client{},
		endpoint: userinfoEndpoint,
	}
}

func (u userinfoValidator) Validate(token string) error {
	request, err := http.NewRequest(http.MethodGet, u.endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	request.AddCookie(&http.Cookie{
		Name:     "access_token",
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})

	response, err := u.client.Do(request)
	if err != nil {
		return fmt.Errorf("doing request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return core.ErrNotAuthenticated
	}

	return nil
}

func (u userinfoValidator) Ready() bool {
	return u.endpoint != ""
}

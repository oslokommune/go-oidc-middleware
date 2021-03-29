package introspection

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/oslokommune/go-oidc-middleware/pkg/v2/core"
)

func New(clientID, clientSecret, introspectionURL string) core.Validator {
	return &introspectionValidator{
		client:   http.Client{},
		endpoint: introspectionURL,

		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

func (i introspectionValidator) Validate(token string) error {
	values := url.Values{}
	values.Add("token", token)

	request, err := http.NewRequest(http.MethodPost, i.endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken(i.clientID, i.clientSecret)))

	response, err := i.client.Do(request)
	if err != nil {
		return fmt.Errorf("doing request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("validating status code")
	}

	return nil
}

func (i introspectionValidator) Ready() bool {
	return i.endpoint != ""
}

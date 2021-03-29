package introspection

import (
	"net/http"
)

type introspectionValidator struct {
	client   http.Client
	endpoint string

	clientID     string
	clientSecret string
}

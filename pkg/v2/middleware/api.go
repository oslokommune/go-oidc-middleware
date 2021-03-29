package middleware

import (
	"fmt"
	"net/http"

	"github.com/oslokommune/go-oidc-middleware/pkg/v2/core"
	"github.com/oslokommune/go-oidc-middleware/pkg/v2/validators/jwt"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/oslokommune/go-oidc-middleware/pkg/v2/validators/composite"
	"github.com/oslokommune/go-oidc-middleware/pkg/v2/validators/introspection"
	"github.com/oslokommune/go-oidc-middleware/pkg/v2/validators/userinfo"
	log "github.com/sirupsen/logrus"
)

// New creates a new authentication middleware
//goland:noinspection GoUnusedExportedFunction
func New(options Options) http.HandlerFunc {
	document, err := core.FetchDiscoveryDocument(options.DiscoveryURL)
	if err != nil {
		log.Fatal(err)
	}

	validator := composite.NewCompositeValidator(
		jwt.New(*document.KeyResponse, document.Issuer, options.Audience),
		introspection.New(options.ClientID, options.ClientSecret, document.IntrospectionEndpoint),
		userinfo.New(document.UserinfoEndpoint),
	)

	return func(writer http.ResponseWriter, request *http.Request) {
		token, err := jwtmiddleware.FromAuthHeader(request)
		if err != nil {
			log.Error(fmt.Errorf("fetching token: %w", err))
		}

		err = validator.Validate(token)
		if err != nil {
			log.Warn(fmt.Errorf("validating token: %w", err))
		}
	}
}

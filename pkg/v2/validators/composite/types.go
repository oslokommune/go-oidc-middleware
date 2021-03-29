package composite

import "github.com/oslokommune/go-oidc-middleware/pkg/v2/core"

type compositeValidator struct {
	validators []core.Validator
}

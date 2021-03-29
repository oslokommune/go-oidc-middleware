package composite

import "github.com/oslokommune/go-oidc-middleware/pkg/v2/core"

func NewCompositeValidator(validators ...core.Validator) core.Validator {
	return compositeValidator{validators: validators}
}

func (c compositeValidator) Validate(token string) error {
	for _, validator := range c.validators {
		if validator.Ready() {
			return validator.Validate(token)
		}
	}

	return nil
}

func (c compositeValidator) Ready() bool {
	return true
}

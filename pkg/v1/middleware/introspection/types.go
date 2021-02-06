package introspection

import "github.com/sirupsen/logrus"

type IntrospectionValidationOptions struct {
	Logger *logrus.Logger

	IntrospectionURL string

	ClientID     string
	ClientSecret string

	Token string
}

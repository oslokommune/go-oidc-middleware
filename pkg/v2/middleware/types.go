package middleware

import (
	"net/url"
)

type Options struct {
	// DiscoveryURL is the OpenID Connect well known URL
	DiscoveryURL url.URL

	ClientID     string
	ClientSecret string

	// Audience is the expected audience
	Audience string
}

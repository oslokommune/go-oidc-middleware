# go-oidc-middleware
A middleware for validating JWT tokens made by an OpenID Connect compliant provider

## How it works

By fetching information from the discovery URL ([.well-known](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)) it can validate a JWT token sent with an Authentication header.

## Middlewares

### General

#### Relevant middleware function
* `NewAuthenticationMiddleware(discoveryURL url.URL) *jwtmiddleware.JWTMiddleware`

### Gin

#### Relevant middleware function
* `NewGinAuthenticationMiddleware(discoveryURL url.URL) *gin.HandlerFunc`

#### Usage
```golang
import github.com/oslokommune/go-oidc-middleware/pkg/v1/middleware"

func NewRouter() *gin.Engine {
	router := gin.Default()

	discoveryURL := url.Parse("https://auth-provider.url/.well-known/openid-configuration")

	router.Use(middleware.NewGinAuthenticationMiddleware(*discoveryURL))

	return router
}
```

package testing

type TestDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
}

type TestTokenOptions struct {
	Secret   *TestingSecret
	Username string
	Issuer   string
}

type TestingSecret struct {
	PrivateKey string
	PublicKey  string

	Kid string
	Kty string
	E   string
	Use string
	Alg string
	N   string
}

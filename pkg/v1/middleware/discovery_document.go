package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func newDiscoveryDocument(discoveryURL url.URL) *DiscoveryDocument {
	return &DiscoveryDocument{
		DiscoveryURL: discoveryURL,
	}
}

func (document *DiscoveryDocument) Initialize() error {
	err := loadDiscoveryDocument(document)
	if err != nil {
		return fmt.Errorf("error loading discovery document: %w", err)
	}

	err = loadJwksData(document)
	if err != nil {
		return fmt.Errorf("error loading jwks data: %w", err)
	}

	return nil
}

func loadDiscoveryDocument(document *DiscoveryDocument) error {
	resp, err := http.Get(document.DiscoveryURL.String())
	if err != nil {
		return fmt.Errorf("could not fetch discovery url: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	err = json.NewDecoder(resp.Body).Decode(document)
	if err != nil {
		return fmt.Errorf("error decoding discovery document: %w", err)
	}

	return nil
}

func loadJwksData(document *DiscoveryDocument) error {
	resp, err := http.Get(document.JWKSURL)
	if err != nil {
		return fmt.Errorf("could not fetch jwks URL")
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	jwks := JSONWebKeyResponse{}

	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return fmt.Errorf("error decoding jwks data: %w", err)
	}

	document.KeyResponse = &jwks

	return nil
}

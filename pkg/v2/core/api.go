package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func FetchDiscoveryDocument(discoveryURL url.URL) (DiscoveryDocument, error) {
	var doc DiscoveryDocument

	resp, err := http.Get(discoveryURL.String())
	if err != nil {
		return DiscoveryDocument{}, fmt.Errorf("fetching discovery url: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	err = json.NewDecoder(resp.Body).Decode(&doc)
	if err != nil {
		return DiscoveryDocument{}, fmt.Errorf("decoding discovery document: %w", err)
	}

	resp, err = http.Get(doc.JWKSURL)
	if err != nil {
		return DiscoveryDocument{}, fmt.Errorf("fetching jwks URL")
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	jwks := JSONWebKeyResponse{}

	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return DiscoveryDocument{}, fmt.Errorf("decoding jwks data: %w", err)
	}

	return doc, nil
}

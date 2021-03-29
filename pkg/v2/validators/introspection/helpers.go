package introspection

import (
	"encoding/base64"
	"fmt"
)

func bearerToken(clientID, clientSecret string) string {
	rawToken := []byte(fmt.Sprintf("%s:%s", clientID, clientSecret))

	return base64.StdEncoding.EncodeToString(rawToken)
}

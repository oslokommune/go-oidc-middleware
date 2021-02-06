package introspection

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
)

func ValidateToken(options IntrospectionValidationOptions) (err error) {
	values := url.Values{}
	values.Add("client_id", options.ClientID)
	values.Add("client_secret", options.ClientSecret)
	values.Add("token", options.Token)

	request, err := http.NewRequest(http.MethodPost, options.IntrospectionURL, strings.NewReader(values.Encode()))
	if err != nil {
		options.Logger.Info("Error creating introspection request")

		return err
	}

	client := http.Client{}

	response, err := client.Do(request)
	if err != nil {
		options.Logger.Info("Error doing introspection request")

		return err
	}

	if response.StatusCode != http.StatusOK {
		options.Logger.WithFields(log.Fields{
			"statusCode": response.StatusCode,
			"status":     response.Status,
		}).Info("Invalid introspection response")

		return errors.New(fmt.Sprintf("error validating token: %d", response.StatusCode))
	}

	return nil
}

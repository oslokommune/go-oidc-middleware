package userinfo

import (
	"net/http"
)

type userinfoValidator struct {
	client   http.Client
	endpoint string
}

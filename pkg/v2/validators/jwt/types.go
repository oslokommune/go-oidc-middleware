package jwt

import "github.com/dgrijalva/jwt-go"

type jwtValidator struct {
	active  bool
	checker func(token *jwt.Token) (interface{}, error)
}

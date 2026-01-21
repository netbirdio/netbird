package auth

import (
	"crypto/subtle"
	"net/http"
)

type BasicAuth struct {
	username, password string
}

func NewBasicAuth(username string, password string) BasicAuth {
	return BasicAuth{
		username: username,
		password: password,
	}
}

func (BasicAuth) Type() Method {
	return MethodBasicAuth
}

func (b BasicAuth) Authenticate(r *http.Request) (string, bool, any) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", false, nil
	}

	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(b.username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(b.password)) == 1

	// If authenticated, then return the username.
	if usernameMatch && passwordMatch {
		return username, false, nil
	}

	return "", false, nil
}

func (b BasicAuth) Middleware(next http.Handler) http.Handler {
	return next
}

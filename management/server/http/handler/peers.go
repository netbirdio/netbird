package handler

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"io"
	"net/http"
	"strings"
)

// Peers is a handler that returns peers of the account
type Peers struct {
}

func NewPeers() *Peers {
	return &Peers{}
}

func (h *Peers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// since we are here it means that JWT validation was successful in the middleware
	// therefore we can get parsed user token from the request context
	token := r.Context().Value("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	name := claims["sub"]
	w.WriteHeader(200)
	_, err := io.Copy(w, strings.NewReader(fmt.Sprintf("{\"name\":\"%v\"}", name)))
	if err != nil {
		return

	}
}

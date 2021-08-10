package handler

import (
	"fmt"
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
	name := "whateverdsdsds@gmail.com"
	w.WriteHeader(200)
	_, err := io.Copy(w, strings.NewReader(fmt.Sprintf("{\"name\":\"%v\"}", name)))
	if err != nil {
		return

	}
}

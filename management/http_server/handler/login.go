package handler

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/gorilla/sessions"
	"github.com/wiretrustee/wiretrustee/management/http_server/middleware"
	"net/http"
)

type Login struct {
	authenticator *middleware.Authenticator
	sessionStore  sessions.Store
}

func NewLogin(authenticator *middleware.Authenticator, sessionStore sessions.Store) *Login {
	return &Login{
		authenticator: authenticator,
		sessionStore:  sessionStore,
	}
}

func (h *Login) Handle(w http.ResponseWriter, r *http.Request) {

	// Generate random state
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state := base64.StdEncoding.EncodeToString(b)

	session, err := h.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	url := h.authenticator.Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

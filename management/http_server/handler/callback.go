package handler

import (
	"context"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/wiretrustee/wiretrustee/management/http_server/middleware"
	"log"
	"net/http"
)

type Callback struct {
	authenticator *middleware.Authenticator
	sessionStore  sessions.Store
}

func NewCallback(authenticator *middleware.Authenticator, sessionStore sessions.Store) *Callback {
	return &Callback{
		authenticator: authenticator,
		sessionStore:  sessionStore,
	}
}

// https://wiretrustee.eu.auth0.com/authorize?client_id=cdE0PVSXMFUNqGvvFq9XrWyr3EB23Uu1&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid+profile&state=oAfXxceIT9bmLI%2Bw3GKrtMixfEvh5ZotheBg2cADlTY%3D
func (h *Callback) Handle(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	token, err := h.authenticator.Config.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: h.authenticator.Config.ClientID,
	}

	idToken, err := h.authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), rawIDToken)

	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

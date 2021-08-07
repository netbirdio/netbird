package handler

import (
	"context"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	middleware2 "github.com/wiretrustee/wiretrustee/management/server/http/middleware"
	"log"
	"net/http"
)

// Callback handler used to receive a callback from the identity provider
type Callback struct {
	authenticator *middleware2.Authenticator
	sessionStore  sessions.Store
}

func NewCallback(authenticator *middleware2.Authenticator, sessionStore sessions.Store) *Callback {
	return &Callback{
		authenticator: authenticator,
		sessionStore:  sessionStore,
	}
}

// ServeHTTP checks the user session, verifies the state, verifies the token, stores user profile in a session,
// and in case of the successful auth redirects user to the main page
func (h *Callback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionStore.Get(r, "auth-session")
	if err != nil {
		//todo redirect to the error page stating: "error occurred plz try again later and a link to login"
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		//todo redirect to the error page stating: "error authenticating plz try to login once again"
		//http.Error(w, "invalid state parameter", http.StatusBadRequest)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	token, err := h.authenticator.Config.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		//todo redirect to the error page stating: "error authenticating plz try to login once again"
		//w.WriteHeader(http.StatusUnauthorized)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		//todo redirect to the error page stating: "error occurred plz try again later and a link to login"
		//http.Error(w, "no id_token field in oauth2 token.", http.StatusInternalServerError)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: h.authenticator.Config.ClientID,
	}

	idToken, err := h.authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), rawIDToken)

	if err != nil {
		//todo redirect to the error page stating: "error occurred plz try again later and a link to login"
		//http.Error(w, "failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// get the userInfo from the token
	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		//todo redirect to the error page stating: "error occurred plz try again later and a link to login"
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile

	err = session.Save(r, w)
	if err != nil {
		//todo redirect to the error page stating: "error occurred plz try again later and a link to login"
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// redirect to logged in page
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

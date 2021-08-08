package handler

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/gorilla/sessions"
	middleware2 "github.com/wiretrustee/wiretrustee/management/server/http/middleware"
	"io/fs"
	"net/http"
)

// Login handler used to login a user
type Login struct {
	authenticator *middleware2.Authenticator
	sessionStore  sessions.Store
	sessionMaxAge int
	sessionDomain string
}

func NewLogin(authenticator *middleware2.Authenticator, sessionStore sessions.Store, sessionMaxAge int, sessionDomain string) *Login {
	return &Login{
		authenticator: authenticator,
		sessionStore:  sessionStore,
		sessionMaxAge: sessionMaxAge,
		sessionDomain: sessionDomain,
	}
}

// ServeHTTP generates a new session state for a user and redirects the user to the auth URL
func (h *Login) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Generate random state
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		//todo redirect to the error page stating: "error occurred plz try again later and a link to login"
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state := base64.StdEncoding.EncodeToString(b)
	session, err := h.sessionStore.Get(r, "auth-session")
	if err != nil {
		switch err.(type) {
		case *fs.PathError:
			// a case when session doesn't exist in the store but was sent by the client in the cookie -> create new session ID
			// it appears that in this case session is always non empty object
			session.ID = "" //nolint
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	session.Values["state"] = state //nolint
	session.Options.MaxAge = h.sessionMaxAge
	session.Options.Secure = true
	session.Options.HttpOnly = true
	session.Options.Domain = h.sessionDomain
	err = session.Save(r, w) //nolint
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	url := h.authenticator.Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

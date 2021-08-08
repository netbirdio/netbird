package handler

import (
	"github.com/gorilla/sessions"
	"net/http"
	"net/url"
)

// Logout logs out a user
type Logout struct {
	authDomain   string
	authClientId string
	sessionStore sessions.Store
}

func NewLogout(authDomain string, authClientId string, sessionStore sessions.Store) *Logout {
	return &Logout{authDomain: authDomain, authClientId: authClientId, sessionStore: sessionStore}
}

// ServeHTTP redirects user to teh auth identity provider logout URL
func (h *Logout) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	session, err := h.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session.Options.MaxAge = -1
	err = h.sessionStore.Save(r, w, session)

	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	logoutUrl, err := url.Parse("https://" + h.authDomain)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logoutUrl.Path += "/v2/logout"
	parameters := url.Values{}

	var scheme string
	if r.TLS == nil {
		scheme = "http"
	} else {
		scheme = "https"
	}

	returnTo, err := url.Parse(scheme + "://" + r.Host + "/login")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", h.authClientId)
	logoutUrl.RawQuery = parameters.Encode()

	http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
}

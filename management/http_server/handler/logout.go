package handler

import (
	"net/http"
	"net/url"
)

// Logout logs out a user
type Logout struct {
	authDomain   string
	authClientId string
}

func NewLogout(authDomain string, authClientId string) *Logout {
	return &Logout{authDomain: authDomain, authClientId: authClientId}
}

// ServeHTTP redirects user to teh auth identity provider logout URL
func (h *Logout) ServeHTTP(w http.ResponseWriter, r *http.Request) {

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

package handler

import (
	"fmt"
	"github.com/gorilla/sessions"
	"io"
	"net/http"
	"strings"
)

// Dashboard is a handler of the main page of the app (dashboard)
type Dashboard struct {
	sessionStore sessions.Store
}

func NewDashboard(sessionStore sessions.Store) *Dashboard {
	return &Dashboard{
		sessionStore: sessionStore,
	}
}

// ServeHTTP verifies if user is authenticated and returns a user dashboard
func (h *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	session, err := h.sessionStore.Get(r, "auth-session")
	if err != nil {
		//todo redirect to the error page stating: "error occurred plz try again later and a link to login"
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	//todo get user account and relevant data to show
	profile := session.Values["profile"].(map[string]interface{})
	name := profile["name"]
	w.WriteHeader(200)
	_, err = io.Copy(w, strings.NewReader("hello "+fmt.Sprintf("%v", name)))
	if err != nil {
		return

	}

	//template.RenderTemplate(w, "dashboard", session.Values["profile"])
}

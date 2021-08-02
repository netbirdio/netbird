package handler

import (
	"fmt"
	"github.com/gorilla/sessions"
	"io"
	"net/http"
	"strings"
)

type Dashboard struct {
	sessionStore sessions.Store
}

func NewDashboard(sessionStore sessions.Store) *Dashboard {
	return &Dashboard{
		sessionStore: sessionStore,
	}
}

func (u *Dashboard) Handle(w http.ResponseWriter, r *http.Request) {

	session, err := u.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	profile := session.Values["profile"].(map[string]interface{})
	name := profile["name"]
	w.WriteHeader(200)
	_, err = io.Copy(w, strings.NewReader("hello "+fmt.Sprintf("%v", name)))
	if err != nil {
		return

	}
	//template.RenderTemplate(w, "dashboard", session.Values["profile"])
}

package middleware

import (
	"github.com/gorilla/sessions"
	"net/http"
)

type AuthMiddleware struct {
	sessionStore sessions.Store
}

func NewAuth(sessionStore sessions.Store) *AuthMiddleware {
	return &AuthMiddleware{sessionStore: sessionStore}
}

func (am *AuthMiddleware) IsAuthenticated(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	session, err := am.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := session.Values["profile"]; !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {
		next(w, r)
	}
}

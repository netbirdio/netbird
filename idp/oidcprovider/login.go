package oidcprovider

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
	log "github.com/sirupsen/logrus"
)

//go:embed templates/*.html
var templateFS embed.FS

// LoginHandler handles the login flow
type LoginHandler struct {
	storage  *OIDCStorage
	callback func(string) string
	tmpl     *template.Template
}

// NewLoginHandler creates a new login handler
func NewLoginHandler(storage *OIDCStorage, callback func(string) string) (*LoginHandler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	return &LoginHandler{
		storage:  storage,
		callback: callback,
		tmpl:     tmpl,
	}, nil
}

// Router returns the login router
func (h *LoginHandler) Router() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.loginPage)
	r.Post("/", h.handleLogin)
	return r
}

// loginPage displays the login form
func (h *LoginHandler) loginPage(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	if authRequestID == "" {
		http.Error(w, "missing auth request ID", http.StatusBadRequest)
		return
	}

	data := map[string]interface{}{
		"AuthRequestID": authRequestID,
		"Error":         "",
	}

	if err := h.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Errorf("failed to render login template: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleLogin processes the login form submission
func (h *LoginHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	authRequestID := r.FormValue("authRequestID")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if authRequestID == "" || username == "" || password == "" {
		data := map[string]interface{}{
			"AuthRequestID": authRequestID,
			"Error":         "Please fill in all fields",
		}
		h.tmpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	// Validate credentials and get user ID
	userID, err := h.storage.CheckUsernamePasswordSimple(username, password)
	if err != nil {
		log.Warnf("login failed for user %s: %v", username, err)
		data := map[string]interface{}{
			"AuthRequestID": authRequestID,
			"Error":         "Invalid username or password",
		}
		h.tmpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	// Complete the auth request
	if err := h.storage.CompleteAuthRequest(r.Context(), authRequestID, userID); err != nil {
		log.Errorf("failed to complete auth request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Redirect to callback
	callbackURL := h.callback(authRequestID)
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

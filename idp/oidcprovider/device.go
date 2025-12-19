package oidcprovider

import (
	"encoding/base64"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	log "github.com/sirupsen/logrus"
)

// DeviceHandler handles the device authorization flow
type DeviceHandler struct {
	storage      *OIDCStorage
	tmpl         *template.Template
	secureCookie *securecookie.SecureCookie
}

// NewDeviceHandler creates a new device handler
func NewDeviceHandler(storage *OIDCStorage) (*DeviceHandler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	// Generate secure cookie keys
	hashKey := securecookie.GenerateRandomKey(32)
	blockKey := securecookie.GenerateRandomKey(32)

	return &DeviceHandler{
		storage:      storage,
		tmpl:         tmpl,
		secureCookie: securecookie.New(hashKey, blockKey),
	}, nil
}

// Router returns the device flow router
func (h *DeviceHandler) Router() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.userCodePage)
	r.Post("/login", h.handleLogin)
	r.Post("/confirm", h.handleConfirm)
	return r
}

// userCodePage displays the user code entry form
func (h *DeviceHandler) userCodePage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")

	data := map[string]interface{}{
		"UserCode": userCode,
		"Error":    "",
		"Step":     "code", // code, login, or confirm
	}

	if userCode != "" {
		// Verify the user code exists
		_, err := h.storage.GetDeviceAuthorizationByUserCode(r.Context(), userCode)
		if err != nil {
			data["Error"] = "Invalid or expired user code"
			data["UserCode"] = ""
		} else {
			data["Step"] = "login"
		}
	}

	if err := h.tmpl.ExecuteTemplate(w, "device.html", data); err != nil {
		log.Errorf("failed to render device template: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleLogin processes the login form on the device flow
func (h *DeviceHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	userCode := r.FormValue("user_code")
	username := r.FormValue("username")
	password := r.FormValue("password")

	data := map[string]interface{}{
		"UserCode": userCode,
		"Error":    "",
		"Step":     "login",
	}

	if userCode == "" || username == "" || password == "" {
		data["Error"] = "Please fill in all fields"
		h.tmpl.ExecuteTemplate(w, "device.html", data)
		return
	}

	// Validate credentials
	userID, err := h.storage.CheckUsernamePasswordSimple(username, password)
	if err != nil {
		log.Warnf("device login failed for user %s: %v", username, err)
		data["Error"] = "Invalid username or password"
		h.tmpl.ExecuteTemplate(w, "device.html", data)
		return
	}

	// Get device authorization info
	authState, err := h.storage.GetDeviceAuthorizationByUserCode(r.Context(), userCode)
	if err != nil {
		data["Error"] = "Invalid or expired user code"
		data["Step"] = "code"
		data["UserCode"] = ""
		h.tmpl.ExecuteTemplate(w, "device.html", data)
		return
	}

	// Set secure cookie with user info for confirmation step
	cookieValue := map[string]string{
		"user_code": userCode,
		"user_id":   userID,
	}

	encoded, err := h.secureCookie.Encode("device_auth", cookieValue)
	if err != nil {
		log.Errorf("failed to encode cookie: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "device_auth",
		Value:    encoded,
		Path:     "/device",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	// Show confirmation page
	data["Step"] = "confirm"
	data["ClientID"] = authState.ClientID
	data["Scopes"] = authState.Scopes
	data["UserID"] = userID

	h.tmpl.ExecuteTemplate(w, "device.html", data)
}

// handleConfirm processes the authorization decision
func (h *DeviceHandler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	// Get values from cookie
	cookie, err := r.Cookie("device_auth")
	if err != nil {
		http.Redirect(w, r, "/device", http.StatusFound)
		return
	}

	var cookieValue map[string]string
	if err := h.secureCookie.Decode("device_auth", cookie.Value, &cookieValue); err != nil {
		http.Redirect(w, r, "/device", http.StatusFound)
		return
	}

	userCode := cookieValue["user_code"]
	userID := cookieValue["user_id"]
	action := r.FormValue("action")

	data := map[string]interface{}{
		"Step": "result",
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "device_auth",
		Value:    "",
		Path:     "/device",
		MaxAge:   -1,
		HttpOnly: true,
	})

	if action == "allow" {
		if err := h.storage.CompleteDeviceAuthorization(r.Context(), userCode, userID); err != nil {
			log.Errorf("failed to complete device authorization: %v", err)
			data["Error"] = "Failed to authorize device"
		} else {
			data["Success"] = true
			data["Message"] = "Device authorized successfully! You can now close this window."
		}
	} else {
		if err := h.storage.DenyDeviceAuthorization(r.Context(), userCode); err != nil {
			log.Errorf("failed to deny device authorization: %v", err)
		}
		data["Success"] = false
		data["Message"] = "Authorization denied. You can close this window."
	}

	h.tmpl.ExecuteTemplate(w, "device.html", data)
}

// GenerateUserCode generates a user-friendly code for device flow
func GenerateUserCode() string {
	// Generate a base20 code (BCDFGHJKLMNPQRSTVWXZ - no vowels to avoid words)
	chars := "BCDFGHJKLMNPQRSTVWXZ"
	b := securecookie.GenerateRandomKey(8)
	result := make([]byte, 8)
	for i := range result {
		result[i] = chars[int(b[i])%len(chars)]
	}
	// Format as XXXX-XXXX
	return string(result[:4]) + "-" + string(result[4:])
}

// GenerateDeviceCode generates a secure device code
func GenerateDeviceCode() string {
	b := securecookie.GenerateRandomKey(32)
	return base64.RawURLEncoding.EncodeToString(b)
}

package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

// PathPrefix is the unique URL prefix for serving the proxy's own web assets.
// Using a distinctive prefix prevents collisions with backend application routes.
const PathPrefix = "/__netbird__"

//go:embed dist/*
var files embed.FS

var (
	webFS   fs.FS
	tmpl    *template.Template
	initErr error
)

func init() {
	webFS, initErr = fs.Sub(files, "dist")
	if initErr != nil {
		return
	}

	var indexHTML []byte
	indexHTML, initErr = fs.ReadFile(webFS, "index.html")
	if initErr != nil {
		return
	}

	tmpl, initErr = template.New("index").Parse(string(indexHTML))
}

// AssetHandler returns middleware that intercepts requests for the proxy's
// own web assets (under PathPrefix) and serves them from the embedded
// filesystem, preventing them from being forwarded to backend services.
func AssetHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, PathPrefix+"/") {
			serveAsset(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveAsset serves a static file from the embedded filesystem.
func serveAsset(w http.ResponseWriter, r *http.Request) {
	if initErr != nil {
		http.Error(w, initErr.Error(), http.StatusInternalServerError)
		return
	}

	// Strip the prefix to get the embedded FS path (e.g. "assets/index.js").
	filePath := strings.TrimPrefix(r.URL.Path, PathPrefix+"/")
	content, err := fs.ReadFile(webFS, filePath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	setContentType(w, filePath)
	w.Write(content) //nolint:errcheck
}

// ServeHTTP serves the web UI. For static assets it serves them directly,
// for other paths it renders the page with the provided data.
// Optional statusCode can be passed to set a custom HTTP status code (default 200).
func ServeHTTP(w http.ResponseWriter, r *http.Request, data any, statusCode ...int) {
	if initErr != nil {
		http.Error(w, initErr.Error(), http.StatusInternalServerError)
		return
	}

	path := r.URL.Path

	// Serve robots.txt
	if path == "/robots.txt" {
		content, err := fs.ReadFile(webFS, "robots.txt")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(content) //nolint:errcheck
		return
	}

	// Serve static assets directly (handles requests that reach here
	// via auth middleware calling ServeHTTP for unauthenticated requests).
	if strings.HasPrefix(path, PathPrefix+"/") {
		serveAsset(w, r)
		return
	}

	// Render the page with data
	dataJSON, _ := json.Marshal(data) //nolint:errcheck

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct {
		Data template.JS
	}{
		Data: template.JS(dataJSON), //nolint:gosec
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if len(statusCode) > 0 {
		w.WriteHeader(statusCode[0])
	}
	w.Write(buf.Bytes()) //nolint:errcheck
}

func setContentType(w http.ResponseWriter, filePath string) {
	switch filepath.Ext(filePath) {
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".ttf":
		w.Header().Set("Content-Type", "font/ttf")
	case ".woff":
		w.Header().Set("Content-Type", "font/woff")
	case ".woff2":
		w.Header().Set("Content-Type", "font/woff2")
	case ".ico":
		w.Header().Set("Content-Type", "image/x-icon")
	}
}

// ErrorStatus represents the connection status for each component in the error page.
type ErrorStatus struct {
	Proxy       bool
	Destination bool
}

// ServeErrorPage renders a user-friendly error page with the given details.
func ServeErrorPage(w http.ResponseWriter, r *http.Request, code int, title, message, requestID string, status ErrorStatus) {
	ServeHTTP(w, r, map[string]any{
		"page": "error",
		"error": map[string]any{
			"code":        code,
			"title":       title,
			"message":     message,
			"proxy":       status.Proxy,
			"destination": status.Destination,
			"requestId":   requestID,
		},
	}, code)
}

// ServeAccessDeniedPage renders a simple access denied page without the connection status graph.
func ServeAccessDeniedPage(w http.ResponseWriter, r *http.Request, code int, title, message, requestID string) {
	ServeHTTP(w, r, map[string]any{
		"page": "error",
		"error": map[string]any{
			"code":      code,
			"title":     title,
			"message":   message,
			"requestId": requestID,
			"simple":    true,
			"retryUrl":  stripAuthParams(r.URL),
		},
	}, code)
}

// stripAuthParams returns the request URI with auth-related query parameters removed.
func stripAuthParams(u *url.URL) string {
	q := u.Query()
	q.Del("session_token")
	q.Del("error")
	q.Del("error_description")
	clean := *u
	clean.RawQuery = q.Encode()
	return clean.RequestURI()
}

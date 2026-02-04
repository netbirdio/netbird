package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

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
		w.Write(content)
		return
	}

	// Serve static assets directly
	if strings.HasPrefix(path, "/assets/") {
		filePath := strings.TrimPrefix(path, "/")
		content, err := fs.ReadFile(webFS, filePath)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

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

		w.Write(content)
		return
	}

	// Render the page with data
	dataJSON, _ := json.Marshal(data)

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct {
		Data template.JS
	}{
		Data: template.JS(dataJSON),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if len(statusCode) > 0 {
		w.WriteHeader(statusCode[0])
	}
	w.Write(buf.Bytes())
}

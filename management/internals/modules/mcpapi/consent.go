package mcpapi

import (
	"embed"
	"html/template"
	"net/http"

	log "github.com/sirupsen/logrus"
)

//go:embed templates/*.html
var templateFiles embed.FS

var (
	consentTemplate = parsePage("consent.html")
	errorTemplate   = parsePage("error.html")
)

// parsePage pairs a page with the shared layout. Each page gets its own set because every
// page defines the same blocks.
func parsePage(name string) *template.Template {
	funcs := template.FuncMap{"armScript": func() template.JS { return armScript }}
	return template.Must(template.New(name).Funcs(funcs).ParseFS(templateFiles, "templates/layout.html", "templates/"+name))
}

// armScript keeps the approve button disabled until the page sees the pointer move, a key
// press or a tap, and briefly after. A window opened under a mouse that keeps clicking, as
// in a double-click, cannot take those clicks. Without scripts the button stays usable.
const armScript = `(function(){var b=document.getElementById("approve"),armed=false;b.disabled=true;` +
	`function arm(){if(armed)return;armed=true;setTimeout(function(){b.disabled=false},600)}` +
	`addEventListener("pointermove",arm);addEventListener("keydown",arm);` +
	`addEventListener("pointerdown",function(e){if(e.pointerType!=="mouse")arm()})})();`

type consentPage struct {
	ClientName     string
	RedirectHost   string
	Loopback       bool
	WriteRequested bool
	Request        string
	Action         string
	Nonce          string
}

// pageHeaders keep the pages out of caches and frames, so the consent buttons cannot be
// clickjacked from another site. Only a script carrying scriptNonce may run.
func pageHeaders(w http.ResponseWriter, scriptNonce string) {
	scripts := ""
	if scriptNonce != "" {
		scripts = "; script-src 'nonce-" + scriptNonce + "'"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"+scripts)
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func renderConsent(w http.ResponseWriter, page consentPage) {
	page.Nonce = randomToken()
	pageHeaders(w, page.Nonce)
	if err := consentTemplate.ExecuteTemplate(w, "layout", page); err != nil {
		log.Debugf("failed to render MCP consent page: %v", err)
	}
}

func renderError(w http.ResponseWriter, status int, message string) {
	pageHeaders(w, "")
	w.WriteHeader(status)
	if err := errorTemplate.ExecuteTemplate(w, "layout", message); err != nil {
		log.Debugf("failed to render MCP error page: %v", err)
	}
}

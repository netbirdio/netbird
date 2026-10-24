package mcpapi

import (
	"html/template"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const pageStyle = `
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f6f8;color:#1c1e21}
main{max-width:440px;margin:10vh auto;padding:32px;background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.12)}
h1{font-size:20px;margin:0 0 16px}p{line-height:1.5;margin:0 0 12px}
.warn{background:#fff6e5;border:1px solid #f0c36d;border-radius:8px;padding:10px 12px}
label{display:block;margin:8px 0}.actions{display:flex;gap:12px;margin-top:20px}
button{flex:1;padding:10px;border-radius:8px;border:1px solid #c9ccd1;background:#fff;font-size:15px;cursor:pointer}
button.primary{background:#f68330;border-color:#f68330;color:#fff}
button:disabled{opacity:.6;cursor:default}
@media (prefers-color-scheme:dark){body{background:#18191b;color:#e4e6eb}main{background:#242526}button{background:#3a3b3c;color:#e4e6eb;border-color:#4e4f50}.warn{background:#3a2f12;border-color:#8a6d1f}}`

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize {{.ClientName}} - NetBird</title><style>` + pageStyle + `</style></head>
<body><main>
<h1>Allow {{.ClientName}} to access NetBird?</h1>
<p>It will be able to use the NetBird management API as you, limited to what your role allows.</p>
<p>After you sign in you will be sent back to <strong>{{.RedirectHost}}</strong>.</p>
{{if .Loopback}}<p class="warn">This is an application on your own computer. Continue only if you started this connection yourself just now.</p>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="request" value="{{.Request}}">
<label><input type="checkbox" checked disabled> Read your NetBird configuration</label>
{{if .WriteRequested}}<label><input type="checkbox" name="write" value="on" checked> Make changes: create, update and delete</label>{{end}}
<div class="actions">
<button type="submit" name="action" value="deny">Cancel</button>
<button type="submit" name="action" value="approve" class="primary" id="approve">Continue to sign in</button>
</div>
</form>
<script nonce="{{.Nonce}}">` + armScript + `</script>
</main></body></html>`))

// armScript keeps the approve button disabled until the page sees the pointer move, a key
// press or a tap, and briefly after. A window opened under a mouse that keeps clicking, as
// in a double-click, cannot take those clicks. Without scripts the button stays usable.
const armScript = `(function(){var b=document.getElementById("approve"),armed=false;b.disabled=true;` +
	`function arm(){if(armed)return;armed=true;setTimeout(function(){b.disabled=false},600)}` +
	`addEventListener("pointermove",arm);addEventListener("keydown",arm);` +
	`addEventListener("pointerdown",function(e){if(e.pointerType!=="mouse")arm()})})();`

var errorTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetBird authorization</title><style>` + pageStyle + `</style></head>
<body><main><h1>Authorization failed</h1><p>{{.}}</p></main></body></html>`))

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
	nonce, err := randomToken()
	if err != nil {
		renderError(w, http.StatusInternalServerError, "The page could not be prepared. Try again.")
		return
	}
	page.Nonce = nonce
	pageHeaders(w, nonce)
	if err := consentTemplate.Execute(w, page); err != nil {
		log.Debugf("failed to render MCP consent page: %v", err)
	}
}

func renderError(w http.ResponseWriter, status int, message string) {
	pageHeaders(w, "")
	w.WriteHeader(status)
	if err := errorTemplate.Execute(w, message); err != nil {
		log.Debugf("failed to render MCP error page: %v", err)
	}
}

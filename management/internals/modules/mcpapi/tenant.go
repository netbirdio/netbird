package mcpapi

import (
	"net/http"
	"net/url"
)

// accountParam is the query parameter a deployment that lets users manage other accounts
// switches the request's account by: https://<mgmt>/api/mcp?account=<account id>. Without
// such a middleware nothing switches, and requireTenant refuses any account but the caller's.
const accountParam = "account"

// accountQuery returns the account query of an MCP URL, "?account=<id>", or "".
func accountQuery(r *http.Request) string {
	account := r.URL.Query().Get(accountParam)
	if account == "" {
		return ""
	}
	return "?" + url.Values{accountParam: {account}}.Encode()
}

// canonicalResource reduces an RFC 8707 resource to the scheme, host and path tokens are bound
// to. The account query is allowed and dropped: it picks the account, which is authorized on
// every request, not the server the token is for.
func canonicalResource(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil {
		return "", false
	}
	for key := range u.Query() {
		if key != accountParam {
			return "", false
		}
	}
	u.RawQuery = ""
	u.ForceQuery = false
	return u.String(), true
}

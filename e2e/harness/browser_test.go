//go:build e2e

package harness

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Login flows hand out URLs on the deployment's public address, which only the container
// itself answers on. Browser has to land those requests on the mapped port while keeping
// the public Host header the server builds its redirects from, and keep the cookies that
// tie one step of a login to the next. Both are checkable against a local server.
func TestBrowserReachesPublicURLThroughBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "login", Value: "kept", Path: "/"})
		case "/echo":
			cookie, err := r.Cookie("login")
			if err != nil {
				http.Error(w, "no cookie", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, r.Host+" "+cookie.Value)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := &Combined{BaseURL: server.URL}
	browser, err := c.Browser()
	require.NoError(t, err)

	resp, err := browser.Get(c.PublicURL() + "/set")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the public URL did not reach the base URL")

	resp, err = browser.Get(c.PublicURL() + "/echo")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the cookie was not sent back: %s", body)
	assert.Equal(t, "localhost:8080 kept", string(body), "the request must carry the public host and the cookie")

	resp, err = browser.Get(server.URL + "/set")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "other addresses are dialed as given")
}

// The public URL is where the embedded IdP sends the browser, so it has to be the issuer
// the server is configured with, minus the IdP's own path.
func TestPublicURLMatchesIssuer(t *testing.T) {
	c := &Combined{}
	assert.Equal(t, containerIssuer, c.PublicURL()+"/oauth2", "PublicURL drifted from the configured issuer")
}

func TestHostPort(t *testing.T) {
	for raw, want := range map[string]string{
		"http://localhost:8080": "localhost:8080",
		"http://localhost":      "localhost:80",
		"https://example.test":  "example.test:443",
		"http://[::1]:8080":     "[::1]:8080",
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Equal(t, want, hostPort(u), "dial address of %s", raw)
	}
}

func TestBrowserRejectsBaseURLWithoutHost(t *testing.T) {
	c := &Combined{BaseURL: "not a url"}
	_, err := c.Browser()
	assert.Error(t, err, "a base URL without a host cannot be dialed")
}

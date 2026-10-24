package server

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	dexsql "github.com/netbirdio/dex/storage/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/oauth2"

	"github.com/netbirdio/netbird/management/internals/modules/mcpapi"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	mcpTestOwnerEmail    = "owner@netbird.test"
	mcpTestOwnerPassword = "Netbird-Test-Passw0rd!" //nolint:gosec // throwaway test credential

	// mcpTestClientRedirect is where the test's MCP client registers to receive its
	// authorization code. Nothing listens there: the browser stops at the redirect and the
	// test reads the code from it, as a native client's loopback listener would.
	mcpTestClientRedirectHost = "127.0.0.1:53682"
	mcpTestClientRedirect     = "http://" + mcpTestClientRedirectHost + "/callback"

	mcpTestToolsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
)

var (
	mcpConsentRequestField = regexp.MustCompile(`name="request"\s+value="([^"]*)"`)
	mcpFormAction          = regexp.MustCompile(`<form[^>]*\saction="([^"]*)"`)
	mcpLocalConnectorLink  = regexp.MustCompile(`href="([^"]*/auth/local[^"]*)"`)
)

// mcpTestServer is a management server booted the way a self-hosted deployment with the
// embedded IdP runs it, served on the address its issuer names.
type mcpTestServer struct {
	*BaseServer
	web *httptest.Server
	// base is the issuer without /oauth2: the URL the deployment believes it is served at.
	base    string
	idpFile string
}

// startMCPTestServer boots a BaseServer with the embedded IdP and the MCP environment the
// caller set. The configuration is what management derives from an embedded IdP section and
// nothing else, so a passing test means a self-hosted deployment needs no other setting.
func startMCPTestServer(t *testing.T) *mcpTestServer {
	t.Helper()

	// The issuer names the address the test serves on, so the broker reaches Dex's token
	// endpoint and the browser follows redirects between the two as it would in a deployment.
	web := httptest.NewUnstartedServer(nil)
	t.Cleanup(web.Close)
	base := "http://" + web.Listener.Addr().String()
	issuer := base + "/oauth2"

	dir := t.TempDir()
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	idpFile := filepath.Join(dir, "idp.db")

	// HttpConfig is what management/cmd ApplyEmbeddedIdPConfig fills in from the issuer.
	cfg := &nbconfig.Config{
		Datadir:                dir,
		DataStoreEncryptionKey: key,
		StoreConfig:            nbconfig.StoreConfig{Engine: types.SqliteStoreEngine},
		EmbeddedIdP: &idp.EmbeddedIdPConfig{
			Enabled:      true,
			Issuer:       issuer,
			LocalAddress: web.Listener.Addr().String(),
			Storage: idp.EmbeddedStorageConfig{
				Type:   "sqlite3",
				Config: idp.EmbeddedStorageTypeConfig{File: idpFile},
			},
		},
		HttpConfig: &nbconfig.HttpServerConfig{
			AuthIssuer:               issuer,
			AuthAudience:             idp.StaticClientDashboard,
			AuthClientID:             idp.StaticClientDashboard,
			CLIAuthAudience:          idp.StaticClientCLI,
			AuthUserIDClaim:          "sub",
			AuthKeysLocation:         issuer + "/keys",
			OIDCConfigEndpoint:       issuer + "/.well-known/openid-configuration",
			IdpSignKeyRefreshEnabled: true,
			AuthCallbackURL:          base + types.ProxyCallbackEndpointFull,
		},
	}

	s := NewServer(&Config{
		NbConfig:                    cfg,
		DNSDomain:                   DefaultSelfHostedDomain,
		MgmtSingleAccModeDomain:     DefaultSelfHostedDomain,
		DisableLegacyManagementPort: true,
		DisableMetrics:              true,
		DisableGeoliteUpdate:        true,
		UserDeleteFromIDPEnabled:    true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	appMetrics, err := telemetry.NewAppMetricsWithMeter(ctx, noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)
	Inject[telemetry.AppMetrics](s, appMetrics)
	Inject[geolocation.Geolocation](s, &geolocation.Mock{})

	require.NoError(t, s.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, s.Stop()) })

	// The MCP endpoint itself is mounted separately. A stand-in at its path shows which user
	// a request to it authenticates as, after the API auth middleware the broker wraps.
	s.ApiRouter().HandleFunc(mcpapi.Path, func(w http.ResponseWriter, r *http.Request) {
		userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"user": userAuth.UserId, "account": userAuth.AccountId})
	}).Methods(http.MethodPost)

	// The same root handler Start serves: /oauth2 goes to Dex, everything else to the API.
	web.Config.Handler = s.handlerFunc(ctx, s.GRPCServer(), s.APIHandler(), s.IDPHandler(), s.Metrics().GetMeter())
	web.Start()

	return &mcpTestServer{BaseServer: s, web: web, base: base, idpFile: idpFile}
}

// setMCPTestEnv pins the environment the MCP wiring reads, so the host's own cannot leak in.
func setMCPTestEnv(t *testing.T, enabled string) {
	t.Helper()
	t.Setenv(mcpapi.EnvEnabled, enabled)
	t.Setenv(mcpapi.EnvOAuthKey, "")
	t.Setenv(nbcache.RedisStoreEnvVar, "")
	t.Setenv("NB_IDP_CACHE_REDIS_ADDRESS", "")
	t.Setenv(geolocationDisabledKey, "")
}

// reply is a response read to the end and closed.
type reply struct {
	StatusCode int
	Header     http.Header
	URL        *url.URL
}

func readReply(t *testing.T, resp *http.Response) (reply, string) {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{StatusCode: resp.StatusCode, Header: resp.Header, URL: resp.Request.URL}, string(data)
}

// request sends a request to the server and returns the response with its body read.
func (m *mcpTestServer) request(t *testing.T, method, path, body string, header http.Header) (reply, string) {
	t.Helper()
	req, err := http.NewRequest(method, m.base+path, strings.NewReader(body))
	require.NoError(t, err)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := m.web.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return readReply(t, resp)
}

// setupOwner creates the instance owner through /api/setup, the way the dashboard's first
// run does, and returns its user ID.
func (m *mcpTestServer) setupOwner(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(api.SetupRequest{Email: mcpTestOwnerEmail, Password: mcpTestOwnerPassword, Name: "Owner"})
	require.NoError(t, err)
	resp, data := m.request(t, http.MethodPost, "/api/setup", string(body), http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup: %s", data)

	var setup api.SetupResponse
	require.NoError(t, json.Unmarshal([]byte(data), &setup))
	return setup.UserId
}

// dexRedirectURIs reads a client's redirect URIs from the embedded IdP's own storage, the
// list Dex checks an authorization request against.
func dexRedirectURIs(t *testing.T, file, clientID string) []string {
	t.Helper()
	st, err := (&dexsql.SQLite3{File: file}).Open(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	client, err := st.GetClient(context.Background(), clientID)
	require.NoError(t, err)
	return client.RedirectURIs
}

// mcpBrowser plays the user's browser during an MCP sign-in: it keeps cookies across the
// broker and Dex, and stops at the MCP client's loopback redirect.
func mcpBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Host == mcpTestClientRedirectHost {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}}
}

// browse sends a request through the browser and returns where it ended and the page body.
func browse(t *testing.T, browser *http.Client, method, target string, form url.Values) (reply, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	require.NoError(t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := browser.Do(req)
	require.NoError(t, err, "%s %s", method, target)
	defer func() { _ = resp.Body.Close() }()
	return readReply(t, resp)
}

// pageLink resolves an HTML-escaped link on the page the response answers.
func pageLink(t *testing.T, resp reply, ref string) string {
	t.Helper()
	u, err := resp.URL.Parse(html.UnescapeString(ref))
	require.NoError(t, err)
	return u.String()
}

// signInWithOAuth walks a remote MCP client through the broker as the owner: registration,
// consent with write access, the login at the embedded Dex and the code exchange. It returns
// the broker's access token.
func (m *mcpTestServer) signInWithOAuth(t *testing.T) string {
	t.Helper()
	browser := mcpBrowser(t)

	reg, err := json.Marshal(map[string]any{"client_name": "server-test", "redirect_uris": []string{mcpTestClientRedirect}})
	require.NoError(t, err)
	resp, data := m.request(t, http.MethodPost, "/api/mcp/auth/register", string(reg), http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registration: %s", data)
	var client struct {
		ClientID string `json:"client_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(data), &client))

	verifier := oauth2.GenerateVerifier()
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {mcpTestClientRedirect},
		"scope":                 {"mcp:read mcp:write"},
		"state":                 {"client-state"},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {m.base + "/api" + mcpapi.Path},
	}
	resp, data = browse(t, browser, http.MethodGet, m.base+"/api/mcp/auth/authorize?"+query.Encode(), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "consent page: %s", data)
	field := mcpConsentRequestField.FindStringSubmatch(data)
	require.Len(t, field, 2, "the consent page carries the sealed request")

	// Approving sends the browser to Dex with the broker's callback as redirect_uri. Dex
	// rejects a redirect URI its client does not list, so reaching the login form proves the
	// embedded IdP registered the callback on its own.
	resp, data = browse(t, browser, http.MethodPost, m.base+"/api/mcp/auth/authorize",
		url.Values{"request": {html.UnescapeString(field[1])}, "action": {"approve"}, "write": {"on"}})
	if !strings.Contains(data, `name="password"`) {
		require.Equal(t, http.StatusOK, resp.StatusCode, "Dex refused the broker's login request at %s: %s", resp.URL, data)
		link := mcpLocalConnectorLink.FindStringSubmatch(data)
		require.Len(t, link, 2, "neither a login form nor the local connector at %s", resp.URL)
		resp, data = browse(t, browser, http.MethodGet, pageLink(t, resp, link[1]), nil)
	}
	action := mcpFormAction.FindStringSubmatch(data)
	require.Len(t, action, 2, "Dex shows its login form at %s: %s", resp.URL, data)

	resp, data = browse(t, browser, http.MethodPost, pageLink(t, resp, action[1]),
		url.Values{"login": {mcpTestOwnerEmail}, "password": {mcpTestOwnerPassword}})
	require.Equal(t, http.StatusFound, resp.StatusCode, "the sign-in ends at the client's redirect, at %s: %s", resp.URL, data)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, mcpTestClientRedirectHost, loc.Host, "the broker redirects to the client")
	require.Empty(t, loc.Query().Get("error"), "the broker refused the sign-in: %s", loc.Query().Get("error_description"))
	require.Equal(t, "client-state", loc.Query().Get("state"), "the client's state comes back")
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "the redirect carries an authorization code")

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {mcpTestClientRedirect},
		"client_id":     {client.ClientID},
		"code_verifier": {verifier},
		"resource":      {m.base + "/api" + mcpapi.Path},
	}
	resp, data = m.request(t, http.MethodPost, "/api/mcp/auth/token", tokenForm.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "code exchange: %s", data)
	var tokens struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	require.NoError(t, json.Unmarshal([]byte(data), &tokens))
	require.True(t, strings.HasPrefix(tokens.AccessToken, "nbmcp_"), "the broker issues its own access token")
	assert.ElementsMatch(t, []string{"mcp:read", "mcp:write"}, strings.Fields(tokens.Scope), "write was approved")
	return tokens.AccessToken
}

// TestMCPWithEmbeddedIdP boots management the way a self-hosted deployment with the embedded
// IdP runs it, with nothing but NB_MCP_ENABLED added, and checks the OAuth broker and the
// authentication of its tokens at the MCP endpoint path end to end in-process.
func TestMCPWithEmbeddedIdP(t *testing.T) {
	setMCPTestEnv(t, "true")
	m := startMCPTestServer(t)
	require.NotNil(t, m.MCPBroker(), "the embedded IdP's PKCE flow starts the broker without further configuration")
	ownerID := m.setupOwner(t)

	// A request that claims another host must still get URLs built from the issuer: the
	// shipped proxies do not forward these headers on /api, and a forged one must not move
	// where clients are sent to sign in.
	forged := http.Header{"X-Forwarded-Host": {"attacker.example"}, "X-Forwarded-Proto": {"https"}}

	t.Run("anonymous calls get the challenge built from the issuer", func(t *testing.T) {
		header := http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"}}
		for k, v := range forged {
			header[k] = v
		}
		resp, body := m.request(t, http.MethodPost, "/api"+mcpapi.Path, mcpTestToolsList, header)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the endpoint needs a credential: %s", body)
		assert.Equal(t, `Bearer resource_metadata="`+m.base+`/api/mcp/.well-known/oauth-protected-resource"`,
			resp.Header.Get("WWW-Authenticate"), "the challenge points under /api at the issuer's host")

		resp, _ = m.request(t, http.MethodGet, "/api/users", "", nil)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the REST API still needs a credential")
		assert.Empty(t, resp.Header.Get("WWW-Authenticate"), "the challenge is only added on the MCP endpoint")
	})

	t.Run("discovery documents are built from the issuer", func(t *testing.T) {
		for _, path := range []string{"/api/mcp/.well-known/oauth-protected-resource", mcpapi.ProtectedResourcePath} {
			resp, body := m.request(t, http.MethodGet, path, "", forged)
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s is served without a token: %s", path, body)
			var prm struct {
				Resource             string   `json:"resource"`
				AuthorizationServers []string `json:"authorization_servers"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &prm))
			assert.Equal(t, m.base+"/api/mcp", prm.Resource, "%s names the MCP endpoint at the issuer's host", path)
			assert.Equal(t, []string{m.base + "/api/mcp/auth"}, prm.AuthorizationServers, "%s names the broker as the authorization server", path)
		}

		for _, path := range []string{"/api/mcp/auth/.well-known/openid-configuration", "/.well-known/oauth-authorization-server/api/mcp/auth"} {
			resp, body := m.request(t, http.MethodGet, path, "", forged)
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s is served without a token: %s", path, body)
			var meta struct {
				Issuer                string `json:"issuer"`
				AuthorizationEndpoint string `json:"authorization_endpoint"`
				TokenEndpoint         string `json:"token_endpoint"`
				RegistrationEndpoint  string `json:"registration_endpoint"`
				RevocationEndpoint    string `json:"revocation_endpoint"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &meta))
			assert.Equal(t, m.base+"/api/mcp/auth", meta.Issuer, "%s issuer", path)
			assert.Equal(t, m.base+"/api/mcp/auth/authorize", meta.AuthorizationEndpoint, "%s authorization endpoint", path)
			assert.Equal(t, m.base+"/api/mcp/auth/token", meta.TokenEndpoint, "%s token endpoint", path)
			assert.Equal(t, m.base+"/api/mcp/auth/register", meta.RegistrationEndpoint, "%s registration endpoint", path)
			assert.Equal(t, m.base+"/api/mcp/auth/revoke", meta.RevocationEndpoint, "%s revocation endpoint", path)
			assert.NotContains(t, body, "attacker.example", "%s ignores the forwarded host", path)
		}
	})

	t.Run("the embedded IdP registers the broker's callback", func(t *testing.T) {
		assert.Equal(t, idp.StaticClientCLI, m.OAuthConfigProvider().GetCLIClientID(), "the broker logs users in with the CLI client")
		assert.Contains(t, dexRedirectURIs(t, m.idpFile, idp.StaticClientCLI), m.base+idp.MCPCallbackPath,
			"Dex lists the broker's callback for the client the broker logs in with")

		// Dex enforces that list, which is what makes the OAuth sign-in below prove the
		// registration: an unlisted redirect URI never reaches the login form.
		dexAuthorize := func(redirectURI string) int {
			query := url.Values{"client_id": {idp.StaticClientCLI}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {"openid"}}
			resp, _ := browse(t, mcpBrowser(t), http.MethodGet, m.base+"/oauth2/auth?"+query.Encode(), nil)
			return resp.StatusCode
		}
		assert.Equal(t, http.StatusOK, dexAuthorize(m.base+idp.MCPCallbackPath), "Dex starts a login for the broker's callback")
		assert.Equal(t, http.StatusBadRequest, dexAuthorize(m.base+"/api/mcp/auth/elsewhere"), "Dex refuses an unlisted redirect URI")
	})

	t.Run("an OAuth client signs in at the embedded IdP", func(t *testing.T) {
		access := m.signInWithOAuth(t)

		resp, body := m.request(t, http.MethodPost, "/api"+mcpapi.Path, "{}", http.Header{"Authorization": {"Bearer " + access}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "the broker's token is accepted on the MCP endpoint: %s", body)
		var caller map[string]string
		require.NoError(t, json.Unmarshal([]byte(body), &caller))
		assert.Equal(t, ownerID, caller["user"], "the token acts as the user who signed in at Dex")

		// The broker's tokens are bound to the MCP endpoint. Router wraps the API auth
		// middleware so they reach the broker there; anywhere else they must stay useless.
		resp, _ = m.request(t, http.MethodGet, "/api/users", "", http.Header{"Authorization": {"Bearer " + access}})
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a broker token is refused outside /api/mcp")
	})
}

// TestMCPOffByDefault keeps a deployment that did not opt in exactly as it was: no broker, no
// authorization endpoints and no challenge.
func TestMCPOffByDefault(t *testing.T) {
	setMCPTestEnv(t, "")
	m := startMCPTestServer(t)

	assert.Nil(t, m.MCPBroker(), "no broker without NB_MCP_ENABLED")

	resp, _ := m.request(t, http.MethodPost, "/api"+mcpapi.Path, mcpTestToolsList, http.Header{"Content-Type": {"application/json"}})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the endpoint path takes only the API's own credentials")
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"), "no challenge points at a broker that is not running")
	for _, path := range []string{"/api/mcp/auth/token", "/api/mcp/auth/register"} {
		resp, _ := m.request(t, http.MethodPost, path, "", http.Header{"Content-Type": {"application/json"}})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "POST %s is not routed", path)
	}
	for _, path := range []string{"/api/mcp/.well-known/oauth-protected-resource", mcpapi.ProtectedResourcePath, "/.well-known/oauth-authorization-server/api/mcp/auth"} {
		resp, _ := m.request(t, http.MethodGet, path, "", nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GET %s is not served", path)
	}
}

package server

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/oauth2"

	"github.com/netbirdio/netbird/management/internals/modules/mcpapi"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/instance"
	"github.com/netbirdio/netbird/management/server/metrics"
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
	base string
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

	// The same root handler Start serves: /oauth2 goes to Dex, everything else to the API.
	web.Config.Handler = s.handlerFunc(ctx, s.GRPCServer(), s.APIHandler(), s.IDPHandler(), s.Metrics().GetMeter())
	web.Start()

	return &mcpTestServer{BaseServer: s, web: web, base: base}
}

// setMCPTestEnv pins the environment the MCP wiring reads, so the host's own cannot leak in,
// and lets /api/setup issue the owner's PAT the test calls tools with.
func setMCPTestEnv(t *testing.T, enabled string) {
	t.Helper()
	t.Setenv(mcpapi.EnvEnabled, enabled)
	t.Setenv(mcpapi.EnvTools, "")
	t.Setenv(mcpapi.EnvOAuthKey, "")
	t.Setenv(nbcache.RedisStoreEnvVar, "")
	t.Setenv("NB_IDP_CACHE_REDIS_ADDRESS", "")
	t.Setenv(geolocationDisabledKey, "")
	t.Setenv(instance.SetupPATEnabledEnvKey, "true")
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
// run does, and returns the personal access token setup issues for it.
func (m *mcpTestServer) setupOwner(t *testing.T) string {
	t.Helper()
	createPAT := true
	body, err := json.Marshal(api.SetupRequest{Email: mcpTestOwnerEmail, Password: mcpTestOwnerPassword, Name: "Owner", CreatePat: &createPAT})
	require.NoError(t, err)
	resp, data := m.request(t, http.MethodPost, "/api/setup", string(body), http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup: %s", data)

	var setup api.SetupResponse
	require.NoError(t, json.Unmarshal([]byte(data), &setup))
	require.NotNil(t, setup.PersonalAccessToken, "setup returns a PAT when NB_SETUP_PAT_ENABLED is set")
	return *setup.PersonalAccessToken
}

// connect opens an MCP session that sends authorization on every request, the way a client
// configured with a static credential does.
func (m *mcpTestServer) connect(t *testing.T, authorization string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "server-test", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   m.base + "/api" + mcpapi.Path,
		HTTPClient: &http.Client{Transport: authorizationTransport{authorization: authorization}},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

type authorizationTransport struct {
	authorization string
}

func (a authorizationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", a.authorization)
	return http.DefaultTransport.RoundTrip(r)
}

// callTool runs a tool that must succeed and decodes its JSON result into out.
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, out any) {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	require.Len(t, res.Content, 1, "%s returns one content block", name)
	text, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok, "%s returns text", name)
	require.False(t, res.IsError, "%s failed: %s", name, text.Text)
	require.NoError(t, json.Unmarshal([]byte(text.Text), out), "%s returns JSON", name)
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
// IdP runs it, with nothing but NB_MCP_ENABLED added, and checks the MCP endpoint, the OAuth
// broker and the self-hosted metrics report end to end in-process.
func TestMCPWithEmbeddedIdP(t *testing.T) {
	setMCPTestEnv(t, "true")
	m := startMCPTestServer(t)
	require.NotNil(t, m.MCPBroker(), "the embedded IdP's PKCE flow starts the broker without further configuration")
	pat := m.setupOwner(t)

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
		// Documents from both routers: RFC 9728 and RFC 8414 clients look at the root,
		// while the shipped proxies forward only /api.
		docs := []struct{ path, field, want string }{
			{mcpapi.ProtectedResourcePath, "resource", m.base + "/api/mcp"},
			{"/.well-known/oauth-authorization-server/api/mcp/auth", "issuer", m.base + "/api/mcp/auth"},
			{"/api/mcp/auth/.well-known/openid-configuration", "issuer", m.base + "/api/mcp/auth"},
		}
		for _, doc := range docs {
			resp, body := m.request(t, http.MethodGet, doc.path, "", forged)
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s is served without a token: %s", doc.path, body)
			var fields map[string]any
			require.NoError(t, json.Unmarshal([]byte(body), &fields))
			assert.Equal(t, doc.want, fields[doc.field], "%s names its %s at the issuer's host", doc.path, doc.field)
			assert.NotContains(t, body, "attacker.example", "%s ignores the forwarded host", doc.path)
		}
	})

	t.Run("a personal access token calls tools", func(t *testing.T) {
		session := m.connect(t, "Token "+pat)

		var viaREST api.User
		resp, body := m.request(t, http.MethodGet, "/api/users/current", "", http.Header{"Authorization": {"Token " + pat}})
		require.Equal(t, http.StatusOK, resp.StatusCode, body)
		require.NoError(t, json.Unmarshal([]byte(body), &viaREST))

		var me api.User
		callTool(t, session, "get_current_user", nil, &me)
		assert.Equal(t, viaREST, me, "the tool returns what GET /api/users/current returns")
		assert.Equal(t, mcpTestOwnerEmail, me.Email, "the PAT acts as the owner")
	})

	t.Run("an OAuth client signs in at the embedded IdP", func(t *testing.T) {
		access := m.signInWithOAuth(t)
		session := m.connect(t, "Bearer "+access)

		var me api.User
		callTool(t, session, "get_current_user", nil, &me)
		assert.Equal(t, mcpTestOwnerEmail, me.Email, "the token acts as the user who signed in at Dex")

		// The broker's tokens are bound to the MCP endpoint. Router wraps the API auth
		// middleware so they reach the broker there; anywhere else they must stay useless.
		resp, _ := m.request(t, http.MethodGet, "/api/users", "", http.Header{"Authorization": {"Bearer " + access}})
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a broker token is refused outside /api/mcp")
	})

	t.Run("self-hosted metrics report the endpoint and its use", func(t *testing.T) {
		report := m.mcpMetrics()
		before := report()
		assert.True(t, before.Enabled, "MCP is reported enabled")
		assert.True(t, before.OAuthEnabled, "the broker is reported running")

		session := m.connect(t, "Token "+pat)
		var me api.User
		callTool(t, session, "get_current_user", nil, &me)

		after := report()
		assert.Equal(t, before.ToolCallsLastDay+1, after.ToolCallsLastDay, "a tool call through the handler is counted")
		assert.Equal(t, 1, after.UsersLastDay, "calls with the PAT and the OAuth token are one user")
	})
}

// TestMCPOffByDefault keeps a deployment that did not opt in exactly as it was: no route, no
// broker, no challenge and nothing reported as enabled.
func TestMCPOffByDefault(t *testing.T) {
	setMCPTestEnv(t, "")
	m := startMCPTestServer(t)

	assert.Nil(t, m.MCPBroker(), "no broker without NB_MCP_ENABLED")

	var match mux.RouteMatch
	matched := m.ApiRouter().Match(httptest.NewRequest(http.MethodPost, "/api"+mcpapi.Path, nil), &match)
	assert.False(t, matched && match.MatchErr == nil, "the MCP endpoint is not mounted")

	for _, path := range []string{"/api" + mcpapi.Path, "/api/mcp/auth/token", "/api/mcp/auth/register"} {
		resp, _ := m.request(t, http.MethodPost, path, mcpTestToolsList, http.Header{"Content-Type": {"application/json"}})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "POST %s is not routed", path)
		assert.Empty(t, resp.Header.Get("WWW-Authenticate"), "POST %s carries no challenge", path)
	}
	for _, path := range []string{"/api/mcp/.well-known/oauth-protected-resource", mcpapi.ProtectedResourcePath, "/.well-known/oauth-authorization-server/api/mcp/auth"} {
		resp, _ := m.request(t, http.MethodGet, path, "", nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GET %s is not served", path)
	}

	assert.Equal(t, metrics.MCPMetrics{}, m.mcpMetrics()(), "the metrics report MCP off and unused")
}

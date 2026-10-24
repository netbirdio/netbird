package mcpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	clientCallback = "http://localhost:3118/callback"
	idpCode        = "idp-code"
	idpToken       = "idp-access-token"
)

// fakeIdP plays the identity provider: its authorize endpoint logs the user in at once and
// redirects back, and its token endpoint checks the PKCE exchange the broker makes.
type fakeIdP struct {
	srv *httptest.Server

	mu            sync.Mutex
	authorize     url.Values
	refuse        bool
	tokenRequests int
	// basicSecret, when set, plays an application that takes its secret only in HTTP Basic.
	basicSecret string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authorize = r.URL.Query()
		refuse := f.refuse
		f.mu.Unlock()
		back := url.Values{"state": {r.URL.Query().Get("state")}}
		if refuse {
			back.Set("error", "access_denied")
		} else {
			back.Set("code", idpCode)
		}
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?"+back.Encode(), http.StatusFound)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		f.mu.Lock()
		f.tokenRequests++
		authorize, secret := f.authorize, f.basicSecret
		f.mu.Unlock()
		clientID := r.PostForm.Get("client_id")
		if secret != "" {
			id, presented, _ := r.BasicAuth()
			if id != "upstream-client" || presented != secret {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			clientID = id
		}
		ok := r.PostForm.Get("grant_type") == "authorization_code" &&
			r.PostForm.Get("code") == idpCode &&
			clientID == "upstream-client" &&
			r.PostForm.Get("redirect_uri") == authorize.Get("redirect_uri") &&
			oauth2.S256ChallengeFromVerifier(r.PostForm.Get("code_verifier")) == authorize.Get("code_challenge")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + idpToken + `","token_type":"Bearer"}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type stubIdentity struct{}

func (stubIdentity) ValidateAndParseToken(_ context.Context, value string) (auth.UserAuth, *jwt.Token, error) {
	if value != idpToken {
		return auth.UserAuth{}, nil, errors.New("unknown token")
	}
	return auth.UserAuth{UserId: "user-1", Domain: "example.com", DomainCategory: "private"}, &jwt.Token{}, nil
}

func (stubIdentity) EnsureUserAccessByJWTGroups(_ context.Context, userAuth auth.UserAuth, _ *jwt.Token) (auth.UserAuth, error) {
	return userAuth, nil
}

type stubAccounts struct {
	mu        sync.Mutex
	users     map[string]*types.User
	storeDown bool
}

func (a *stubAccounts) GetAccountIDFromUserAuth(context.Context, auth.UserAuth) (string, string, error) {
	return "account-1", "", nil
}

func (a *stubAccounts) SyncUserJWTGroups(context.Context, auth.UserAuth) error { return nil }

func (a *stubAccounts) GetUserFromUserAuth(ctx context.Context, userAuth auth.UserAuth) (*types.User, error) {
	return a.GetUserByID(ctx, userAuth.UserId)
}

func (a *stubAccounts) GetUserByID(_ context.Context, id string) (*types.User, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.storeDown {
		return nil, status.NewGetUserFromStoreError()
	}
	u, ok := a.users[id]
	if !ok {
		return nil, status.NewUserNotFoundError(id)
	}
	copied := *u
	return &copied, nil
}

func (a *stubAccounts) set(fn func(u *types.User)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a.users["user-1"])
}

type brokerEnv struct {
	t        *testing.T
	idp      *fakeIdP
	broker   *Broker
	accounts *stubAccounts
	grants   GrantStore
	srv      *httptest.Server
	now      time.Time
}

// testRedisEnv points the broker tests at a Redis server, such as redis://127.0.0.1:6379/15,
// instead of the memory store. The grant store tests start one in a container without it.
const testRedisEnv = "NB_MCP_TEST_REDIS_URL"

func newTestGrants(t *testing.T) GrantStore {
	t.Helper()
	redisURL := os.Getenv(testRedisEnv)
	if redisURL == "" {
		return newMemoryGrants()
	}
	grants, err := newRedisGrants(context.Background(), redisURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = grants.client.Close() })
	return grants
}

// newBrokerEnv mounts the broker like BaseServer.Router does: the challenge outermost, then
// a stand-in for the API auth middleware that only lets bypass paths through, wrapped by the
// broker, and an MCP endpoint that echoes the caller it was handed.
func newBrokerEnv(t *testing.T) *brokerEnv {
	t.Helper()
	return newBrokerEnvWith(t, httptest.NewServer, nil)
}

// newBrokerEnvWith serves the env with serve, mounts endpoint as the MCP endpoint when it is
// not nil instead of the echo handler, and lets configure adjust the broker's configuration.
func newBrokerEnvWith(t *testing.T, serve func(http.Handler) *httptest.Server, endpoint http.Handler, configure ...func(*BrokerConfig)) *brokerEnv {
	t.Helper()
	env := &brokerEnv{t: t, idp: newFakeIdP(t), now: time.Unix(1_800_000_000, 0), grants: newTestGrants(t)}
	env.accounts = &stubAccounts{users: map[string]*types.User{"user-1": {Id: "user-1", AccountID: "account-1"}}}

	cfg := BrokerConfig{
		Flow: &FlowConfig{
			ClientID:              "upstream-client",
			Audience:              "https://api.example/",
			AuthorizationEndpoint: env.idp.srv.URL + "/authorize",
			TokenEndpoint:         env.idp.srv.URL + "/oauth/token",
			Scope:                 "openid profile email",
		},
		Secrets:  Secrets{Tokens: []byte("test secret"), Registrations: []byte("test registrations")},
		Grants:   env.grants,
		Identity: stubIdentity{},
		Accounts: env.accounts,
	}
	for _, fn := range configure {
		fn(&cfg)
	}
	broker, err := NewBroker(cfg)
	require.NoError(t, err)
	t.Cleanup(broker.Close)
	broker.now = func() time.Time { return env.now }
	env.broker = broker

	apiAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bypass.ShouldBypass(r.URL.Path, next, w, r) {
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	root := mux.NewRouter()
	root.Use(broker.ChallengeMiddleware())
	root.Use(broker.AuthMiddleware(apiAuth))
	api := root.PathPrefix(apiPrefix).Subrouter()
	require.NoError(t, broker.RegisterEndpoints(root, api))
	echo := func(w http.ResponseWriter, r *http.Request) {
		userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
		require.NoError(t, err)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": userAuth.UserId, "account": userAuth.AccountId, "is_pat": userAuth.IsPAT,
			"write": writeAllowed(r.Context()),
		})
	}
	if endpoint != nil {
		api.Handle(Path, endpoint)
	} else {
		api.HandleFunc(Path, echo)
	}
	api.HandleFunc("/peers", echo)

	env.srv = serve(root)
	t.Cleanup(env.srv.Close)
	return env
}

// client talks to the broker directly, trusting its test certificate when it serves https.
func (e *brokerEnv) client() *http.Client {
	return e.srv.Client()
}

// browser follows redirects between management and the identity provider with cookies, and
// stops at the MCP client's callback, which a real client would be listening on.
func (e *brokerEnv) browser() *http.Client {
	jar, err := cookiejar.New(nil)
	require.NoError(e.t, err)
	return &http.Client{
		Jar:       jar,
		Transport: e.srv.Client().Transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Host == "localhost:3118" || req.URL.Host == "localhost:5555" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (e *brokerEnv) register(redirectURIs ...string) string {
	body, err := json.Marshal(map[string]any{"client_name": "Test <Client>", "redirect_uris": redirectURIs})
	require.NoError(e.t, err)
	resp, err := e.client().Post(e.srv.URL+"/api/mcp/auth/register", "application/json", strings.NewReader(string(body)))
	require.NoError(e.t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(e.t, http.StatusCreated, resp.StatusCode)
	var reg clientRegistrationResponse
	require.NoError(e.t, json.NewDecoder(resp.Body).Decode(&reg))
	return reg.ClientID
}

type authRequest struct {
	clientID    string
	redirectURI string
	verifier    string
	scope       string
	extra       url.Values
}

func (e *brokerEnv) newRequest(clientID string) authRequest {
	return authRequest{clientID: clientID, redirectURI: clientCallback, verifier: oauth2.GenerateVerifier(), scope: "mcp:read mcp:write"}
}

func (e *brokerEnv) authorizeURL(req authRequest) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {req.clientID},
		"redirect_uri":          {req.redirectURI},
		"state":                 {"client-state"},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(req.verifier)},
		"code_challenge_method": {"S256"},
		"scope":                 {req.scope},
		"resource":              {e.srv.URL + "/api/mcp"},
	}
	for k, v := range req.extra {
		q[k] = v
	}
	return e.srv.URL + "/api/mcp/auth/authorize?" + q.Encode()
}

var requestField = regexp.MustCompile(`name="request" value="([^"]+)"`)

// consent opens the consent page and returns its body and the sealed request it carries.
func (e *brokerEnv) consent(browser *http.Client, req authRequest) (string, string) {
	resp, err := browser.Get(e.authorizeURL(req))
	require.NoError(e.t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	require.Equal(e.t, http.StatusOK, resp.StatusCode, string(body))
	m := requestField.FindStringSubmatch(string(body))
	require.Len(e.t, m, 2, "consent page carries the sealed request")
	return string(body), m[1]
}

// decide submits the consent form and returns where the flow finally sent the browser.
func (e *brokerEnv) decide(browser *http.Client, sealed string, form url.Values) *url.URL {
	resp := e.submit(browser, sealed, form, "same-origin")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(e.t, http.StatusFound, resp.StatusCode, "the flow ends with a redirect to the client")
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(e.t, err)
	return loc
}

// submit posts the consent form with the Sec-Fetch-Site value the browser would send.
func (e *brokerEnv) submit(browser *http.Client, sealed string, form url.Values, fetchSite string) *http.Response {
	form.Set("request", sealed)
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/api/mcp/auth/authorize", strings.NewReader(form.Encode()))
	require.NoError(e.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if fetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	resp, err := browser.Do(req)
	require.NoError(e.t, err)
	return resp
}

// login runs the whole browser leg and returns the client's callback URL.
func (e *brokerEnv) login(req authRequest, allowWrite bool) *url.URL {
	browser := e.browser()
	_, sealed := e.consent(browser, req)
	form := url.Values{"action": {"approve"}}
	if allowWrite {
		form.Set("write", "on")
	}
	return e.decide(browser, sealed, form)
}

func (e *brokerEnv) tokenRequest(form url.Values) (int, map[string]any) {
	resp, err := e.client().PostForm(e.srv.URL+"/api/mcp/auth/token", form)
	require.NoError(e.t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	require.NoError(e.t, json.NewDecoder(resp.Body).Decode(&out))
	return resp.StatusCode, out
}

func (e *brokerEnv) exchange(req authRequest, code string) (int, map[string]any) {
	return e.tokenRequest(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {req.clientID},
		"redirect_uri":  {req.redirectURI},
		"code_verifier": {req.verifier},
		"resource":      {e.srv.URL + "/api/mcp"},
	})
}

// mcpResult is what a call to the stand-in MCP endpoint returned.
type mcpResult struct {
	status    int
	challenge string
	caller    map[string]any
}

func (e *brokerEnv) callMCP(path, token string, mutate func(*http.Request)) mcpResult {
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader("{}"))
	require.NoError(e.t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if mutate != nil {
		mutate(req)
	}
	resp, err := e.client().Do(req)
	require.NoError(e.t, err)
	defer func() { _ = resp.Body.Close() }()
	out := mcpResult{status: resp.StatusCode, challenge: resp.Header.Get("WWW-Authenticate")}
	_ = json.NewDecoder(resp.Body).Decode(&out.caller)
	return out
}

func TestBrokerFullLogin(t *testing.T) {
	env := newBrokerEnv(t)
	clientID := env.register(clientCallback)
	req := env.newRequest(clientID)

	browser := env.browser()
	page, sealed := env.consent(browser, req)
	assert.Contains(t, page, "Allow Test &lt;Client&gt; to access NetBird?", "the client is named, HTML-escaped")
	assert.Contains(t, page, "localhost:3118", "the redirect host is shown")
	assert.Contains(t, page, "application on your own computer", "loopback clients get a warning")

	back := env.decide(browser, sealed, url.Values{"action": {"approve"}, "write": {"on"}})
	assert.Equal(t, "localhost:3118", back.Host)
	assert.Equal(t, "client-state", back.Query().Get("state"))
	assert.Equal(t, env.srv.URL+"/api/mcp/auth", back.Query().Get("iss"), "RFC 9207 issuer is the broker")
	code := back.Query().Get("code")
	require.NotEmpty(t, code)

	// The identity provider was asked for a login only, with the broker's own callback and audience.
	env.idp.mu.Lock()
	upstream := env.idp.authorize
	env.idp.mu.Unlock()
	assert.Equal(t, "upstream-client", upstream.Get("client_id"))
	assert.Equal(t, env.srv.URL+"/api/mcp/auth/callback", upstream.Get("redirect_uri"))
	assert.Equal(t, "https://api.example/", upstream.Get("audience"))
	assert.Equal(t, "S256", upstream.Get("code_challenge_method"))

	status, tokens := env.exchange(req, code)
	require.Equal(t, http.StatusOK, status, tokens)
	assert.Equal(t, "Bearer", tokens["token_type"])
	assert.Equal(t, float64(3600), tokens["expires_in"])
	assert.Equal(t, "mcp:read mcp:write", tokens["scope"])
	access := tokens["access_token"].(string)
	assert.True(t, strings.HasPrefix(access, accessTokenPrefix))

	res := env.callMCP("/api/mcp", access, nil)
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, "user-1", res.caller["user"])
	assert.Equal(t, "account-1", res.caller["account"])
	assert.Equal(t, true, res.caller["write"])

	t.Run("token is bound to the MCP endpoint", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/peers", access, nil).status, "an MCP token is not an API token")
		otherHost := env.callMCP("/api/mcp", access, func(r *http.Request) { r.Host = "other.example" })
		assert.Equal(t, http.StatusUnauthorized, otherHost.status, "a token for one host is not valid on another")
	})

	t.Run("refresh issues a working token", func(t *testing.T) {
		status, refreshed := env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID},
		})
		require.Equal(t, http.StatusOK, status, refreshed)
		assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", refreshed["access_token"].(string), nil).status)

		status, out := env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {env.register(clientCallback)},
		})
		assert.Equal(t, http.StatusBadRequest, status, "another client cannot use the refresh token")
		assert.Equal(t, "invalid_grant", out["error"])

		status, out = env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID},
			"resource": {"https://elsewhere.example/api/mcp"},
		})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", out["error"], "every refresh failure is invalid_grant, the error SDKs recover from")
	})

	t.Run("a refresh token is not an access token", func(t *testing.T) {
		refresh := tokens["refresh_token"].(string)
		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", accessTokenPrefix+strings.TrimPrefix(refresh, refreshTokenPrefix), nil).status)
	})

	t.Run("expired access token is refused with a challenge", func(t *testing.T) {
		env.now = env.now.Add(accessTokenTTL + time.Second)
		defer func() { env.now = env.now.Add(-accessTokenTTL - time.Second) }()
		res := env.callMCP("/api/mcp", access, nil)
		assert.Equal(t, http.StatusUnauthorized, res.status)
		assert.Contains(t, res.challenge, "resource_metadata=")
	})

	t.Run("blocked user loses access at once", func(t *testing.T) {
		env.accounts.set(func(u *types.User) { u.Blocked = true })
		defer env.accounts.set(func(u *types.User) { u.Blocked = false })

		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", access, nil).status)
		status, _ := env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, status, "refresh is refused too")
	})
}

// The identity provider hop authenticates the way `netbird up` does, so a PKCE flow that
// works for agents works here too.
func TestBrokerUpstreamClientAuthentication(t *testing.T) {
	t.Run("a confidential client's secret reaches a provider that takes only HTTP Basic", func(t *testing.T) {
		const secret = "s3cret"
		env := newBrokerEnvWith(t, httptest.NewServer, nil, func(cfg *BrokerConfig) { cfg.ClientSecret = secret })
		env.idp.mu.Lock()
		env.idp.basicSecret = secret
		env.idp.mu.Unlock()
		req := env.newRequest(env.register(clientCallback))

		back := env.login(req, false)
		code := back.Query().Get("code")
		require.NotEmpty(t, code, "the provider accepted the client, got %s", back)
		status, tokens := env.exchange(req, code)
		assert.Equal(t, http.StatusOK, status, tokens)
	})

	t.Run("a public client sends its client id in the form, in one request", func(t *testing.T) {
		env := newBrokerEnv(t)
		req := env.newRequest(env.register(clientCallback))

		back := env.login(req, false)
		assert.NotEmpty(t, back.Query().Get("code"), "the provider accepted the client, got %s", back)
		env.idp.mu.Lock()
		defer env.idp.mu.Unlock()
		assert.Equal(t, 1, env.idp.tokenRequests, "the exchange does not probe for the client authentication method")
	})
}

func TestBrokerReadOnlyConsent(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))

	back := env.login(req, false)
	status, tokens := env.exchange(req, back.Query().Get("code"))
	require.Equal(t, http.StatusOK, status, tokens)
	assert.Equal(t, "mcp:read", tokens["scope"], "write was not ticked")

	assert.Equal(t, false, env.callMCP("/api/mcp", tokens["access_token"].(string), nil).caller["write"])

	readOnly := env.newRequest(req.clientID)
	readOnly.scope = "mcp:read"
	page, _ := env.consent(env.browser(), readOnly)
	assert.NotContains(t, page, `name="write"`, "write is not offered when the client did not ask for it")
}

func TestBrokerCodeRedemptionChecks(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))
	code := env.login(req, true).Query().Get("code")

	wrongVerifier := req
	wrongVerifier.verifier = oauth2.GenerateVerifier()
	status, out := env.exchange(wrongVerifier, code)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", out["error"])

	otherClient := req
	otherClient.clientID = env.register(clientCallback)
	status, out = env.exchange(otherClient, code)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", out["error"])

	otherRedirect := req
	otherRedirect.redirectURI = "http://localhost:3118/elsewhere"
	status, _ = env.exchange(otherRedirect, code)
	assert.Equal(t, http.StatusBadRequest, status)

	status, out = env.tokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {req.clientID},
		"redirect_uri": {req.redirectURI}, "code_verifier": {req.verifier}, "resource": {"https://elsewhere.example/api/mcp"},
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", out["error"])

	env.now = env.now.Add(codeTTL + time.Second)
	status, out = env.exchange(req, code)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", out["error"], "codes expire")

	status, out = env.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "client_id": {req.clientID}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "unsupported_grant_type", out["error"])

	status, out = env.tokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"nbmcpc_forged"},
		"redirect_uri": {req.redirectURI}, "code_verifier": {req.verifier},
	})
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", out["error"], "an unknown client is told to register again")

	status, out = env.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "client_id": {"nbmcpc_forged"}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", out["error"], "a failed refresh always asks the client to sign in again")
}

func TestBrokerKeyChangeSignsOutButKeepsRegistrations(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))
	status, tokens := env.exchange(req, env.login(req, true).Query().Get("code"))
	require.Equal(t, http.StatusOK, status, tokens)

	// NB_MCP_OAUTH_KEY changes: the token key rotates, the registration key does not.
	rotated, err := newSealer([]byte("rotated secret"))
	require.NoError(t, err)
	env.broker.seal = rotated

	res := env.callMCP("/api/mcp", tokens["access_token"].(string), nil)
	assert.Equal(t, http.StatusUnauthorized, res.status, "access tokens are revoked")
	assert.Contains(t, res.challenge, "resource_metadata=")

	status, out := env.tokenRequest(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {req.clientID},
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", out["error"], "refresh tokens are revoked")

	// The client signs in again with the id it already has.
	again := env.newRequest(req.clientID)
	status, tokens = env.exchange(again, env.login(again, true).Query().Get("code"))
	require.Equal(t, http.StatusOK, status, tokens)
	assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", tokens["access_token"].(string), nil).status)
}

func TestBrokerSessionEndsAfterAFixedTime(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))
	status, tokens := env.exchange(req, env.login(req, true).Query().Get("code"))
	require.Equal(t, http.StatusOK, status, tokens)

	refresh := func(token string) (int, map[string]any) {
		return env.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {req.clientID}})
	}

	// Refreshing every day keeps the client working, but never past the end of the session.
	token := tokens["refresh_token"].(string)
	for range 29 {
		env.now = env.now.Add(24 * time.Hour)
		status, out := refresh(token)
		require.Equal(t, http.StatusOK, status, out)
		token = out["refresh_token"].(string)
	}

	env.now = env.now.Add(24*time.Hour - 30*time.Minute)
	status, out := refresh(token)
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, float64(30*60), out["expires_in"], "the last access token ends with the session")
	last := out["access_token"].(string)

	env.now = env.now.Add(30*time.Minute + time.Second)
	status, out = refresh(out["refresh_token"].(string))
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", out["error"], "the session ended thirty days after the login")
	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", last, nil).status)
}

func TestBrokerLoginOverHTTPS(t *testing.T) {
	env := newBrokerEnvWith(t, httptest.NewTLSServer, nil)
	req := env.newRequest(env.register(clientCallback))

	resp, err := env.browser().Get(env.authorizeURL(req))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "__Host-"+consentCookie, cookies[0].Name, "a sibling subdomain cannot set a __Host- cookie")
	assert.Equal(t, "/", cookies[0].Path, "__Host- cookies must use the root path")
	assert.True(t, cookies[0].Secure)

	status, tokens := env.exchange(req, env.login(req, true).Query().Get("code"))
	require.Equal(t, http.StatusOK, status, tokens)
	assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", tokens["access_token"].(string), nil).status)
}

func TestBrokerAuthorizeValidation(t *testing.T) {
	env := newBrokerEnv(t)
	clientID := env.register(clientCallback)

	// get returns the status, headers and cookies of the authorize response, body already closed.
	type authorizeResult struct {
		status  int
		header  http.Header
		cookies []*http.Cookie
	}
	get := func(req authRequest) authorizeResult {
		resp, err := env.browser().Get(env.authorizeURL(req))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return authorizeResult{status: resp.StatusCode, header: resp.Header, cookies: resp.Cookies()}
	}

	t.Run("unknown client gets a page, not a redirect", func(t *testing.T) {
		req := env.newRequest("nbmcpc_forged")
		assert.Equal(t, http.StatusBadRequest, get(req).status)
	})

	t.Run("unregistered redirect gets a page, not a redirect", func(t *testing.T) {
		req := env.newRequest(clientID)
		req.redirectURI = "https://evil.example/callback"
		assert.Equal(t, http.StatusBadRequest, get(req).status)
	})

	t.Run("loopback redirect matches on any port", func(t *testing.T) {
		req := env.newRequest(clientID)
		req.redirectURI = "http://localhost:5555/callback"
		resp := get(req)
		assert.Equal(t, http.StatusOK, resp.status)
		var consentSet bool
		for _, c := range resp.cookies {
			consentSet = consentSet || (c.Name == consentCookie && c.HttpOnly && c.SameSite == http.SameSiteStrictMode)
		}
		assert.True(t, consentSet, "the consent page binds itself to the browser")
		assert.Equal(t, "DENY", resp.header.Get("X-Frame-Options"), "the consent page cannot be framed")
	})

	t.Run("only the page's own script may run", func(t *testing.T) {
		resp, err := env.browser().Get(env.authorizeURL(env.newRequest(clientID)))
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		csp := resp.Header.Get("Content-Security-Policy")
		m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
		require.Len(t, m, 2, "the consent page allows one script by nonce: %s", csp)
		assert.Contains(t, string(body), `<script nonce="`+m[1]+`">`, "the arming script carries the nonce")
		assert.Contains(t, string(body), `id="approve"`)
		assert.NotContains(t, get(env.newRequest("nbmcpc_forged")).header.Get("Content-Security-Policy"), "script-src",
			"error pages run no scripts")
	})

	redirected := func(t *testing.T, req authRequest) url.Values {
		resp := get(req)
		require.Equal(t, http.StatusFound, resp.status)
		loc, err := url.Parse(resp.header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "localhost:3118", loc.Host)
		assert.Equal(t, env.srv.URL+"/api/mcp/auth", loc.Query().Get("iss"))
		return loc.Query()
	}

	t.Run("a malformed request for an https client gets a page, not a redirect", func(t *testing.T) {
		// Anyone can register any https redirect, so redirecting errors there would be an open redirect.
		req := env.newRequest(env.register("https://app.example/callback"))
		req.redirectURI = "https://app.example/callback"
		req.extra = url.Values{"code_challenge_method": {"plain"}}
		resp := get(req)
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Empty(t, resp.header.Get("Location"))
	})

	t.Run("missing PKCE goes back to the client", func(t *testing.T) {
		req := env.newRequest(clientID)
		req.extra = url.Values{"code_challenge_method": {"plain"}}
		assert.Equal(t, "invalid_request", redirected(t, req).Get("error"))
	})

	t.Run("another resource goes back to the client", func(t *testing.T) {
		req := env.newRequest(clientID)
		req.extra = url.Values{"resource": {"https://elsewhere.example/api/mcp"}}
		assert.Equal(t, "invalid_target", redirected(t, req).Get("error"))
	})
}

func TestBrokerConsentDecisions(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))

	t.Run("deny goes back to the client", func(t *testing.T) {
		browser := env.browser()
		_, sealed := env.consent(browser, req)
		back := env.decide(browser, sealed, url.Values{"action": {"deny"}})
		assert.Equal(t, "access_denied", back.Query().Get("error"))
		assert.Equal(t, "client-state", back.Query().Get("state"))
	})

	t.Run("a consent form submitted from another browser is refused", func(t *testing.T) {
		_, sealed := env.consent(env.browser(), req)
		resp, err := env.browser().PostForm(env.srv.URL+"/api/mcp/auth/authorize", url.Values{"request": {sealed}, "action": {"approve"}})
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "the consent cookie binds the decision to the browser that saw the page")
	})

	t.Run("a consent form posted from another site is refused", func(t *testing.T) {
		browser := env.browser()
		_, sealed := env.consent(browser, req)
		for _, site := range []string{"cross-site", "same-site"} {
			resp := env.submit(browser, sealed, url.Values{"action": {"approve"}}, site)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Sec-Fetch-Site %s", site)
		}
	})

	t.Run("a callback without the login cookie is refused", func(t *testing.T) {
		resp, err := env.browser().Get(env.srv.URL + "/api/mcp/auth/callback?code=" + idpCode + "&state=anything")
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("an identity provider refusal goes back to the client", func(t *testing.T) {
		env.idp.mu.Lock()
		env.idp.refuse = true
		env.idp.mu.Unlock()
		defer func() { env.idp.mu.Lock(); env.idp.refuse = false; env.idp.mu.Unlock() }()
		back := env.login(req, true)
		assert.Equal(t, "access_denied", back.Query().Get("error"))
		assert.Empty(t, back.Query().Get("code"))
	})

	t.Run("a blocked user gets no code", func(t *testing.T) {
		env.accounts.set(func(u *types.User) { u.Blocked = true })
		defer env.accounts.set(func(u *types.User) { u.Blocked = false })
		back := env.login(req, true)
		assert.Equal(t, "access_denied", back.Query().Get("error"))
		assert.Empty(t, back.Query().Get("code"))
	})
}

func TestBrokerRegistrationKeepsUsableRedirects(t *testing.T) {
	env := newBrokerEnv(t)

	body := `{"client_name":"Cursor","redirect_uris":["cursor://anysphere.cursor-mcp/oauth/callback","http://localhost:8787/callback"]}`
	resp, err := http.Post(env.srv.URL+"/api/mcp/auth/register", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var reg clientRegistrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&reg))
	assert.Equal(t, []string{"http://localhost:8787/callback"}, reg.RedirectURIs, "the custom scheme is dropped, the loopback kept")
	assert.Equal(t, "none", reg.TokenEndpointAuthMethod)
	assert.True(t, strings.HasPrefix(reg.ClientID, clientIDPrefix))

	// A name cut at the 100-byte limit keeps whole characters, in the response and on the
	// consent page.
	long := strings.Repeat("a", 99) + "é"
	nameBody, err := json.Marshal(map[string]any{"client_name": long, "redirect_uris": []string{clientCallback}})
	require.NoError(t, err)
	resp3, err := http.Post(env.srv.URL+"/api/mcp/auth/register", "application/json", strings.NewReader(string(nameBody)))
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp3.StatusCode)
	var named clientRegistrationResponse
	require.NoError(t, json.NewDecoder(resp3.Body).Decode(&named))
	assert.Equal(t, strings.Repeat("a", 99), named.ClientName, "the response echoes the stored name, cut before the split character")
	page, _ := env.consent(env.browser(), env.newRequest(named.ClientID))
	assert.Contains(t, page, "Allow "+strings.Repeat("a", 99)+" to access")

	resp2, err := http.Post(env.srv.URL+"/api/mcp/auth/register", "application/json", strings.NewReader(`{"redirect_uris":["http://evil.example/cb"]}`))
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode, "a client with no usable redirect is refused")
}

func TestBrokerMetadata(t *testing.T) {
	env := newBrokerEnv(t)

	var meta authorizationServer
	resp, err := http.Get(env.srv.URL + authServerMetadataPath)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	assert.Equal(t, env.srv.URL+"/api/mcp/auth", meta.Issuer)
	assert.Equal(t, env.srv.URL+"/api/mcp/auth/authorize", meta.AuthorizationEndpoint, "management runs the authorize step")
	assert.Equal(t, env.srv.URL+"/api/mcp/auth/token", meta.TokenEndpoint, "management issues the tokens")
	assert.Equal(t, []string{scopeRead, scopeWrite}, meta.ScopesSupported)
	for _, endpoint := range []string{meta.Issuer, meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.RegistrationEndpoint} {
		assert.True(t, strings.HasPrefix(endpoint, env.srv.URL+"/api/mcp/"), "%s sits under the MCP endpoint", endpoint)
	}
	assert.True(t, meta.IssParameterSupported)

	var prm protectedResource
	resp2, err := http.Get(env.srv.URL + ProtectedResourcePath)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&prm))
	assert.Equal(t, env.srv.URL+"/api/mcp", prm.Resource)
	assert.Equal(t, []string{env.srv.URL + "/api/mcp/auth"}, prm.AuthorizationServers)
}

func TestNewBrokerRequiresAFlow(t *testing.T) {
	secrets := Secrets{Tokens: []byte("x"), Registrations: []byte("y")}
	grants := newMemoryGrants()
	_, err := NewBroker(BrokerConfig{Secrets: secrets, Grants: grants, Identity: stubIdentity{}, Accounts: &stubAccounts{}})
	assert.Error(t, err)
	_, err = NewBroker(BrokerConfig{Flow: &FlowConfig{ClientID: "c"}, Secrets: secrets, Grants: grants, Identity: stubIdentity{}, Accounts: &stubAccounts{}})
	assert.Error(t, err, "endpoints are required")
}

func TestNewBrokerValidatesTheBaseURL(t *testing.T) {
	cfg := func(base string) BrokerConfig {
		return BrokerConfig{
			Flow:     &FlowConfig{ClientID: "c", AuthorizationEndpoint: "https://idp/authorize", TokenEndpoint: "https://idp/token"},
			Secrets:  Secrets{Tokens: []byte("x"), Registrations: []byte("y")},
			Grants:   newMemoryGrants(),
			Identity: stubIdentity{},
			Accounts: &stubAccounts{},
			BaseURL:  base,
		}
	}
	for _, bad := range []string{"netbird.example.com", "ftp://netbird.example.com", "https://netbird.example.com/oauth2", "https://netbird.example.com?x=1", "https://user@netbird.example.com"} {
		_, err := NewBroker(cfg(bad))
		assert.Error(t, err, "%q is not a base URL", bad)
	}
	for base, want := range map[string]string{"https://netbird.example.com/": "https://netbird.example.com", "http://localhost:8080": "http://localhost:8080"} {
		b, err := NewBroker(cfg(base))
		require.NoError(t, err, base)
		t.Cleanup(b.Close)
		assert.Equal(t, want, b.base)
	}
}

// With a configured base URL, what a client or a proxy sends in Host and the forwarding
// headers changes none of the URLs the broker hands out.
func TestBrokerBaseURLIgnoresForwardingHeaders(t *testing.T) {
	env := newBrokerEnv(t)
	env.broker.base = "https://netbird.example.com"

	getJSON := func(path string, out any) {
		req, err := http.NewRequest(http.MethodGet, env.srv.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("X-Forwarded-Host", "attacker.example")
		req.Header.Set("X-Forwarded-Proto", "http")
		resp, err := env.client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
	}

	var meta authorizationServer
	getJSON("/api/mcp/auth/.well-known/openid-configuration", &meta)
	assert.Equal(t, "https://netbird.example.com/api/mcp/auth", meta.Issuer)
	assert.Equal(t, "https://netbird.example.com/api/mcp/auth/token", meta.TokenEndpoint)

	var prm protectedResource
	getJSON("/api/mcp/.well-known/oauth-protected-resource", &prm)
	assert.Equal(t, "https://netbird.example.com/api/mcp", prm.Resource)

	req, err := http.NewRequest(http.MethodPost, env.srv.URL+"/api/mcp", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	resp, err := env.client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, `Bearer resource_metadata="https://netbird.example.com/api/mcp/.well-known/oauth-protected-resource"`, resp.Header.Get("WWW-Authenticate"))

	// The login is sent to the identity provider with the callback it has registered. Over
	// https the consent cookie is Secure, which this plain-HTTP test server cannot carry.
	env.broker.base = "http://netbird.example.com"
	browser := env.browser()
	authReq := env.newRequest(env.register(clientCallback))
	authReq.extra = url.Values{"resource": {"http://netbird.example.com/api/mcp"}}
	_, sealed := env.consent(browser, authReq)
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	decided := env.submit(browser, sealed, url.Values{"action": {"approve"}}, "same-origin")
	_ = decided.Body.Close()
	require.Equal(t, http.StatusFound, decided.StatusCode)
	location, err := url.Parse(decided.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "http://netbird.example.com/api/mcp/auth/callback", location.Query().Get("redirect_uri"))
}

// Behind a reverse proxy that forwards only /api, clients find the broker's metadata only at
// its OpenID path-appended form, and the TypeScript MCP SDK validates that document as
// OpenID provider metadata. OpenID Connect Discovery 1.0 section 3 lists the fields it needs.
func TestBrokerMetadataIsValidOpenIDProviderMetadata(t *testing.T) {
	env := newBrokerEnv(t)

	getJSON := func(path string, out any) {
		resp, err := http.Get(env.srv.URL + path)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out), path)
	}

	var meta map[string]any
	getJSON("/api/mcp/auth/.well-known/openid-configuration", &meta)
	for _, field := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"} {
		assert.NotEmpty(t, meta[field], "OpenID provider metadata needs %s", field)
	}
	jwksURI, ok := meta["jwks_uri"].(string)
	require.True(t, ok, "jwks_uri is a URL")
	require.True(t, strings.HasPrefix(jwksURI, env.srv.URL+"/api/"), "the key set is under /api, which the proxy forwards: %s", jwksURI)

	var keys struct {
		Keys []any `json:"keys"`
	}
	getJSON(strings.TrimPrefix(jwksURI, env.srv.URL), &keys)
	assert.NotNil(t, keys.Keys, "the key set is a JSON Web Key Set")
	assert.Empty(t, keys.Keys, "the broker signs nothing a client verifies")
}

// Anyone can mint the login cookie the callback takes, and every callback stores a marker and
// may call the identity provider, so callbacks are limited per client address.
func TestBrokerLimitsCallbacksPerClient(t *testing.T) {
	env := newBrokerEnv(t)
	callback := func(forwardedFor string) int {
		req, err := http.NewRequest(http.MethodGet, env.srv.URL+"/api/mcp/auth/callback?state=x&code=y", nil)
		require.NoError(t, err)
		req.Header.Set("X-Forwarded-For", forwardedFor)
		resp, err := env.client().Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for i := range callbackBurst {
		require.Equal(t, http.StatusBadRequest, callback(fmt.Sprintf("198.51.100.%d", i)), "callback %d without a login cookie is refused, not limited", i)
	}
	assert.Equal(t, http.StatusTooManyRequests, callback("203.0.113.7"),
		"the burst is spent, and an untrusted peer's X-Forwarded-For does not open a new budget")
	assert.NotEmpty(t, env.register(clientCallback), "registration is not limited with the callback")
}

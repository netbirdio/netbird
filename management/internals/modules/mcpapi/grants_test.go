package mcpapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

// session is a logged-in client: its request and the tokens of its latest exchange.
type session struct {
	req     authRequest
	access  string
	refresh string
}

func (e *brokerEnv) signIn() session {
	e.t.Helper()
	req := e.newRequest(e.register(clientCallback))
	status, tokens := e.exchange(req, e.login(req, true).Query().Get("code"))
	require.Equal(e.t, http.StatusOK, status, tokens)
	return session{req: req, access: tokens["access_token"].(string), refresh: tokens["refresh_token"].(string)}
}

func (e *brokerEnv) refreshWith(s session, token string) (int, map[string]any) {
	return e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {s.req.clientID}})
}

func (e *brokerEnv) revokeToken(token, clientID string) int {
	resp, err := e.client().PostForm(e.srv.URL+"/api/mcp/auth/revoke", url.Values{"token": {token}, "client_id": {clientID}})
	require.NoError(e.t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestBrokerCodesAreSingleUse(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))
	code := env.login(req, true).Query().Get("code")

	status, tokens := env.exchange(req, code)
	require.Equal(t, http.StatusOK, status, tokens)

	status, out := env.exchange(req, code)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", out["error"], "a code works once")

	// OAuth 2.1 section 4.1.3: a reused code may have been stolen, so the first session ends too.
	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", tokens["access_token"].(string), nil).status)
	status, _ = env.tokenRequest(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {req.clientID},
	})
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestBrokerRotatesRefreshTokens(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()

	status, second := env.refreshWith(s, s.refresh)
	require.Equal(t, http.StatusOK, status, second)
	assert.NotEqual(t, s.refresh, second["refresh_token"], "each refresh returns a new refresh token")

	t.Run("a repeat within the grace window gets that rotation's tokens", func(t *testing.T) {
		env.now = env.now.Add(refreshGrace / 2)
		status, out := env.refreshWith(s, s.refresh)
		require.Equal(t, http.StatusOK, status, out)
		assert.Equal(t, refreshIDOf(t, env, second["refresh_token"].(string)), refreshIDOf(t, env, out["refresh_token"].(string)),
			"both racing requests end with the same current refresh token")
		assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", second["access_token"].(string), nil).status,
			"two requests racing with one token do not sign the client out")
	})

	t.Run("a replay after the grace window revokes the session", func(t *testing.T) {
		env.now = env.now.Add(refreshGrace)
		status, third := env.refreshWith(s, second["refresh_token"].(string))
		require.Equal(t, http.StatusOK, status, third)
		require.NotEqual(t, refreshIDOf(t, env, second["refresh_token"].(string)), refreshIDOf(t, env, third["refresh_token"].(string)))

		status, out := env.refreshWith(s, s.refresh)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", out["error"])

		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", third["access_token"].(string), nil).status,
			"the legitimate client's tokens end with the session")
		status, _ = env.refreshWith(s, third["refresh_token"].(string))
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

func TestBrokerRevocationEndpoint(t *testing.T) {
	env := newBrokerEnv(t)

	t.Run("a client revokes its own session", func(t *testing.T) {
		s := env.signIn()
		assert.Equal(t, http.StatusOK, env.revokeToken(s.refresh, s.req.clientID))
		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", s.access, nil).status)
		status, _ := env.refreshWith(s, s.refresh)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("an access token revokes the session too", func(t *testing.T) {
		s := env.signIn()
		assert.Equal(t, http.StatusOK, env.revokeToken(s.access, s.req.clientID))
		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", s.access, nil).status)
	})

	t.Run("another client's token is refused and an unknown one changes nothing", func(t *testing.T) {
		s := env.signIn()
		assert.Equal(t, http.StatusBadRequest, env.revokeToken(s.refresh, env.register(clientCallback)))
		assert.Equal(t, http.StatusOK, env.revokeToken("nbmcpr_garbage", s.req.clientID))
		assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", s.access, nil).status, "the session is untouched")
	})

	t.Run("the token alone is enough for a public client", func(t *testing.T) {
		s := env.signIn()
		assert.Equal(t, http.StatusOK, env.revokeToken(s.refresh, ""))
		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", s.access, nil).status)
	})

	t.Run("a request without a token is malformed", func(t *testing.T) {
		resp, err := env.client().PostForm(env.srv.URL+"/api/mcp/auth/revoke", url.Values{})
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestBrokerCallbackIsSingleUse(t *testing.T) {
	env := newBrokerEnv(t)
	req := env.newRequest(env.register(clientCallback))
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Walk the browser leg by hand up to the callback, keeping the login cookie.
	browser := env.browser()
	_, sealed := env.consent(browser, req)
	browser.CheckRedirect = noRedirect.CheckRedirect
	decided := env.submit(browser, sealed, url.Values{"action": {"approve"}}, "same-origin")
	_ = decided.Body.Close()
	require.Equal(t, http.StatusFound, decided.StatusCode)
	var cookie *http.Cookie
	for _, c := range decided.Cookies() {
		if c.Name == loginCookie {
			cookie = c
		}
	}
	require.NotNil(t, cookie)
	atIdP, err := noRedirect.Get(decided.Header.Get("Location"))
	require.NoError(t, err)
	_ = atIdP.Body.Close()
	callbackURL := atIdP.Header.Get("Location")

	callback := func() int {
		r, err := http.NewRequest(http.MethodGet, callbackURL, nil)
		require.NoError(t, err)
		r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		resp, err := noRedirect.Do(r)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	assert.Equal(t, http.StatusFound, callback(), "the first callback completes the sign-in")
	assert.Equal(t, http.StatusBadRequest, callback(), "a replayed callback is refused")
	env.idp.mu.Lock()
	defer env.idp.mu.Unlock()
	assert.Equal(t, 1, env.idp.tokenRequests, "a replay never reaches the identity provider")
}

// faultyGrants fails or holds grant store calls while armed.
type faultyGrants struct {
	GrantStore
	down       atomic.Bool
	failRotate atomic.Bool // fail the next rotation without applying it
	lostReply  atomic.Bool // apply the next rotation but report an error, like a timeout
	holdRotate atomic.Bool // hold the next rotation until release is closed
	entered    chan struct{}
	release    chan struct{}
}

// errDown is what the stores return when Redis does not answer.
var errDown = fmt.Errorf("%w: connection refused", errStoreUnavailable)

func (f *faultyGrants) start(ctx context.Context, codeID string, codeTTL time.Duration, grantID string, record grantRecord, ttl time.Duration) (string, bool, error) {
	if f.down.Load() {
		return "", false, errDown
	}
	return f.GrantStore.start(ctx, codeID, codeTTL, grantID, record, ttl)
}

func (f *faultyGrants) claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if f.down.Load() {
		return false, errDown
	}
	return f.GrantStore.claim(ctx, key, ttl)
}

func (f *faultyGrants) load(ctx context.Context, grantID string) (grantRecord, bool, error) {
	if f.down.Load() {
		return grantRecord{}, false, errDown
	}
	return f.GrantStore.load(ctx, grantID)
}

func (f *faultyGrants) rotate(ctx context.Context, grantID, presented, next string, now time.Time) (rotationOutcome, string, error) {
	switch {
	case f.down.Load(), f.failRotate.CompareAndSwap(true, false):
		return grantGone, "", errDown
	case f.lostReply.CompareAndSwap(true, false):
		_, _, _ = f.GrantStore.rotate(ctx, grantID, presented, next, now)
		return grantGone, "", errDown
	case f.holdRotate.CompareAndSwap(true, false):
		close(f.entered)
		<-f.release
	}
	return f.GrantStore.rotate(ctx, grantID, presented, next, now)
}

func (f *faultyGrants) revoke(ctx context.Context, grantID string) error {
	if f.down.Load() {
		return errDown
	}
	return f.GrantStore.revoke(ctx, grantID)
}

func withFaults(env *brokerEnv) *faultyGrants {
	f := &faultyGrants{GrantStore: env.grants, entered: make(chan struct{}), release: make(chan struct{})}
	env.broker.grants = f
	return f
}

func TestBrokerStoreOutageFailsClosedWithout401(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()
	faults := withFaults(env)
	faults.down.Store(true)

	res := env.callMCP("/api/mcp", s.access, nil)
	assert.Equal(t, http.StatusServiceUnavailable, res.status, "an outage is neither a pass nor a reason to sign in again")

	status, out := env.refreshWith(s, s.refresh)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "temporarily_unavailable", out["error"])

	faults.down.Store(false)
	assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", s.access, nil).status, "the session survives the outage")
}

func TestBrokerRefusesTokensWithoutAGrant(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()
	var g grant
	require.NoError(t, env.broker.seal.open(purposeAccess, accessTokenPrefix, s.access, &g))

	// A token from before grants existed, or one whose grant was never saved.
	g.GrantID = ""
	legacy, err := env.broker.seal.seal(purposeAccess, accessTokenPrefix, g)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", legacy, nil).status)

	g.GrantID = "never-saved"
	unknown, err := env.broker.seal.seal(purposeAccess, accessTokenPrefix, g)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", unknown, nil).status)
}

func TestBrokerTenantURLs(t *testing.T) {
	env := newBrokerEnv(t)
	tenantURL := env.srv.URL + "/api/mcp?account=tenant-1"

	// The challenge on a tenant URL points at metadata that repeats the tenant.
	resp, err := env.client().Post(tenantURL, "application/json", nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	challenge := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, challenge, `/api/mcp/.well-known/oauth-protected-resource?account=tenant-1"`)

	// RFC 9728 section 3.3, as strictly as the Go SDK checks it, at the URL the challenge names
	// and at the well-known location.
	for _, metadataURL := range []string{
		env.srv.URL + "/api/mcp/.well-known/oauth-protected-resource?account=tenant-1",
		env.srv.URL + "/.well-known/oauth-protected-resource/api/mcp?account=tenant-1",
	} {
		prm, err := oauthex.GetProtectedResourceMetadata(context.Background(), metadataURL, tenantURL, env.client())
		require.NoError(t, err, metadataURL)
		assert.Equal(t, tenantURL, prm.Resource)
	}

	req := env.newRequest(env.register(clientCallback))
	req.extra = url.Values{"resource": {tenantURL}}
	back := env.login(req, true)
	require.NotEmpty(t, back.Query().Get("code"), "a tenant resource is this server: %s", back.String())

	status, tokens := env.tokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "client_id": {req.clientID},
		"redirect_uri": {req.redirectURI}, "code_verifier": {req.verifier}, "resource": {tenantURL},
	})
	require.Equal(t, http.StatusOK, status, tokens)
	assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp?account=tenant-1", tokens["access_token"].(string), nil).status)

	other := env.newRequest(req.clientID)
	other.extra = url.Values{"resource": {env.srv.URL + "/api/mcp?debug=1"}}
	resp, err = env.browser().Get(env.authorizeURL(other))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "invalid_target", loc.Query().Get("error"), "any other query is another resource")
}

func TestBrokerKeepsOneRecordPerSession(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()
	var g grant
	require.NoError(t, env.broker.seal.open(purposeRefresh, refreshTokenPrefix, s.refresh, &g))

	token := s.refresh
	for range 5 {
		env.now = env.now.Add(time.Hour)
		status, out := env.refreshWith(s, token)
		require.Equal(t, http.StatusOK, status, out)
		token = out["refresh_token"].(string)
	}
	record, ok, err := env.grants.load(context.Background(), g.GrantID)
	require.NoError(t, err)
	require.True(t, ok)
	var latest grant
	require.NoError(t, env.broker.seal.open(purposeRefresh, refreshTokenPrefix, token, &latest))
	assert.Equal(t, latest.ID, record.Current, "the record tracks the one refresh token that works")
	assert.Equal(t, g.GrantID, latest.GrantID, "rotation keeps the session")
}

func refreshIDOf(t *testing.T, env *brokerEnv, token string) string {
	t.Helper()
	var g grant
	require.NoError(t, env.broker.seal.open(purposeRefresh, refreshTokenPrefix, token, &g))
	return g.ID
}

// refreshInFlight starts a refresh that has loaded its grant and holds it before the rotation
// until the returned function is called.
func refreshInFlight(t *testing.T, env *brokerEnv, s session, token string) (release func() (int, map[string]any)) {
	t.Helper()
	faults := withFaults(env)
	faults.holdRotate.Store(true)
	type result struct {
		status int
		out    map[string]any
	}
	done := make(chan result, 1)
	go func() {
		status, out := env.refreshWith(s, token)
		done <- result{status, out}
	}()
	<-faults.entered
	return func() (int, map[string]any) {
		close(faults.release)
		r := <-done
		return r.status, r.out
	}
}

func TestBrokerRevocationSurvivesARefreshInFlight(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()
	finish := refreshInFlight(t, env, s, s.refresh)

	require.Equal(t, http.StatusOK, env.revokeToken(s.access, s.req.clientID))
	status, out := finish()
	assert.Equal(t, http.StatusBadRequest, status, "the refresh that read the grant before the revocation is refused: %v", out)
	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", s.access, nil).status, "the revoked session stays revoked")
}

func TestBrokerReplayRevocationSurvivesAThiefsRefreshInFlight(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()
	// The thief rotates the stolen token first, then refreshes again while the client
	// presents the stolen one.
	status, stolen := env.refreshWith(s, s.refresh)
	require.Equal(t, http.StatusOK, status)
	env.now = env.now.Add(refreshGrace + time.Second)
	finish := refreshInFlight(t, env, s, stolen["refresh_token"].(string))

	status, _ = env.refreshWith(s, s.refresh)
	require.Equal(t, http.StatusBadRequest, status, "the replay is detected")
	status, out := finish()
	assert.Equal(t, http.StatusBadRequest, status, "the thief's refresh in flight does not bring the session back: %v", out)
	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", stolen["access_token"].(string), nil).status)
}

func TestBrokerRacingRefreshesAllSucceed(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()
	type result struct {
		status int
		out    map[string]any
	}
	const racers = 8
	results := make(chan result, racers)
	for range racers {
		go func() {
			status, out := env.refreshWith(s, s.refresh)
			results <- result{status, out}
		}()
	}
	ids := map[string]bool{}
	for range racers {
		r := <-results
		require.Equal(t, http.StatusOK, r.status, r.out)
		ids[refreshIDOf(t, env, r.out["refresh_token"].(string))] = true
	}
	assert.Len(t, ids, 1, "every racing request ends with the same refresh token")
}

// A client that refreshes in bursts, like one whose parallel calls each find the access token
// expired, refreshes with the token it just got while slower requests still carry the old one.
func TestBrokerRefreshBurstDoesNotChainRotations(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()

	status, first := env.refreshWith(s, s.refresh)
	require.Equal(t, http.StatusOK, status, first)
	gen1 := refreshIDOf(t, env, first["refresh_token"].(string))

	env.now = env.now.Add(refreshGrace / 2)
	status, again := env.refreshWith(s, first["refresh_token"].(string))
	require.Equal(t, http.StatusOK, status, again)
	assert.Equal(t, gen1, refreshIDOf(t, env, again["refresh_token"].(string)), "the new token does not rotate again within the grace window")

	status, straggler := env.refreshWith(s, s.refresh)
	require.Equal(t, http.StatusOK, status, "a slow request with the replaced token is not a replay: %v", straggler)
	assert.Equal(t, gen1, refreshIDOf(t, env, straggler["refresh_token"].(string)))

	env.now = env.now.Add(refreshGrace)
	status, later := env.refreshWith(s, first["refresh_token"].(string))
	require.Equal(t, http.StatusOK, status, later)
	assert.NotEqual(t, gen1, refreshIDOf(t, env, later["refresh_token"].(string)), "after the grace window the current token rotates")
}

func TestBrokerRetryAfterAFailedRotation(t *testing.T) {
	t.Run("the rotation failed", func(t *testing.T) {
		env := newBrokerEnv(t)
		s := env.signIn()
		withFaults(env).failRotate.Store(true)

		status, out := env.refreshWith(s, s.refresh)
		require.Equal(t, http.StatusServiceUnavailable, status, out)
		status, out = env.refreshWith(s, s.refresh)
		assert.Equal(t, http.StatusOK, status, "the retry the 503 asked for rotates: %v", out)
	})

	t.Run("the rotation landed but its reply was lost", func(t *testing.T) {
		env := newBrokerEnv(t)
		s := env.signIn()
		withFaults(env).lostReply.Store(true)

		status, out := env.refreshWith(s, s.refresh)
		require.Equal(t, http.StatusServiceUnavailable, status, out)
		env.now = env.now.Add(time.Second)
		status, out = env.refreshWith(s, s.refresh)
		require.Equal(t, http.StatusOK, status, "the retry gets the rotation that landed: %v", out)
		assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", out["access_token"].(string), nil).status)
	})
}

// Every change to the user behind a session ends it, on the next call and the next refresh,
// and lifting a block or an approval brings it back.
func TestBrokerSessionFollowsTheUser(t *testing.T) {
	cases := []struct {
		name    string
		change  func(u *types.User)
		restore func(u *types.User)
	}{
		{"blocked", func(u *types.User) { u.Blocked = true }, func(u *types.User) { u.Blocked = false }},
		{"pending approval", func(u *types.User) { u.PendingApproval = true }, func(u *types.User) { u.PendingApproval = false }},
		{"moved to another account", func(u *types.User) { u.AccountID = "account-2" }, func(u *types.User) { u.AccountID = "account-1" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newBrokerEnv(t)
			s := env.signIn()

			env.accounts.set(c.change)
			assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", s.access, nil).status, "the next call is refused")
			status, out := env.refreshWith(s, s.refresh)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "invalid_grant", out["error"], "the next refresh is refused")

			env.accounts.set(c.restore)
			assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", s.access, nil).status, "the session is not revoked, only refused while the user is")
		})
	}

	t.Run("deleted", func(t *testing.T) {
		env := newBrokerEnv(t)
		s := env.signIn()
		env.accounts.mu.Lock()
		deleted := env.accounts.users["user-1"]
		delete(env.accounts.users, "user-1")
		env.accounts.mu.Unlock()

		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", s.access, nil).status)
		status, _ := env.refreshWith(s, s.refresh)
		assert.Equal(t, http.StatusBadRequest, status)

		// The same ID added again later is a new user: the old sessions stay dead.
		env.accounts.mu.Lock()
		recreated := *deleted
		recreated.CreatedAt = env.now.Add(time.Hour)
		env.accounts.users["user-1"] = &recreated
		env.accounts.mu.Unlock()
		env.now = env.now.Add(2 * time.Hour)
		assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", s.access, nil).status,
			"a user re-created under the same ID does not inherit the session")
		status, _ = env.refreshWith(s, s.refresh)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("created just before the login", func(t *testing.T) {
		env := newBrokerEnv(t)
		env.accounts.set(func(u *types.User) { u.CreatedAt = env.now.Add(30 * time.Second) })
		s := env.signIn()
		assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", s.access, nil).status,
			"a user created at the login callback, a moment before the code is redeemed, keeps the session")
	})
}

func TestBrokerRefusesATokenForAnotherAccountsGrant(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()
	var g grant
	require.NoError(t, env.broker.seal.open(purposeAccess, accessTokenPrefix, s.access, &g))

	// A token naming another account on a real grant cannot be sealed by anyone without the
	// key; the grant check refuses it anyway.
	g.Identity.AccountID = "account-2"
	forged, err := env.broker.seal.seal(purposeAccess, accessTokenPrefix, g)
	require.NoError(t, err)
	env.accounts.set(func(u *types.User) { u.AccountID = "account-2" })
	assert.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", forged, nil).status)
}

// A database outage is not a verdict on the user: clients get 503 and retry, and keep their
// session, instead of being signed out by 401 or invalid_grant.
func TestBrokerUserStoreOutageFailsClosedWithout401(t *testing.T) {
	env := newBrokerEnv(t)
	s := env.signIn()

	env.accounts.mu.Lock()
	env.accounts.storeDown = true
	env.accounts.mu.Unlock()
	assert.Equal(t, http.StatusServiceUnavailable, env.callMCP("/api/mcp", s.access, nil).status, "a call during the outage is retried")
	status, out := env.refreshWith(s, s.refresh)
	assert.Equal(t, http.StatusServiceUnavailable, status, "a refresh during the outage is retried")
	assert.Equal(t, "temporarily_unavailable", out["error"])

	env.accounts.mu.Lock()
	env.accounts.storeDown = false
	env.accounts.mu.Unlock()
	assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", s.access, nil).status, "the session survives the outage")
	status, out = env.refreshWith(s, s.refresh)
	assert.Equal(t, http.StatusOK, status, "the refresh token survives the outage: %v", out)
}

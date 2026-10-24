//go:build e2e

package mcpe2e

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/netbirdio/netbird/e2e/harness"
)

const (
	// clientRedirectHost and clientRedirect are where the test's MCP client registers to
	// receive its authorization code. Nothing listens there: the browser stops at the
	// redirect and the test reads the code from it, as a native client's loopback listener
	// would.
	clientRedirectHost = "127.0.0.1:53682"
	clientRedirect     = "http://" + clientRedirectHost + "/callback"

	scopeRead  = "mcp:read"
	scopeWrite = "mcp:write"

	// maxBody bounds what the test reads of any response.
	maxBody = 1 << 20
	// maxSignInSteps bounds the pages between the consent decision and the client redirect:
	// at most a connector choice and the login form.
	maxSignInSteps = 4
)

var (
	resourceMetadataPattern = regexp.MustCompile(`resource_metadata="([^"]+)"`)
	formActionPattern       = regexp.MustCompile(`<form[^>]*\saction="([^"]*)"`)
	requestFieldPattern     = regexp.MustCompile(`name="request"\s+value="([^"]*)"`)
	localConnectorPattern   = regexp.MustCompile(`href="([^"]*/auth/local[^"]*)"`)
	inlineBlockPattern      = regexp.MustCompile(`(?is)<(style|script)\b.*?</(style|script)>`)
)

// protectedResource is the RFC 9728 document the 401 challenge points to.
type protectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// authServerMetadata is the part of the broker's RFC 8414 metadata a client relies on.
type authServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	RevocationEndpoint            string   `json:"revocation_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// page is a response the browser ended on, with its body read.
type page struct {
	status int
	header http.Header
	body   string
	// url is the request the response answers, after any redirects were followed.
	url *url.URL
}

// redirectsToClient returns the client redirect when the page is one.
func (p *page) redirectsToClient() (*url.URL, bool) {
	if p.status != http.StatusFound && p.status != http.StatusSeeOther {
		return nil, false
	}
	loc, err := url.Parse(p.header.Get("Location"))
	if err != nil || loc.Host != clientRedirectHost {
		return nil, false
	}
	return loc, true
}

// oauthClient is a remote MCP client signing in through the broker, paired with the
// browser its user signs in with.
type oauthClient struct {
	t        *testing.T
	browser  *http.Client
	resource string
	meta     authServerMetadata
	clientID string
}

// consentStep is an authorization request that reached the consent page.
type consentStep struct {
	page     *page
	request  string
	action   *url.URL
	state    string
	verifier string
}

// newOAuthClient discovers the authorization server from the MCP endpoint's 401, the way
// a client that was only given the endpoint URL does, and registers itself.
func newOAuthClient(ctx context.Context, t *testing.T) *oauthClient {
	t.Helper()
	browser, err := srv.Browser()
	require.NoError(t, err)
	browser.CheckRedirect = stopAtClient

	base := srv.PublicURL()
	endpoint := base + mcpPath
	status, header := probe(ctx, t, browser, endpoint, "")
	require.Equal(t, http.StatusUnauthorized, status, "an MCP call without a credential must be refused")
	challenge := header.Get("WWW-Authenticate")
	m := resourceMetadataPattern.FindStringSubmatch(challenge)
	require.Len(t, m, 2, "the 401 must carry the RFC 9728 resource_metadata pointer, got WWW-Authenticate %q; "+
		"without it the OAuth broker did not start", challenge)
	// Shipped reverse proxies forward only /api and /oauth2 to management, so the pointer has
	// to stay under /api to be reachable.
	assert.Equal(t, endpoint+"/.well-known/oauth-protected-resource", m[1], "challenge points outside /api")

	var resource protectedResource
	getJSON(ctx, t, browser, m[1], &resource)
	require.Equal(t, endpoint, resource.Resource, "the resource must be the endpoint the client connected to")
	require.Len(t, resource.AuthorizationServers, 1, "exactly one authorization server")
	issuer := resource.AuthorizationServers[0]
	assert.Equal(t, base+"/api/mcp/auth", issuer, "management's broker issues the tokens, not the IdP")

	var rootResource protectedResource
	getJSON(ctx, t, browser, base+"/.well-known/oauth-protected-resource/api/mcp", &rootResource)
	assert.Equal(t, resource, rootResource, "the root well-known location serves the same document")

	var meta authServerMetadata
	getJSON(ctx, t, browser, issuer+"/.well-known/openid-configuration", &meta)
	require.Equal(t, issuer, meta.Issuer, "the metadata must name the issuer it was found under")
	assert.Contains(t, meta.CodeChallengeMethodsSupported, "S256", "PKCE with S256 is offered")
	assert.ElementsMatch(t, []string{scopeRead, scopeWrite}, meta.ScopesSupported, "advertised scopes")
	for name, endpointURL := range map[string]string{
		"authorization": meta.AuthorizationEndpoint, "token": meta.TokenEndpoint,
		"registration": meta.RegistrationEndpoint, "revocation": meta.RevocationEndpoint,
	} {
		assert.True(t, strings.HasPrefix(endpointURL, base+"/api/"), "the %s endpoint %q must be under /api", name, endpointURL)
	}

	var rfc8414 authServerMetadata
	getJSON(ctx, t, browser, base+"/.well-known/oauth-authorization-server/api/mcp/auth", &rfc8414)
	assert.Equal(t, meta, rfc8414, "the RFC 8414 location serves the same document")

	c := &oauthClient{t: t, browser: browser, resource: resource.Resource, meta: meta}
	c.register(ctx)
	return c
}

// register performs RFC 7591 dynamic registration as a public client.
func (c *oauthClient) register(ctx context.Context) {
	c.t.Helper()
	body, err := json.Marshal(map[string]any{
		"client_name":                "netbird-e2e",
		"redirect_uris":              []string{clientRedirect},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	require.NoError(c.t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.meta.RegistrationEndpoint, strings.NewReader(string(body)))
	require.NoError(c.t, err)
	req.Header.Set("Content-Type", "application/json")
	p := c.do(req)
	require.Equal(c.t, http.StatusCreated, p.status, "registration: %s", p.body)

	var reg struct {
		ClientID                string   `json:"client_id"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	require.NoError(c.t, json.Unmarshal([]byte(p.body), &reg), "registration: %s", p.body)
	require.NotEmpty(c.t, reg.ClientID, "registration returns a client id")
	assert.Equal(c.t, []string{clientRedirect}, reg.RedirectURIs, "the loopback redirect is kept")
	assert.Equal(c.t, "none", reg.TokenEndpointAuthMethod, "MCP clients are public")
	c.clientID = reg.ClientID
}

// consent starts an authorization request for read and write and returns the consent page
// it lands on.
func (c *oauthClient) consent(ctx context.Context) *consentStep {
	c.t.Helper()
	step := &consentStep{state: uniqueName("state"), verifier: oauth2.GenerateVerifier()}
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.clientID},
		"redirect_uri":          {clientRedirect},
		"scope":                 {scopeRead + " " + scopeWrite},
		"state":                 {step.state},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(step.verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {c.resource},
	}
	step.page = c.get(ctx, c.meta.AuthorizationEndpoint+"?"+query.Encode())
	require.Equal(c.t, http.StatusOK, step.page.status, "consent page: %s", abbreviate(step.page.body))

	m := requestFieldPattern.FindStringSubmatch(step.page.body)
	require.Len(c.t, m, 2, "the consent page carries the sealed request: %s", abbreviate(step.page.body))
	step.request = html.UnescapeString(m[1])
	step.action = c.formAction(step.page)
	assert.Contains(c.t, step.page.body, `name="write"`, "write is offered when the client asks for it")
	return step
}

// authorize runs the whole browser part of the flow: consent, with or without write, then
// sign-in at the embedded IdP as the bootstrapped admin. It returns the authorization code
// and the PKCE verifier that redeems it.
func (c *oauthClient) authorize(ctx context.Context, allowWrite bool) (string, string) {
	c.t.Helper()
	step := c.consent(ctx)
	form := url.Values{"request": {step.request}, "action": {"approve"}}
	if allowWrite {
		form.Set("write", "on")
	}
	// Posted the way a browser posts the consent page's own form.
	decided := c.postForm(ctx, step.action.String(), form, map[string]string{"Sec-Fetch-Site": "same-origin"})
	loc := c.signIn(ctx, decided)

	q := loc.Query()
	require.Empty(c.t, q.Get("error"), "the broker refused the sign-in: %s", q.Get("error_description"))
	assert.Equal(c.t, step.state, q.Get("state"), "the client's state comes back unchanged")
	assert.Equal(c.t, c.meta.Issuer, q.Get("iss"), "RFC 9207 issuer identification")
	require.NotEmpty(c.t, q.Get("code"), "the redirect carries an authorization code")
	return q.Get("code"), step.verifier
}

// signIn follows the identity provider's pages until the flow redirects back to the
// client, submitting the admin's credentials on the login form, and returns that redirect.
func (c *oauthClient) signIn(ctx context.Context, p *page) *url.URL {
	c.t.Helper()
	submitted := false
	for range maxSignInSteps {
		if loc, ok := p.redirectsToClient(); ok {
			return loc
		}
		if strings.Contains(p.body, `name="password"`) {
			// The IdP answers a refused login with the form again, under an error status.
			require.False(c.t, submitted, "the IdP did not accept the admin's credentials at %s (HTTP %d)", p.url, p.status)
			submitted = true
			p = c.postForm(ctx, c.formAction(p).String(), url.Values{
				"login":    {harness.AdminEmail},
				"password": {harness.AdminPassword},
			}, nil)
			continue
		}
		require.Equal(c.t, http.StatusOK, p.status, "unexpected answer at %s: %s", p.url, abbreviate(p.body))
		m := localConnectorPattern.FindStringSubmatch(p.body)
		require.Len(c.t, m, 2, "neither a login form nor the local connector at %s: %s", p.url, abbreviate(p.body))
		p = c.get(ctx, c.resolve(p, m[1]).String())
	}
	require.FailNow(c.t, "sign-in did not finish", "still at %s after %d pages", p.url, maxSignInSteps)
	return nil
}

// codeForm is the token request that redeems an authorization code.
func (c *oauthClient) codeForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {clientRedirect},
		"client_id":     {c.clientID},
		"code_verifier": {verifier},
		"resource":      {c.resource},
	}
}

// refreshForm is the token request that rotates a refresh token.
func (c *oauthClient) refreshForm(refreshToken string) url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.clientID},
		"resource":      {c.resource},
	}
}

// exchange redeems an authorization code and returns the tokens.
func (c *oauthClient) exchange(ctx context.Context, code, verifier string) tokenResponse {
	c.t.Helper()
	status, body := c.tokenRequest(ctx, c.codeForm(code, verifier))
	require.Equal(c.t, http.StatusOK, status, "code exchange: %s", body)
	return decodeTokens(c.t, body)
}

// tokenRequest posts a form to the token endpoint and returns the status and body.
func (c *oauthClient) tokenRequest(ctx context.Context, form url.Values) (int, string) {
	c.t.Helper()
	p := c.postForm(ctx, c.meta.TokenEndpoint, form, nil)
	return p.status, p.body
}

// revoke ends the session a token belongs to.
func (c *oauthClient) revoke(ctx context.Context, token string) {
	c.t.Helper()
	p := c.postForm(ctx, c.meta.RevocationEndpoint, url.Values{"token": {token}, "client_id": {c.clientID}}, nil)
	require.Equal(c.t, http.StatusOK, p.status, "revocation: %s", p.body)
}

// status sends a GET with the given Authorization header and returns the status code.
func (c *oauthClient) status(ctx context.Context, target, authorization string) int {
	c.t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	require.NoError(c.t, err)
	req.Header.Set("Authorization", authorization)
	return c.do(req).status
}

func (c *oauthClient) get(ctx context.Context, target string) *page {
	c.t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	require.NoError(c.t, err)
	return c.do(req)
}

func (c *oauthClient) postForm(ctx context.Context, target string, form url.Values, headers map[string]string) *page {
	c.t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	require.NoError(c.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.do(req)
}

// do sends the request through the browser and reads the page it ends on.
func (c *oauthClient) do(req *http.Request) *page {
	c.t.Helper()
	resp, err := c.browser.Do(req)
	require.NoError(c.t, err, "%s %s", req.Method, req.URL)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	require.NoError(c.t, err, "read %s", req.URL)
	return &page{status: resp.StatusCode, header: resp.Header, body: string(body), url: resp.Request.URL}
}

// formAction returns where the page's form posts to.
func (c *oauthClient) formAction(p *page) *url.URL {
	c.t.Helper()
	m := formActionPattern.FindStringSubmatch(p.body)
	require.Len(c.t, m, 2, "no form at %s: %s", p.url, abbreviate(p.body))
	return c.resolve(p, m[1])
}

// abbreviate keeps failure messages about an HTML page readable: what the page says
// matters, not its inline styles and scripts.
func abbreviate(body string) string {
	const limit = 4 << 10
	body = inlineBlockPattern.ReplaceAllString(body, "")
	body = strings.Join(strings.Fields(body), " ")
	if len(body) <= limit {
		return body
	}
	return body[:limit] + "... (truncated)"
}

// resolve turns an HTML-escaped link on the page into an absolute URL.
func (c *oauthClient) resolve(p *page, ref string) *url.URL {
	c.t.Helper()
	u, err := p.url.Parse(html.UnescapeString(ref))
	require.NoError(c.t, err, "link %q at %s", ref, p.url)
	return u
}

// stopAtClient follows every redirect except the one to the MCP client, which ends the
// browser's part of the flow.
func stopAtClient(req *http.Request, via []*http.Request) error {
	if req.URL.Host == clientRedirectHost {
		return http.ErrUseLastResponse
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

func getJSON(ctx context.Context, t *testing.T, client *http.Client, target string, out any) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err, "GET %s", target)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET %s: %s", target, body)
	require.NoError(t, json.Unmarshal(body, out), "GET %s: %s", target, body)
}

func decodeTokens(t *testing.T, body string) tokenResponse {
	t.Helper()
	var tokens tokenResponse
	require.NoError(t, json.Unmarshal([]byte(body), &tokens), "token response: %s", body)
	require.NotEmpty(t, tokens.AccessToken, "token response carries an access token: %s", body)
	require.NotEmpty(t, tokens.RefreshToken, "token response carries a refresh token: %s", body)
	return tokens
}

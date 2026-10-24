package mcpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/shared/ratelimit"
	"github.com/netbirdio/netbird/trustedproxy"
)

const (
	authorizePath = authPath + "/authorize"
	callbackPath  = authPath + "/callback"
	tokenPath     = authPath + "/token"  //nolint:gosec // an endpoint path, not a credential
	revokePath    = authPath + "/revoke" //nolint:gosec // an endpoint path, not a credential
	jwksPath      = authPath + "/jwks"

	scopeRead  = "mcp:read"
	scopeWrite = "mcp:write"

	clientIDPrefix     = "nbmcpc_"
	codePrefix         = "nbmcpk_"
	accessTokenPrefix  = "nbmcp_"
	refreshTokenPrefix = "nbmcpr_"

	consentCookie = "nb_mcp_consent"
	loginCookie   = "nb_mcp_login"

	accessTokenTTL = time.Hour
	// sessionTTL is how long a login lasts. Refresh tokens expire with the session.
	sessionTTL = 30 * 24 * time.Hour
	codeTTL    = 2 * time.Minute
	consentTTL = 10 * time.Minute
	loginTTL   = 10 * time.Minute

	maxFormBody    = 64 << 10
	maxStateLength = 1024
	maxClientName  = 100
)

// Identity validates the token the identity provider returns after login. The API's auth
// manager satisfies it.
type Identity interface {
	ValidateAndParseToken(ctx context.Context, value string) (auth.UserAuth, *jwt.Token, error)
	EnsureUserAccessByJWTGroups(ctx context.Context, userAuth auth.UserAuth, token *jwt.Token) (auth.UserAuth, error)
}

// Accounts resolves the NetBird user behind a login and re-checks it on every MCP call. The
// account manager satisfies it.
type Accounts interface {
	GetAccountIDFromUserAuth(ctx context.Context, userAuth auth.UserAuth) (string, string, error)
	SyncUserJWTGroups(ctx context.Context, userAuth auth.UserAuth) error
	GetUserFromUserAuth(ctx context.Context, userAuth auth.UserAuth) (*types.User, error)
	GetUserByID(ctx context.Context, id string) (*types.User, error)
}

// Limiter rate limits MCP calls per user. The API rate limiter satisfies it.
type Limiter interface {
	Allow(key string) bool
}

// BrokerConfig configures the MCP authorization server.
type BrokerConfig struct {
	// Flow is the PKCE flow of the identity provider users log in with.
	Flow *FlowConfig
	// ClientSecret is sent to the identity provider's token endpoint when its client is confidential.
	ClientSecret string
	// Secrets seal everything the broker issues; see ResolveSecrets.
	Secrets Secrets
	// Grants holds the sessions; see NewGrantStore.
	Grants   GrantStore
	Identity Identity
	Accounts Accounts
	// Limiter is optional.
	Limiter Limiter
	// HTTPClient is used for the identity provider's token endpoint; nil means a client with a timeout.
	HTTPClient *http.Client
	// TrustedProxies are the reverse proxies whose X-Forwarded-For the callback's rate limit
	// believes. Without them every request counts against the address it came from.
	TrustedProxies []netip.Prefix
	// BaseURL is the scheme and host clients reach management at, such as
	// https://netbird.example.com. Empty takes them from each request and its forwarding
	// headers. Set it when the deployment knows its URL: the issuer, the resource and the
	// callback registered at the identity provider then match it whatever the proxy sends.
	BaseURL string
}

// Broker is the OAuth 2.1 authorization server for the MCP endpoint, in the shape remote
// MCP vendors use: management renders its own consent, sends the user to the identity
// provider only to log in, receives that login on its own callback, and issues its own
// tokens, bound to the MCP endpoint and re-checked against the user on every call.
type Broker struct {
	flow         *FlowConfig
	clientSecret string
	seal         *sealer
	clients      *sealer
	base         string
	grants       GrantStore
	identity     Identity
	accounts     Accounts
	limiter      Limiter
	callbacks    *ratelimit.APIRateLimiter
	http         *http.Client
	now          func() time.Time
	closeOnce    sync.Once
}

// Callbacks per client address. The callback is the one unauthenticated endpoint that
// stores something and calls the identity provider, and anyone can mint the login cookie
// it takes, so it is limited the way the reverse proxy's OAuth callback is.
const (
	callbacksPerMinute = 30
	callbackBurst      = 30
)

// NewBroker validates the configuration and builds the broker.
func NewBroker(cfg BrokerConfig) (*Broker, error) {
	if cfg.Flow == nil || cfg.Flow.ClientID == "" || cfg.Flow.AuthorizationEndpoint == "" || cfg.Flow.TokenEndpoint == "" {
		return nil, errors.New("the PKCE flow needs a client id, an authorization endpoint and a token endpoint")
	}
	if cfg.Identity == nil || cfg.Accounts == nil || cfg.Grants == nil {
		return nil, errors.New("identity, accounts and a grant store are required")
	}
	seal, err := newSealer(cfg.Secrets.Tokens)
	if err != nil {
		return nil, err
	}
	clients, err := newSealer(cfg.Secrets.Registrations)
	if err != nil {
		return nil, err
	}
	base, err := parseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Broker{
		flow:         cfg.Flow,
		clientSecret: cfg.ClientSecret,
		seal:         seal,
		clients:      clients,
		base:         base,
		grants:       cfg.Grants,
		identity:     cfg.Identity,
		accounts:     cfg.Accounts,
		limiter:      cfg.Limiter,
		http:         client,
		now:          time.Now,
		callbacks: ratelimit.NewAPIRateLimiter(&ratelimit.RateLimiterConfig{
			RequestsPerMinute: callbacksPerMinute,
			Burst:             callbackBurst,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
			TrustedProxies:    trustedproxy.FromPrefixes(cfg.TrustedProxies),
		}),
	}, nil
}

// Close stops the callback rate limiter and closes the grant store's connection. It is safe
// to call more than once.
func (b *Broker) Close() {
	b.closeOnce.Do(func() {
		b.callbacks.Stop()
		if closer, ok := b.grants.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				log.Debugf("failed to close the MCP grant store: %v", err)
			}
		}
	})
}

// RegisterEndpoints mounts the discovery documents and the authorization server. Everything
// here is reached before the client holds a token, so all of it bypasses the API auth.
func (b *Broker) RegisterEndpoints(root, api *mux.Router) error {
	paths := []string{
		ProtectedResourcePath, authServerMetadataPath, openIDConfigurationPath,
		apiPrefix + resourceMetadataAPIPath, apiPrefix + openIDConfigurationAPIPath, apiPrefix + registrationPath,
		apiPrefix + authorizePath, apiPrefix + callbackPath, apiPrefix + tokenPath, apiPrefix + revokePath,
		apiPrefix + jwksPath,
	}
	for _, p := range paths {
		if err := bypass.AddBypassPath(p); err != nil {
			return fmt.Errorf("bypass %s: %w", p, err)
		}
	}

	root.HandleFunc(ProtectedResourcePath, b.protectedResource).Methods(http.MethodGet, http.MethodOptions)
	root.HandleFunc(authServerMetadataPath, b.authorizationServer).Methods(http.MethodGet, http.MethodOptions)
	root.HandleFunc(openIDConfigurationPath, b.authorizationServer).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc(openIDConfigurationAPIPath, b.authorizationServer).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc(resourceMetadataAPIPath, b.protectedResource).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc(registrationPath, b.register).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc(authorizePath, b.authorize).Methods(http.MethodGet)
	api.HandleFunc(authorizePath, b.decide).Methods(http.MethodPost)
	api.Handle(callbackPath, b.callbacks.Middleware(http.HandlerFunc(b.callback))).Methods(http.MethodGet)
	api.HandleFunc(tokenPath, b.token).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc(revokePath, b.revoke).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc(jwksPath, b.jwks).Methods(http.MethodGet, http.MethodOptions)
	return nil
}

// parseBaseURL checks a configured base URL is a scheme and host only, and drops a trailing
// slash.
func parseBaseURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("the MCP base URL %q must be a scheme and host, such as https://netbird.example.com", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// baseURL is the scheme and host clients reach management at: the configured one, or the
// one the request came in on.
func (b *Broker) baseURL(r *http.Request) string {
	if b.base != "" {
		return b.base
	}
	return externalBaseURL(r)
}

func (b *Broker) issuerURL(r *http.Request) string {
	return b.baseURL(r) + authIssuerPath
}

func (b *Broker) resourceURL(r *http.Request) string {
	return b.baseURL(r) + apiPrefix + Path
}

// authorizationServer is the RFC 8414 metadata of the broker.
type authorizationServer struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethods     []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IssParameterSupported             bool     `json:"authorization_response_iss_parameter_supported"`
	// Behind a proxy that forwards only /api, MCP clients reach this document only at its
	// OpenID path-appended form, which the TypeScript SDK validates as OpenID provider
	// metadata. That needs these three fields. The broker issues no ID tokens, so its key
	// set is empty.
	JWKSURI                          string   `json:"jwks_uri"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func (b *Broker) authorizationServer(w http.ResponseWriter, r *http.Request) {
	base := b.baseURL(r)
	util.WriteJSONObject(r.Context(), w, authorizationServer{
		Issuer:                            base + authIssuerPath,
		AuthorizationEndpoint:             base + apiPrefix + authorizePath,
		TokenEndpoint:                     base + apiPrefix + tokenPath,
		RegistrationEndpoint:              base + apiPrefix + registrationPath,
		RevocationEndpoint:                base + apiPrefix + revokePath,
		RevocationEndpointAuthMethods:     []string{"none"},
		ScopesSupported:                   []string{scopeRead, scopeWrite},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		IssParameterSupported:             true,
		JWKSURI:                           base + apiPrefix + jwksPath,
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
	})
}

// jwks serves the broker's key set, which is empty: its tokens are sealed, not signed.
func (b *Broker) jwks(w http.ResponseWriter, r *http.Request) {
	util.WriteJSONObject(r.Context(), w, map[string][]any{"keys": {}})
}

func (b *Broker) protectedResource(w http.ResponseWriter, r *http.Request) {
	util.WriteJSONObject(r.Context(), w, protectedResource{
		// RFC 9728 section 3.3: clients compare this with the URL they connected to, so a tenant
		// URL's account query is repeated. The challenge carries it to this document.
		Resource:               b.resourceURL(r) + accountQuery(r),
		AuthorizationServers:   []string{b.issuerURL(r)},
		ScopesSupported:        []string{scopeRead, scopeWrite},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           serverTitle,
	})
}

// clientInfo is what a client id carries: registration is stateless, so the id itself holds
// the redirect URIs the client registered.
type clientInfo struct {
	RedirectURIs []string `json:"r"`
	Name         string   `json:"n,omitempty"`
	IssuedAt     int64    `json:"i"`
}

func (b *Broker) register(w http.ResponseWriter, r *http.Request) {
	var req clientRegistration
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFormBody)).Decode(&req); err != nil {
		writeRegistrationError(w, "invalid_client_metadata", "request body must be a JSON object")
		return
	}
	// Keep only redirect URIs the broker will ever redirect to. Clients such as Cursor list a
	// custom scheme next to a loopback URI; dropping it keeps the client usable through the other.
	var rejected error
	allowed := make([]string, 0, len(req.RedirectURIs))
	for _, raw := range req.RedirectURIs {
		if err := validateRedirectURI(raw); err != nil {
			rejected = err
			continue
		}
		allowed = append(allowed, raw)
	}
	if len(allowed) == 0 {
		description := "redirect_uris is required"
		if rejected != nil {
			description = rejected.Error()
		}
		writeRegistrationError(w, "invalid_redirect_uri", description)
		return
	}
	req.RedirectURIs = allowed
	req.ClientName = truncate(req.ClientName, maxClientName)

	issued := b.now().Unix()
	clientID, err := b.clients.seal(purposeClient, clientIDPrefix, clientInfo{
		RedirectURIs: req.RedirectURIs,
		Name:         req.ClientName,
		IssuedAt:     issued,
	})
	if err != nil {
		log.WithContext(r.Context()).Errorf("seal MCP client id: %v", err)
		util.WriteErrorResponse("internal error", http.StatusInternalServerError, w)
		return
	}

	resp := clientRegistrationResponse{
		clientRegistration:      req,
		ClientID:                clientID,
		ClientIDIssuedAt:        issued,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
	}
	resp.Scope = scopeRead + " " + scopeWrite
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (b *Broker) lookupClient(clientID string) (clientInfo, bool) {
	var c clientInfo
	if err := b.clients.open(purposeClient, clientIDPrefix, clientID, &c); err != nil {
		return clientInfo{}, false
	}
	return c, true
}

// consentRequest carries a validated authorization request from the consent page to the
// decision, sealed into the page and bound to the browser by the consent cookie.
type consentRequest struct {
	ClientKey      string `json:"c"`
	ClientName     string `json:"n,omitempty"`
	RedirectURI    string `json:"r"`
	State          string `json:"s,omitempty"`
	Challenge      string `json:"p"`
	WriteRequested bool   `json:"w"`
	Resource       string `json:"x"`
	Nonce          string `json:"o"`
	Expires        int64  `json:"e"`
}

// authorize validates the client's request and renders the consent page. Until the client
// and its redirect URI are known good, errors are shown here instead of being redirected.
func (b *Broker) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, ok := b.lookupClient(q.Get("client_id"))
	if !ok {
		renderError(w, http.StatusBadRequest, "This application is not registered with NetBird. Reconnect it to register again.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !redirectAllowed(client.RedirectURIs, redirectURI) {
		renderError(w, http.StatusBadRequest, "The redirect address does not match the one this application registered.")
		return
	}

	state := q.Get("state")
	// A malformed request redirects only to a loopback client. With open registration any
	// https URI can be registered, and redirecting there without any user action would make
	// this endpoint an open redirector.
	fail := func(code, description string) {
		if !isLoopbackRedirect(redirectURI) {
			renderError(w, http.StatusBadRequest, "The application sent an invalid authorization request: "+description+".")
			return
		}
		b.redirectError(w, r, redirectURI, state, code, description)
	}
	if len(state) > maxStateLength {
		fail("invalid_request", "state is too long")
		return
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only the authorization code flow is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || len(challenge) < 43 || len(challenge) > 128 {
		fail("invalid_request", "PKCE with S256 is required")
		return
	}
	if !resourceMatches(q["resource"], b.resourceURL(r)) {
		fail("invalid_target", "the requested resource is not this MCP server")
		return
	}

	scopes := strings.Fields(q.Get("scope"))
	nonce, err := randomToken()
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	req := consentRequest{
		ClientKey:      clientKey(q.Get("client_id")),
		ClientName:     client.Name,
		RedirectURI:    redirectURI,
		State:          state,
		Challenge:      challenge,
		WriteRequested: len(scopes) == 0 || slices.Contains(scopes, scopeWrite),
		Resource:       b.resourceURL(r),
		Nonce:          nonce,
		Expires:        b.now().Add(consentTTL).Unix(),
	}
	sealed, err := b.seal.seal(purposeConsent, "", req)
	if err != nil {
		log.WithContext(r.Context()).Errorf("seal MCP consent request: %v", err)
		renderError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}

	b.setCookie(w, r, consentCookie, nonce, consentTTL, http.SameSiteStrictMode)
	renderConsent(w, consentPage{
		ClientName:     displayName(client.Name),
		RedirectHost:   redirectHost(redirectURI),
		Loopback:       isLoopbackRedirect(redirectURI),
		WriteRequested: req.WriteRequested,
		Request:        sealed,
		Action:         apiPrefix + authorizePath,
	})
}

// upstreamLogin is what the broker remembers while the user logs in at the identity
// provider. It travels in a cookie, so the state sent upstream stays short.
type upstreamLogin struct {
	Request  consentRequest `json:"q"`
	Scopes   []string       `json:"g"`
	Verifier string         `json:"v"`
	State    string         `json:"s"`
	Callback string         `json:"cb"`
	Expires  int64          `json:"e"`
}

// decide handles the consent form: deny goes back to the client, approve sends the user to
// the identity provider to log in.
func (b *Broker) decide(w http.ResponseWriter, r *http.Request) {
	// The form is only ever submitted from the consent page itself.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		renderError(w, http.StatusForbidden, "This request did not come from the NetBird consent page.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "The request could not be read. Start the connection again.")
		return
	}

	var req consentRequest
	if err := b.seal.open(purposeConsent, "", r.PostForm.Get("request"), &req); err != nil || b.expired(req.Expires) {
		renderError(w, http.StatusBadRequest, "This page has expired. Start the connection again from your application.")
		return
	}
	cookie, err := r.Cookie(b.cookieName(r, consentCookie))
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(req.Nonce)) != 1 {
		renderError(w, http.StatusBadRequest, "This page was not opened in this browser. Start the connection again from your application.")
		return
	}
	b.clearCookie(w, r, consentCookie)

	if r.PostForm.Get("action") != "approve" {
		b.redirectError(w, r, req.RedirectURI, req.State, "access_denied", "the user declined the request")
		return
	}

	scopes := []string{scopeRead}
	if req.WriteRequested && r.PostForm.Get("write") == "on" {
		scopes = append(scopes, scopeWrite)
	}
	verifier := oauth2.GenerateVerifier()
	state, err := randomToken()
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	login := upstreamLogin{
		Request:  req,
		Scopes:   scopes,
		Verifier: verifier,
		State:    state,
		Callback: b.baseURL(r) + apiPrefix + callbackPath,
		Expires:  b.now().Add(loginTTL).Unix(),
	}
	sealed, err := b.seal.seal(purposeLogin, "", login)
	if err != nil {
		log.WithContext(r.Context()).Errorf("seal MCP login: %v", err)
		renderError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	b.setCookie(w, r, loginCookie, sealed, loginTTL, http.SameSiteLaxMode)
	http.Redirect(w, r, b.upstreamAuthorizeURL(login), http.StatusFound)
}

func (b *Broker) upstreamAuthorizeURL(login upstreamLogin) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {b.flow.ClientID},
		"redirect_uri":          {login.Callback},
		"scope":                 {b.flow.Scope},
		"state":                 {login.State},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(login.Verifier)},
		"code_challenge_method": {"S256"},
	}
	if b.flow.Audience != "" {
		params.Set("audience", b.flow.Audience)
	}
	sep := "?"
	if strings.Contains(b.flow.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return b.flow.AuthorizationEndpoint + sep + params.Encode()
}

// authCode is the code the broker returns to the client after a successful login.
type authCode struct {
	// ID makes the code single-use: its first redemption is recorded in the grant store.
	ID          string        `json:"j"`
	Identity    grantIdentity `json:"i"`
	ClientKey   string        `json:"c"`
	RedirectURI string        `json:"r"`
	Challenge   string        `json:"p"`
	Resource    string        `json:"x"`
	Scopes      []string      `json:"s"`
	Expires     int64         `json:"e"`
}

// callback receives the identity provider's answer, validates the login exactly like the
// API validates a dashboard login, and hands the client its own authorization code.
func (b *Broker) callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(b.cookieName(r, loginCookie))
	var login upstreamLogin
	if err != nil || b.seal.open(purposeLogin, "", cookie.Value, &login) != nil || b.expired(login.Expires) {
		renderError(w, http.StatusBadRequest, "This sign-in has expired or was started in another browser. Start the connection again from your application.")
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(login.State)) != 1 {
		renderError(w, http.StatusBadRequest, "This sign-in does not match the one started in this browser. Start the connection again from your application.")
		return
	}
	// The cookie stays valid for its 10 minutes whatever the browser does with it, so its first
	// use is recorded: a replay would otherwise make the broker call the identity provider again.
	first, err := b.grants.claim(r.Context(), usedLoginKeyPrefix+login.State, b.until(login.Expires))
	if err != nil {
		log.WithContext(r.Context()).Errorf("MCP OAuth: %v", err)
		renderError(w, http.StatusServiceUnavailable, "Sign-in is temporarily unavailable. Try again shortly.")
		return
	}
	if !first {
		renderError(w, http.StatusBadRequest, "This sign-in was already completed. Start the connection again from your application.")
		return
	}
	b.clearCookie(w, r, loginCookie)

	req := login.Request
	if upstreamErr := q.Get("error"); upstreamErr != "" {
		log.WithContext(r.Context()).Debugf("MCP login refused by the identity provider: %s", upstreamErr)
		b.redirectError(w, r, req.RedirectURI, req.State, "access_denied", "the login was not completed")
		return
	}

	identity, err := b.loginIdentity(r.Context(), q.Get("code"), login)
	if err != nil {
		log.WithContext(r.Context()).Debugf("MCP login failed: %v", err)
		b.redirectError(w, r, req.RedirectURI, req.State, "access_denied", "the login could not be verified")
		return
	}

	codeID, err := randomToken()
	if err != nil {
		b.redirectError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	code, err := b.seal.seal(purposeCode, codePrefix, authCode{
		ID:          codeID,
		Identity:    identity,
		ClientKey:   req.ClientKey,
		RedirectURI: req.RedirectURI,
		Challenge:   req.Challenge,
		Resource:    req.Resource,
		Scopes:      login.Scopes,
		Expires:     b.now().Add(codeTTL).Unix(),
	})
	if err != nil {
		log.WithContext(r.Context()).Errorf("seal MCP authorization code: %v", err)
		b.redirectError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	params := url.Values{"code": {code}, "iss": {b.issuerURL(r)}}
	if req.State != "" {
		params.Set("state", req.State)
	}
	http.Redirect(w, r, withQuery(req.RedirectURI, params), http.StatusFound)
}

// grantIdentity is the NetBird caller an authorization code or token stands for.
type grantIdentity struct {
	UserID         string `json:"u"`
	AccountID      string `json:"a"`
	Domain         string `json:"d,omitempty"`
	DomainCategory string `json:"dc,omitempty"`
}

// loginIdentity redeems the identity provider's code and resolves the NetBird user the same
// way the API auth middleware does for a JWT: validate, ensure the account, apply the JWT
// group restrictions, sync groups, load the user.
func (b *Broker) loginIdentity(ctx context.Context, code string, login upstreamLogin) (grantIdentity, error) {
	if code == "" {
		return grantIdentity{}, errors.New("no authorization code from the identity provider")
	}
	token, err := b.exchangeUpstream(ctx, code, login)
	if err != nil {
		return grantIdentity{}, err
	}

	userAuth, validated, err := b.identity.ValidateAndParseToken(ctx, token)
	if err != nil {
		return grantIdentity{}, fmt.Errorf("validate identity provider token: %w", err)
	}
	accountID, _, err := b.accounts.GetAccountIDFromUserAuth(ctx, userAuth)
	if err != nil {
		return grantIdentity{}, fmt.Errorf("resolve account: %w", err)
	}
	userAuth.AccountId = accountID
	userAuth, err = b.identity.EnsureUserAccessByJWTGroups(ctx, userAuth, validated)
	if err != nil {
		return grantIdentity{}, fmt.Errorf("check JWT group access: %w", err)
	}
	if err := b.accounts.SyncUserJWTGroups(context.WithoutCancel(ctx), userAuth); err != nil {
		log.WithContext(ctx).Errorf("failed to sync user JWT groups during MCP login: %v", err)
	}
	user, err := b.accounts.GetUserFromUserAuth(ctx, userAuth)
	if err != nil {
		return grantIdentity{}, fmt.Errorf("load user: %w", err)
	}
	if err := activeUser(user, userAuth.AccountId); err != nil {
		return grantIdentity{}, err
	}
	return grantIdentity{
		UserID:         user.Id,
		AccountID:      userAuth.AccountId,
		Domain:         userAuth.Domain,
		DomainCategory: userAuth.DomainCategory,
	}, nil
}

type upstreamTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

func (b *Broker) exchangeUpstream(ctx context.Context, code string, login upstreamLogin) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {b.flow.ClientID},
		"code":          {code},
		"redirect_uri":  {login.Callback},
		"code_verifier": {login.Verifier},
	}
	if b.clientSecret != "" {
		form.Set("client_secret", b.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.flow.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := b.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("identity provider token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("identity provider token endpoint answered %d", resp.StatusCode)
	}
	var tokens upstreamTokens
	if err := json.Unmarshal(body, &tokens); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	token := tokens.AccessToken
	if b.flow.UseIDToken {
		token = tokens.IDToken
	}
	if token == "" {
		return "", errors.New("identity provider returned no usable token")
	}
	return token, nil
}

// grant is the payload of the broker's access and refresh tokens.
type grant struct {
	// GrantID names the grant record the token belongs to; the token is refused once it is gone.
	GrantID string `json:"g"`
	// ID identifies a refresh token, so its first use can be recorded and a second one detected.
	ID        string        `json:"j,omitempty"`
	Identity  grantIdentity `json:"i"`
	ClientKey string        `json:"c"`
	Resource  string        `json:"x"`
	Scopes    []string      `json:"s"`
	Expires   int64         `json:"e"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// token redeems authorization codes and refresh tokens. Clients are public, so the client
// id is matched against what the code or refresh token was issued to, and PKCE proves the
// code belongs to the client that started the flow.
func (b *Broker) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "the request body could not be parsed")
		return
	}
	form := r.PostForm
	switch form.Get("grant_type") {
	case "authorization_code":
		if _, ok := b.lookupClient(form.Get("client_id")); !ok {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client, register again")
			return
		}
		b.redeemCode(w, r, form)
	case "refresh_token":
		// Every refresh failure, an unknown client included, answers invalid_grant: it is the
		// only error on which the Go SDK drops its token and signs in again.
		b.refresh(w, r, form)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

// revoke is the RFC 7009 revocation endpoint. Either token of a session revokes the whole
// session, so a client signing out ends it on the server too. Clients are public, so holding
// the token is the credential; a client_id, when sent, must be the one the token was issued
// to (section 2.1). Section 2.2: a token that does not open is answered 200 like a revoked one.
func (b *Broker) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil || r.PostForm.Get("token") == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	token := r.PostForm.Get("token")
	var g grant
	opened := b.seal.open(purposeRefresh, refreshTokenPrefix, token, &g) == nil ||
		b.seal.open(purposeAccess, accessTokenPrefix, token, &g) == nil
	if opened {
		if id := r.PostForm.Get("client_id"); id != "" && clientKey(id) != g.ClientKey {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "the token was issued to another client")
			return
		}
		if err := b.grants.revoke(r.Context(), g.GrantID); err != nil {
			// Section 2.2.1: 503 tells the client the token may still be valid and to retry.
			writeStoreError(w, r, err)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (b *Broker) redeemCode(w http.ResponseWriter, r *http.Request, form url.Values) {
	var code authCode
	if err := b.seal.open(purposeCode, codePrefix, form.Get("code"), &code); err != nil || b.expired(code.Expires) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is invalid or expired")
		return
	}
	if clientKey(form.Get("client_id")) != code.ClientKey || form.Get("redirect_uri") != code.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code was issued to another client")
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(form.Get("code_verifier"))
	if form.Get("code_verifier") == "" || subtle.ConstantTimeCompare([]byte(challenge), []byte(code.Challenge)) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the code verifier does not match")
		return
	}
	if !resourceMatches(form["resource"], code.Resource) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "the requested resource does not match the authorization")
		return
	}
	if code.ID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is invalid or expired")
		return
	}

	grantID, err := randomToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	refreshID, err := randomToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	// The session ends a fixed time after this login. Refreshing never extends it, so the user
	// signs in at the identity provider again, and its checks run again, at least that often.
	expires := b.now().Add(sessionTTL).Unix()
	record := grantRecord{
		UserID: code.Identity.UserID, AccountID: code.Identity.AccountID, ClientKey: code.ClientKey,
		Current: refreshID, Started: b.now().Unix(),
	}
	// Only a redemption that passed every check counts as the code's use, so someone holding
	// the code without its verifier cannot spend it for the client.
	previous, reused, err := b.grants.start(r.Context(), code.ID, b.until(code.Expires), grantID, record, b.until(expires))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if reused {
		// OAuth 2.1 section 4.1.3: a code redeemed twice may have been stolen, so the session
		// the first redemption started is revoked as well.
		if err := b.grants.revoke(r.Context(), previous); err != nil {
			writeStoreError(w, r, err)
			return
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code was already used")
		return
	}
	b.issueTokens(w, r, grant{
		GrantID: grantID, Identity: code.Identity, ClientKey: code.ClientKey, Resource: code.Resource,
		Scopes: code.Scopes, Expires: expires,
	}, refreshID)
}

func (b *Broker) refresh(w http.ResponseWriter, r *http.Request, form url.Values) {
	var g grant
	if err := b.seal.open(purposeRefresh, refreshTokenPrefix, form.Get("refresh_token"), &g); err != nil || b.expired(g.Expires) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is invalid or expired")
		return
	}
	if clientKey(form.Get("client_id")) != g.ClientKey {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was issued to another client")
		return
	}
	if !resourceMatches(form["resource"], g.Resource) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was issued for another resource")
		return
	}
	record, ok, err := b.grants.load(r.Context(), g.GrantID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if !ok || g.ID == "" || !record.belongsTo(g) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the session was revoked or has ended, sign in again")
		return
	}
	if _, err := b.activeIdentity(r.Context(), g.Identity, record.Started); err != nil {
		if errors.Is(err, errStoreUnavailable) {
			writeStoreError(w, r, err)
			return
		}
		log.WithContext(r.Context()).Debugf("MCP refresh refused: %v", err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the user can no longer use this connection")
		return
	}

	next, err := randomToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	// A rotation whose reply is lost to a timeout still lands. The client's retry presents the
	// replaced token within the grace window and gets the rotation's result.
	outcome, refreshID, err := b.grants.rotate(r.Context(), g.GrantID, g.ID, next, b.now())
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	switch outcome {
	case grantRotated, grantServed:
		b.issueTokens(w, r, g, refreshID)
	case grantReplayed:
		log.WithContext(r.Context()).Warnf("MCP refresh token reused for user %s, session revoked", g.Identity.UserID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was already used")
	default:
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the session was revoked or has ended, sign in again")
	}
}

// issueTokens mints an access and a refresh token for a session whose end is g.Expires. The
// refresh token keeps that end, and the access token never outlives it. refreshID is the ID
// the grant record already holds as current.
func (b *Broker) issueTokens(w http.ResponseWriter, r *http.Request, g grant, refreshID string) {
	now := b.now()
	if g.Expires <= now.Unix() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the session has ended, sign in again")
		return
	}
	access := g
	access.ID = ""
	access.Expires = min(now.Add(accessTokenTTL).Unix(), g.Expires)
	refresh := g
	refresh.ID = refreshID

	accessToken, err := b.seal.seal(purposeAccess, accessTokenPrefix, access)
	if err != nil {
		log.WithContext(r.Context()).Errorf("seal MCP access token: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	refreshToken, err := b.seal.seal(purposeRefresh, refreshTokenPrefix, refresh)
	if err != nil {
		log.WithContext(r.Context()).Errorf("seal MCP refresh token: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    access.Expires - now.Unix(),
		RefreshToken: refreshToken,
		Scope:        strings.Join(g.Scopes, " "),
	})
}

// userCreationSlack covers the time between a user's creation at the identity provider
// callback and the code redemption that starts the session, and clock skew between instances.
const userCreationSlack = time.Minute

// activeIdentity reloads the user behind a session and refuses one that is gone, blocked,
// waiting for approval, now in another account, or created after the session began: a
// user removed and added again under the same ID does not inherit the old user's sessions.
func (b *Broker) activeIdentity(ctx context.Context, id grantIdentity, started int64) (*types.User, error) {
	user, err := b.accounts.GetUserByID(ctx, id.UserID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			return nil, fmt.Errorf("load user: %w", err)
		}
		// A store failure says nothing about the user. Refusing would sign every client out
		// during a database outage, so it is answered like one of the grant store.
		return nil, fmt.Errorf("%w: load user: %v", errStoreUnavailable, err)
	}
	if err := activeUser(user, id.AccountID); err != nil {
		return nil, err
	}
	if user.CreatedAt.After(time.Unix(started, 0).Add(userCreationSlack)) {
		return nil, errors.New("the user was created after the session began")
	}
	return user, nil
}

func activeUser(user *types.User, accountID string) error {
	switch {
	case user == nil:
		return errors.New("user not found")
	case user.IsBlocked():
		return errors.New("user is blocked")
	case user.PendingApproval:
		return errors.New("user is pending approval")
	case user.AccountID != accountID:
		return errors.New("user no longer belongs to the account")
	default:
		return nil
	}
}

func (b *Broker) expired(unix int64) bool {
	return b.now().Unix() >= unix
}

// redirectError sends an OAuth error back to a client whose redirect URI was already checked.
func (b *Broker) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	params := url.Values{"error": {code}, "iss": {b.issuerURL(r)}}
	if description != "" {
		params.Set("error_description", description)
	}
	if state != "" {
		params.Set("state", state)
	}
	http.Redirect(w, r, withQuery(redirectURI, params), http.StatusFound)
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oauthError{Error: code, Description: description})
}

// redirectAllowed matches a requested redirect URI against the registered ones: exactly,
// or for loopback http redirects on any port, as OAuth 2.1 and RFC 8252 section 7.3 require
// for native apps that pick a free port at runtime.
func redirectAllowed(registered []string, requested string) bool {
	if requested == "" {
		return false
	}
	if slices.Contains(registered, requested) {
		return true
	}
	req, err := url.Parse(requested)
	if err != nil || req.Scheme != "http" || !isLoopbackHost(req.Hostname()) {
		return false
	}
	for _, raw := range registered {
		reg, err := url.Parse(raw)
		if err != nil || reg.Scheme != "http" || !isLoopbackHost(reg.Hostname()) {
			continue
		}
		if reg.Hostname() == req.Hostname() && reg.Path == req.Path && reg.RawQuery == req.RawQuery {
			return true
		}
	}
	return false
}

// resourceMatches accepts an absent resource parameter, or one or more that all name the
// expected resource, ignoring the account query.
func resourceMatches(values []string, expected string) bool {
	for _, v := range values {
		if canonical, ok := canonicalResource(v); !ok || canonical != expected {
			return false
		}
	}
	return true
}

func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && isLoopbackHost(u.Hostname())
}

func redirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

func withQuery(raw string, params url.Values) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, vs := range params {
		q[k] = vs
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// cookieName uses the __Host- prefix over https. Browsers only accept such a cookie from the
// host itself, so a page on a sibling subdomain (tenant proxy domains share the site) cannot
// plant the consent or login cookie and forge a decision.
func (b *Broker) cookieName(r *http.Request, name string) string {
	if b.isHTTPS(r) {
		return "__Host-" + name
	}
	return name
}

// cookiePath is / over https, which the __Host- prefix requires.
func (b *Broker) cookiePath(r *http.Request) string {
	if b.isHTTPS(r) {
		return "/"
	}
	return authIssuerPath
}

func (b *Broker) isHTTPS(r *http.Request) bool {
	return strings.HasPrefix(b.baseURL(r), "https://")
}

func (b *Broker) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     b.cookieName(r, name),
		Value:    value,
		Path:     b.cookiePath(r),
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		Secure:   b.isHTTPS(r),
		SameSite: sameSite,
	})
}

func (b *Broker) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     b.cookieName(r, name),
		Value:    "",
		Path:     b.cookiePath(r),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   b.isHTTPS(r),
	})
}

// truncate cuts s to at most n bytes without splitting a UTF-8 character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func displayName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "An application"
	}
	return name
}

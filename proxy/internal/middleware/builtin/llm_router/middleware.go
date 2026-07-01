// Package llm_router implements the SlotOnRequest middleware that
// routes a request to an upstream LLM provider based on the model name
// emitted upstream by llm_request_parser. The router rewrites the
// request's outbound target (scheme + host), strips known LLM-vendor
// auth headers, and injects the per-provider auth header from the
// matched route. Unknown or unconfigured models deny with a 403 and
// the canonical llm_policy.model_not_routable code.
package llm_router

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// gcpScope is the OAuth2 scope minted for Vertex AI service-account auth.
const gcpScope = "https://www.googleapis.com/auth/cloud-platform"

// gcpTokenTimeout bounds each GCP token mint/refresh HTTP call so a slow or
// unreachable token endpoint can't block the request indefinitely.
const gcpTokenTimeout = 10 * time.Second

// ID is the registry key for this middleware.
const ID = "llm_router"

// Version is reported via Middleware.Version().
const Version = "1.0.0"

const (
	denyCodeNotRoutable         = "llm_policy.model_not_routable"
	denyReasonNotRoutable       = "model_not_routable"
	denyCodeNoAuthorisedRoute   = "llm_policy.no_authorised_provider"
	denyReasonNoAuthorisedRoute = "no_authorised_provider"
	//nolint:gosec // deny code label, not a credential
	denyCodeUpstreamAuth  = "llm_policy.upstream_auth_failed"
	denyCodeUnmeterable   = "llm_policy.unmeterable_publisher"
	denyReasonUnmeterable = "unmeterable_publisher"
)

// strippedAuthHeaders is the closed list of vendor authentication
// credentials the router clears before injecting the provider-specific
// credential. Strictly auth headers — vendor-specific metadata
// (anthropic-version, openai-organization, openai-project, etc.) is
// NOT stripped because the client SDK sets those and the upstream
// requires them (e.g. Anthropic returns 400 without
// anthropic-version). Each entry is canonicalised by Go's
// http.Header.Del/Set, so listing the canonical shapes here is
// sufficient.
var strippedAuthHeaders = []string{
	"Authorization",       // OpenAI, OpenAI-compatible, most vendors, Bedrock bearer
	"Proxy-Authorization", // upstream proxy auth (defense-in-depth)
	"x-api-key",           // Anthropic
	"api-key",             // Azure OpenAI
	"X-Amz-Date",          // AWS SigV4 — strip client-supplied AWS signing material
	"X-Amz-Security-Token",
	"X-Amz-Content-Sha256",
}

// Middleware routes requests to upstream LLM providers based on the
// llm.model metadata emitted by llm_request_parser.
type Middleware struct {
	cfg Config
	// tokenSrc caches one auto-refreshing OAuth2 TokenSource per GCP
	// service-account key (keyed by a hash of the key material), so Vertex
	// token minting happens once and refreshes are amortised across requests.
	tokenMu  sync.Mutex
	tokenSrc map[string]oauth2.TokenSource
}

// New constructs a Middleware with the supplied configuration. Empty
// or nil Providers slice yields a router that denies every request as
// not-routable.
func New(cfg Config) *Middleware {
	return &Middleware{cfg: cfg, tokenSrc: map[string]oauth2.TokenSource{}}
}

// ID returns the registry identifier.
func (m *Middleware) ID() string { return ID }

// Version returns the implementation version.
func (m *Middleware) Version() string { return Version }

// Slot reports the chain slot the middleware lives in.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnRequest }

// AcceptedContentTypes returns nil because the router only consults
// the metadata emitted by llm_request_parser.
func (m *Middleware) AcceptedContentTypes() []string { return nil }

// MetadataKeys is the closed set of metadata keys this middleware may
// emit. The accumulator drops anything outside this allowlist.
func (m *Middleware) MetadataKeys() []string {
	return []string{
		middleware.KeyLLMResolvedProviderID,
		middleware.KeyLLMAuthorisingGroups,
		middleware.KeyLLMPolicyDecision,
		middleware.KeyLLMPolicyReason,
	}
}

// MutationsSupported reports that the middleware emits header and
// upstream-rewrite mutations.
func (m *Middleware) MutationsSupported() bool { return true }

// Close releases resources owned by the middleware. The router is
// stateless, so this is a no-op.
func (m *Middleware) Close() error { return nil }

// matchOutcome captures why matchRoute returned what it did so the
// caller can distinguish "no provider knows this model" from "providers
// know it but none authorise this peer's groups".
type matchOutcome int

const (
	matchOutcomeFound matchOutcome = iota
	matchOutcomeUnknownModel
	matchOutcomeUnauthorised
)

// Invoke resolves the model to a provider authorised for the caller's
// groups, strips known vendor auth headers, and injects the route's
// auth header. Unknown models deny with model_not_routable; models
// known to a provider that no policy authorises for the caller deny
// with no_authorised_provider.
func (m *Middleware) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	// Vertex AI carries the model in the URL path, not the body, and is
	// selected by path rather than by the model/vendor table. Route it before
	// the model lookup so a model the parser extracted from the path can't be
	// claimed by a same-vendor direct provider (e.g. claude-* on api.anthropic.com).
	reqPath := requestPath(in.URL)
	if isVertexPath(reqPath) {
		model, _ := lookupMetadata(in.Metadata, middleware.KeyLLMModel)
		// The request parser emits no llm.provider for a Vertex publisher it
		// can't parse (e.g. google/gemini). Forwarding such a request would
		// bypass token/budget metering, so deny it rather than serve it
		// unmetered.
		if vendor, _ := lookupMetadata(in.Metadata, middleware.KeyLLMProvider); vendor == "" {
			return denyUnmeterable(), nil
		}
		route, outcome := m.matchVertex(reqPath, model, in.UserGroups)
		switch outcome {
		case matchOutcomeFound:
			return m.allowWithRoute(route, in.UserGroups), nil
		case matchOutcomeUnauthorised:
			return denyNoAuthorisedRoute(model), nil
		default:
			return denyUnknownModel(model), nil
		}
	}

	// Bedrock likewise carries the model in the URL path (/model/{id}/{action}),
	// optionally behind a "/bedrock" gateway-namespace prefix. Route it by path
	// before the model lookup; when the prefix is present, strip it from the
	// forwarded path so the real Bedrock endpoint receives its native path.
	if isBedrockPath(reqPath) {
		model, _ := lookupMetadata(in.Metadata, middleware.KeyLLMModel)
		native, hadPrefix := splitBedrockNamespace(reqPath)
		route, outcome := m.matchBedrock(native, model, in.UserGroups)
		switch outcome {
		case matchOutcomeFound:
			out := m.allowWithRoute(route, in.UserGroups)
			if hadPrefix && out.Mutations != nil && out.Mutations.RewriteUpstream != nil {
				out.Mutations.RewriteUpstream.StripPathPrefix = bedrockNamespacePrefix
			}
			return out, nil
		case matchOutcomeUnauthorised:
			return denyNoAuthorisedRoute(model), nil
		default:
			return denyUnknownModel(model), nil
		}
	}

	model, ok := lookupMetadata(in.Metadata, middleware.KeyLLMModel)
	if !ok || model == "" {
		// Non-inference endpoints (model listing) carry no model but still
		// need rewriting from the synth placeholder to a real upstream;
		// clients such as Codex call GET /v1/models at startup to enumerate
		// availability and read a 403 as "model unavailable".
		route, outcome := m.matchModelless(requestPath(in.URL), in.UserGroups)
		switch outcome {
		case matchOutcomeFound:
			return m.allowWithRoute(route, in.UserGroups), nil
		case matchOutcomeUnauthorised:
			// A recognised model-less endpoint exists but no provider
			// authorises the caller — deny as an authorisation failure
			// rather than masking it as a missing model.
			return denyNoAuthorisedRoute(model), nil
		default:
			return denyMissingModel(), nil
		}
	}

	vendor, _ := lookupMetadata(in.Metadata, middleware.KeyLLMProvider)
	route, outcome := m.matchRoute(model, vendor, requestPath(in.URL), in.UserGroups)
	switch outcome {
	case matchOutcomeFound:
		return m.allowWithRoute(route, in.UserGroups), nil
	case matchOutcomeUnauthorised:
		return denyNoAuthorisedRoute(model), nil
	default:
		return denyUnknownModel(model), nil
	}
}

// matchRoute returns the ProviderRoute that should serve the given
// model + request path for a caller in the given user-groups. Selection
// is:
//
//  1. Filter the configured providers to those whose Models list
//     contains the model.
//  2. Filter the model-matched candidates to those whose
//     AllowedGroupIDs intersect the caller's UserGroups. A route with
//     no AllowedGroupIDs is the catch-all: it stays in the list. If
//     the model was known but no candidate is authorised for this
//     peer, return matchOutcomeUnauthorised so the caller can emit
//     the dedicated no_authorised_provider deny code.
//  3. Vendor precedence: when the request carries a detected vendor
//     (llm.provider) and at least one candidate is the same vendor,
//     drop the rest — a vendor-tagged request must never cross to
//     another vendor's route (e.g. an Anthropic call landing on an
//     OpenAI-compatible gateway that also claims the model).
//  4. Model precedence over path: a route that explicitly lists the
//     model beats a catch-all (empty Models) gateway.
//  5. Disambiguate the survivors by URL path prefix: longest
//     UpstreamPath that prefix-matches the request path wins; an empty
//     UpstreamPath is the catchall. If none prefix-matches, fall back
//     to declaration order so the model stays routable.
func (m *Middleware) matchRoute(model, vendor, reqPath string, userGroups []string) (ProviderRoute, matchOutcome) {
	var modelMatched []ProviderRoute
	for _, route := range m.cfg.Providers {
		if routeClaimsModel(route, model) {
			modelMatched = append(modelMatched, route)
		}
	}
	if len(modelMatched) == 0 {
		return ProviderRoute{}, matchOutcomeUnknownModel
	}

	// Vendor pinning runs BEFORE the group filter so a request the parser
	// tagged with a vendor can never cross to another vendor's route — not
	// even an authorised one. Narrow to same-vendor routes when any
	// model-matched route declares that vendor; setups with no vendor tag on
	// any route fall through unchanged. After narrowing, if no same-vendor
	// route authorises the caller, that's matchOutcomeUnauthorised (no
	// cross-vendor fallback).
	if vendor != "" {
		if vendorMatched := matchingVendor(modelMatched, vendor); len(vendorMatched) > 0 {
			modelMatched = vendorMatched
		}
	}

	var candidates []ProviderRoute
	for _, route := range modelMatched {
		if routeAuthorisesGroups(route, userGroups) {
			candidates = append(candidates, route)
		}
	}
	if len(candidates) == 0 {
		return ProviderRoute{}, matchOutcomeUnauthorised
	}

	// Model routing takes precedence over path. A route that explicitly
	// lists the model must beat a catch-all (empty Models) gateway that
	// claims every model — otherwise an Anthropic request can fall through
	// to an OpenAI-compatible gateway declared earlier. Only when no
	// candidate explicitly claims the model do the catch-alls compete, and
	// the path-prefix tiebreak applies within whichever tier wins.
	if explicit := explicitlyClaiming(candidates, model); len(explicit) > 0 {
		candidates = explicit
	}
	if len(candidates) == 1 {
		return candidates[0], matchOutcomeFound
	}

	best := candidates[0]
	bestLen := -1
	for _, c := range candidates {
		if !pathPrefixMatches(c.UpstreamPath, reqPath) {
			continue
		}
		if len(c.UpstreamPath) > bestLen {
			best = c
			bestLen = len(c.UpstreamPath)
		}
	}
	return best, matchOutcomeFound
}

// isModelLessPath reports whether reqPath is a known OpenAI-shaped
// non-inference endpoint that legitimately carries no model in its
// request (the model-listing endpoints). These must route to an upstream
// rather than deny, so model enumeration works end to end.
func isModelLessPath(reqPath string) bool {
	return reqPath == "/v1/models" || strings.HasPrefix(reqPath, "/v1/models/")
}

// isVertexPath reports whether reqPath is a Google Vertex AI publisher
// endpoint: /v1/projects/{project}/locations/{region}/publishers/{publisher}/
// models/{model}:{action}. The model + vendor live in the path, so these
// requests are routed by path to the Vertex provider rather than by model.
func isVertexPath(reqPath string) bool {
	return strings.HasPrefix(reqPath, "/v1/projects/") &&
		strings.Contains(reqPath, "/publishers/") &&
		strings.Contains(reqPath, "/models/")
}

// bedrockNamespacePrefix is an optional gateway-namespace prefix some clients
// place before the native Bedrock path to disambiguate it from other providers
// that also use "/model/...". It is stripped before forwarding upstream.
const bedrockNamespacePrefix = "/bedrock"

// splitBedrockNamespace removes an optional "/bedrock" namespace prefix,
// returning the native Bedrock path and whether the prefix was present.
func splitBedrockNamespace(reqPath string) (string, bool) {
	if strings.HasPrefix(reqPath, bedrockNamespacePrefix+"/") {
		return strings.TrimPrefix(reqPath, bedrockNamespacePrefix), true
	}
	return reqPath, false
}

// isBedrockPath reports whether reqPath is an AWS Bedrock runtime model
// endpoint: /model/{modelId}/{action} where action is invoke,
// invoke-with-response-stream, converse, or converse-stream — optionally behind
// a "/bedrock" gateway-namespace prefix. The model lives in the path, so these
// requests are routed by path to the Bedrock provider.
func isBedrockPath(reqPath string) bool {
	native, _ := splitBedrockNamespace(reqPath)
	if !strings.HasPrefix(native, "/model/") {
		return false
	}
	return strings.HasSuffix(native, "/invoke") ||
		strings.HasSuffix(native, "/invoke-with-response-stream") ||
		strings.HasSuffix(native, "/converse") ||
		strings.HasSuffix(native, "/converse-stream")
}

// matchVertex selects the Vertex provider authorised for the caller's groups
// and claiming the requested model.
func (m *Middleware) matchVertex(reqPath, model string, userGroups []string) (ProviderRoute, matchOutcome) {
	return m.matchPathRoute(reqPath, model, userGroups, func(r ProviderRoute) bool { return r.Vertex })
}

// matchBedrock selects the Bedrock provider authorised for the caller's groups
// and claiming the requested model.
func (m *Middleware) matchBedrock(reqPath, model string, userGroups []string) (ProviderRoute, matchOutcome) {
	return m.matchPathRoute(reqPath, model, userGroups, func(r ProviderRoute) bool { return r.Bedrock })
}

// matchPathRoute selects a path-routed provider (Vertex/Bedrock). These carry
// the model in the URL, so the model/vendor table is bypassed — but the route's
// configured Models allowlist is still enforced (empty Models = catch-all) so a
// provider credential can't be used for models the operator didn't authorise.
// Returns matchOutcomeUnauthorised when no style route authorises the caller's
// groups, matchOutcomeUnknownModel when an authorised route exists but none
// claims the model (or no style route exists at all), else the chosen route
// (longest UpstreamPath prefix-match wins among multiple).
func (m *Middleware) matchPathRoute(reqPath, model string, userGroups []string, isStyle func(ProviderRoute) bool) (ProviderRoute, matchOutcome) {
	var styled []ProviderRoute
	for _, route := range m.cfg.Providers {
		if isStyle(route) {
			styled = append(styled, route)
		}
	}
	if len(styled) == 0 {
		return ProviderRoute{}, matchOutcomeUnknownModel
	}

	var authorised []ProviderRoute
	for _, route := range styled {
		if routeAuthorisesGroups(route, userGroups) {
			authorised = append(authorised, route)
		}
	}
	if len(authorised) == 0 {
		return ProviderRoute{}, matchOutcomeUnauthorised
	}

	var candidates []ProviderRoute
	for _, route := range authorised {
		if routeClaimsModel(route, model) {
			candidates = append(candidates, route)
		}
	}
	if len(candidates) == 0 {
		return ProviderRoute{}, matchOutcomeUnknownModel
	}
	if len(candidates) == 1 {
		return candidates[0], matchOutcomeFound
	}

	best := candidates[0]
	bestLen := -1
	for _, c := range candidates {
		if !pathPrefixMatches(c.UpstreamPath, reqPath) {
			continue
		}
		if len(c.UpstreamPath) > bestLen {
			best = c
			bestLen = len(c.UpstreamPath)
		}
	}
	return best, matchOutcomeFound
}

// matchModelless selects a route for a non-inference, model-less request.
// It mirrors matchRoute's group-authorisation filter and path-prefix
// tiebreak but skips the per-model filter, since any provider the caller's
// groups authorise can serve a model-listing request. Returns
// matchOutcomeFound with the chosen route (single authorised provider wins
// outright; multiple fall to the longest UpstreamPath prefix-match, then
// declaration order), matchOutcomeUnauthorised when no provider authorises
// the caller, or matchOutcomeUnknownModel when the path isn't a recognised
// model-less endpoint.
func (m *Middleware) matchModelless(reqPath string, userGroups []string) (ProviderRoute, matchOutcome) {
	if !isModelLessPath(reqPath) {
		return ProviderRoute{}, matchOutcomeUnknownModel
	}
	var candidates []ProviderRoute
	for _, route := range m.cfg.Providers {
		// Vertex/Bedrock are path-routed and don't serve OpenAI-style
		// model-listing endpoints; including them here could rewrite a
		// GET /v1/models to an upstream that 404s it.
		if route.Vertex || route.Bedrock {
			continue
		}
		if routeAuthorisesGroups(route, userGroups) {
			candidates = append(candidates, route)
		}
	}
	if len(candidates) == 0 {
		return ProviderRoute{}, matchOutcomeUnauthorised
	}
	if len(candidates) == 1 {
		return candidates[0], matchOutcomeFound
	}

	best := candidates[0]
	bestLen := -1
	for _, c := range candidates {
		if !pathPrefixMatches(c.UpstreamPath, reqPath) {
			continue
		}
		if len(c.UpstreamPath) > bestLen {
			best = c
			bestLen = len(c.UpstreamPath)
		}
	}
	return best, matchOutcomeFound
}

// routeAuthorisesGroups reports whether the route's AllowedGroupIDs
// intersect the caller's userGroups. A route with empty AllowedGroupIDs
// is unreachable: the synthesiser only emits routes bound to at least
// one enabled policy, so an empty list signals a misconfiguration that
// must not be allowed to fall through.
func routeAuthorisesGroups(r ProviderRoute, userGroups []string) bool {
	for _, ug := range userGroups {
		for _, ag := range r.AllowedGroupIDs {
			if ug == ag {
				return true
			}
		}
	}
	return false
}

// authorisingGroupsCSV returns the sorted, deduplicated comma-separated
// intersection of routeGroups and userGroups — i.e. the groups that
// actually authorise the resolved route for this caller. Returns the
// empty string when the intersection is empty (shouldn't happen on the
// allow path, but defensive).
func authorisingGroupsCSV(routeGroups, userGroups []string) string {
	if len(routeGroups) == 0 || len(userGroups) == 0 {
		return ""
	}
	allowed := make(map[string]struct{}, len(routeGroups))
	for _, g := range routeGroups {
		allowed[g] = struct{}{}
	}
	seen := make(map[string]struct{}, len(userGroups))
	out := make([]string, 0, len(userGroups))
	for _, ug := range userGroups {
		if _, ok := allowed[ug]; !ok {
			continue
		}
		if _, dup := seen[ug]; dup {
			continue
		}
		seen[ug] = struct{}{}
		out = append(out, ug)
	}
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// matchingVendor returns the subset of routes whose Vendor equals the
// request's detected vendor. Routes with an empty Vendor never match — an
// untagged route can't be asserted to speak the request's surface, so it
// stays out of the vendor-filtered set (but remains eligible via the
// fall-through when no route matches the vendor at all).
func matchingVendor(routes []ProviderRoute, vendor string) []ProviderRoute {
	var out []ProviderRoute
	for _, r := range routes {
		if r.Vendor == vendor {
			out = append(out, r)
		}
	}
	return out
}

// explicitlyClaiming returns the subset of routes whose Models list
// names the model exactly. Catch-all routes (empty Models) are excluded,
// so callers can prefer a provider that genuinely declares the model over
// a gateway that claims everything.
func explicitlyClaiming(routes []ProviderRoute, model string) []ProviderRoute {
	var out []ProviderRoute
	for _, r := range routes {
		for _, candidate := range r.Models {
			if candidate == model {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// routeClaimsModel reports whether the route's Models list contains
// the given model identifier. An empty Models list is treated as
// "claim every model" — used by gateway-style providers (LiteLLM,
// custom OpenAI-compatible endpoints) that proxy an open-ended set of
// upstream models the operator can't enumerate in NetBird's provider
// config.
func routeClaimsModel(route ProviderRoute, model string) bool {
	if len(route.Models) == 0 {
		return true
	}
	for _, candidate := range route.Models {
		if candidate == model {
			return true
		}
	}
	return false
}

// pathPrefixMatches reports whether upstreamPath matches reqPath on a path-
// segment boundary: an exact match, or reqPath continuing after
// upstreamPath at a "/" separator. This avoids a sibling base like
// "/openai" spuriously matching "/openai-test". An empty (or "/")
// upstreamPath always matches (catchall).
func pathPrefixMatches(upstreamPath, reqPath string) bool {
	if upstreamPath == "" || upstreamPath == "/" {
		return true
	}
	upstreamPath = strings.TrimRight(upstreamPath, "/")
	return reqPath == upstreamPath || strings.HasPrefix(reqPath, upstreamPath+"/")
}

// requestPath extracts the path component from an Input.URL string
// (which is r.URL.String() — typically "/path?query"). Returns the
// raw input on parse failure so the prefix check can still operate on
// the unparsed value.
func requestPath(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return parsed.Path
}

// allowWithRoute builds the Output for a successful route match. The
// returned Mutations carry the upstream rewrite plus — riding on it —
// the StripHeaders list and the AuthHeader to inject.
//
// The strip + inject MUST go through UpstreamRewrite (not HeadersAdd /
// HeadersRemove) because the framework's mutation gate runs every
// header change through a denylist that blocks Authorization,
// Cookie, etc. — exactly the headers the router is replacing. The
// proxy's upstream-build path applies AuthHeader / StripHeaders
// directly, bypassing the denylist by virtue of being a trusted
// proxy operation rather than an arbitrary middleware mutation.
//
// Emits the authorising-groups intersection alongside the resolved
// provider id so identity-stamping middlewares (llm_identity_inject)
// tag the request with ONLY the groups that authorised this specific
// route — not every group the peer happens to be in.
func (m *Middleware) allowWithRoute(route ProviderRoute, userGroups []string) *middleware.Output {
	rewrite := &middleware.UpstreamRewrite{
		Scheme: route.UpstreamScheme,
		Host:   route.UpstreamHost,
		// UpstreamPath is the path component the operator pasted on
		// the provider record (e.g. "/v1/{account}/{gateway}/compat"
		// for Cloudflare AI Gateway). Carrying it on the rewrite so
		// the proxy's URL composer joins it with the agent's request
		// path — without this, the operator's configured upstream
		// path is silently dropped and the gateway returns a 4xx for
		// the malformed URL. Empty value leaves the original
		// target's path untouched.
		Path:          route.UpstreamPath,
		StripHeaders:  append([]string(nil), strippedAuthHeaders...),
		SkipTLSVerify: route.SkipTLSVerify,
	}
	authValue := route.AuthHeaderValue
	if route.GCPServiceAccountKeyB64 != "" {
		// Mint a short-lived OAuth2 token from the service-account key at
		// request time (cached + auto-refreshed) instead of a static value.
		bearer, err := m.gcpBearer(route.GCPServiceAccountKeyB64)
		if err != nil {
			return denyUpstreamAuth()
		}
		authValue = bearer
	}
	if route.AuthHeaderName != "" && authValue != "" {
		rewrite.AuthHeader = &middleware.AuthHeader{
			Name:  route.AuthHeaderName,
			Value: authValue,
		}
	}
	return &middleware.Output{
		Decision:  middleware.DecisionAllow,
		Mutations: &middleware.Mutations{RewriteUpstream: rewrite},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMResolvedProviderID, Value: route.ID},
			{Key: middleware.KeyLLMAuthorisingGroups, Value: authorisingGroupsCSV(route.AllowedGroupIDs, userGroups)},
			{Key: middleware.KeyLLMPolicyDecision, Value: "allow"},
		},
	}
}

// gcpBearer returns a "Bearer <token>" value minted from a base64-encoded GCP
// service-account key, using a cached, auto-refreshing token source.
func (m *Middleware) gcpBearer(saKeyB64 string) (string, error) {
	ts, err := m.gcpTokenSource(saKeyB64)
	if err != nil {
		return "", err
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("mint gcp token: %w", err)
	}
	return "Bearer " + tok.AccessToken, nil
}

// gcpTokenSource returns the cached TokenSource for the given service-account
// key, building it (decode base64 → parse JSON → cloud-platform scope) on first
// use. The returned source caches the token and refreshes it before expiry.
func (m *Middleware) gcpTokenSource(saKeyB64 string) (oauth2.TokenSource, error) {
	sum := sha256.Sum256([]byte(saKeyB64))
	key := hex.EncodeToString(sum[:])

	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	if m.tokenSrc == nil {
		m.tokenSrc = map[string]oauth2.TokenSource{}
	}
	if ts, ok := m.tokenSrc[key]; ok {
		return ts, nil
	}
	jsonKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(saKeyB64))
	if err != nil {
		return nil, fmt.Errorf("decode gcp service-account key: %w", err)
	}
	conf, err := google.JWTConfigFromJSON(jsonKey, gcpScope)
	if err != nil {
		return nil, fmt.Errorf("parse gcp service-account key: %w", err)
	}
	// Bound mint/refresh with a timeout HTTP client so a slow token endpoint
	// can't hang the request. The oauth2 library uses this client for the
	// lifetime of the (auto-refreshing) source.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: gcpTokenTimeout})
	ts := conf.TokenSource(ctx)
	m.tokenSrc[key] = ts
	return ts, nil
}

// denyUpstreamAuth is returned when the router cannot obtain the upstream
// credential (e.g. a malformed service-account key or an unreachable token
// endpoint). It surfaces as a 502 — an upstream problem, not a policy denial.
func denyUpstreamAuth() *middleware.Output {
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: 502,
		DenyReason: &middleware.DenyReason{
			Code:    denyCodeUpstreamAuth,
			Message: "could not obtain upstream credential",
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: "upstream_auth_failed"},
		},
	}
}

// denyUnmeterable returns the deny envelope for a path-routed request whose
// publisher has no parser surface, so its usage can't be metered. Serving it
// would bypass token/budget caps, so it is rejected with a 403.
func denyUnmeterable() *middleware.Output {
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: 403,
		DenyReason: &middleware.DenyReason{
			Code:    denyCodeUnmeterable,
			Message: "request publisher is not supported for metering",
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: denyReasonUnmeterable},
		},
	}
}

// denyMissingModel returns the deny envelope for a request whose
// envelope has no llm.model metadata.
func denyMissingModel() *middleware.Output {
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: 403,
		DenyReason: &middleware.DenyReason{
			Code:    denyCodeNotRoutable,
			Message: "missing llm.model on request envelope",
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: denyReasonNotRoutable},
		},
	}
}

// denyUnknownModel returns the deny envelope for a model that no
// configured provider claims.
func denyUnknownModel(model string) *middleware.Output {
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: 403,
		DenyReason: &middleware.DenyReason{
			Code:    denyCodeNotRoutable,
			Message: fmt.Sprintf("no provider configured for model %s", model),
			Details: map[string]string{"model": model},
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: denyReasonNotRoutable},
		},
	}
}

// denyNoAuthorisedRoute returns the deny envelope for a model that one
// or more providers claim, but where no policy authorises the caller's
// groups for any of those providers.
func denyNoAuthorisedRoute(model string) *middleware.Output {
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: 403,
		DenyReason: &middleware.DenyReason{
			Code:    denyCodeNoAuthorisedRoute,
			Message: fmt.Sprintf("no policy authorises model %s for the caller's groups", model),
			Details: map[string]string{"model": model},
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: denyReasonNoAuthorisedRoute},
		},
	}
}

// lookupMetadata returns the value for key plus a presence flag so
// callers can distinguish absent from empty.
func lookupMetadata(meta []middleware.KV, key string) (string, bool) {
	for _, kv := range meta {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

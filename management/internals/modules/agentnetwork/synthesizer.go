package agentnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// apiKeyPlaceholder is the literal substituted with the provider's
// decrypted API key in catalog AuthHeaderTemplate strings.
const apiKeyPlaceholder = "${API_KEY}" //nolint:gosec // template marker, not a credential

// gcpKeyfilePrefix marks an api_key that holds a base64-encoded GCP
// service-account JSON key ("keyfile::<base64>") rather than a static bearer
// token; the proxy mints OAuth tokens from it. Mirrors Aperture's convention.
const gcpKeyfilePrefix = "keyfile::"

// SynthesizedServiceIDPrefix prefixes the in-memory ID of every
// reverse-proxy service synthesised from Agent Network state. One
// synthesised service exists per (account, cluster); the suffix is the
// account ID so the proxy can dedup mappings cleanly.
const SynthesizedServiceIDPrefix = "agent-net-svc-"

// agentNetworkRequestCaptureBytes is the request-side body capture cap.
// Kept modest: oversized requests (a long conversation's context can be
// many MB) have their routing fields recovered by the proxy's tolerant
// scan rather than buffered here, so there's no need to size this to the
// largest possible request.
const agentNetworkRequestCaptureBytes = 1 << 20

// agentNetworkResponseCaptureBytes is the response-side body capture cap.
// Token usage lives in the trailing SSE message_delta event, so the
// captured prefix must reach the end of the stream. Unlike a request's
// unbounded context, a single response is hard-capped by the model's max
// output tokens (~128K on Opus → a few hundred KB of gzipped SSE even
// with thinking), so 8 MiB is comfortably above any real response and is
// effectively unlimited here — not a moving ceiling. The proxy clamps to
// its own MaxBodyCapBytes at apply time.
const agentNetworkResponseCaptureBytes = 8 << 20

// agentNetworkCaptureContentTypes is the set of content types whose
// bodies the proxy buffers for the LLM middlewares. JSON covers
// buffered request and response bodies; SSE covers streaming
// responses (the response parser sums delta tokens across chunks).
var agentNetworkCaptureContentTypes = []string{
	"application/json",
	"text/event-stream",
}

// Middleware IDs the synthesised target chain registers, mirroring the
// proxy-side built-in registry. Order matters: on_request runs in the
// order they're listed; on_response runs in reverse, so cost_meter must
// come BEFORE llm_response_parser in the slice so the parser populates
// tokens before the cost meter reads them.
const (
	middlewareIDLLMRequestParser  = "llm_request_parser"
	middlewareIDLLMRouter         = "llm_router"
	middlewareIDLLMIdentityInject = "llm_identity_inject"
	middlewareIDLLMLimitCheck     = "llm_limit_check"
	middlewareIDLLMGuardrail      = "llm_guardrail"
	middlewareIDCostMeter         = "cost_meter"
	middlewareIDLLMResponseParser = "llm_response_parser"
	middlewareIDLLMLimitRecord    = "llm_limit_record"
)

// SynthesizeServicesForCluster walks every account's agent-network
// settings row pinned to clusterAddr and synthesises the per-account
// gateway service. Used by the proxy-mapping snapshot path where the
// connecting proxy has a specific cluster address and cares about every
// account that routes through it.
//
// Returns nil (no error) when no settings row references the cluster.
// Per-account synthesis failures are skipped rather than dropping every
// account on the cluster.
func SynthesizeServicesForCluster(ctx context.Context, s store.Store, clusterAddr string) ([]*rpservice.Service, error) {
	clusterAddr = strings.TrimSpace(clusterAddr)
	if clusterAddr == "" {
		return nil, nil
	}

	settingsRows, err := s.GetAgentNetworkSettingsByCluster(ctx, store.LockingStrengthNone, clusterAddr)
	if err != nil {
		return nil, fmt.Errorf("list agent network settings on cluster: %w", err)
	}
	if len(settingsRows) == 0 {
		return nil, nil
	}

	var out []*rpservice.Service
	for _, settings := range settingsRows {
		if settings == nil {
			continue
		}
		services, serr := SynthesizeServices(ctx, s, settings.AccountID)
		if serr != nil {
			continue
		}
		for _, svc := range services {
			if svc != nil && svc.ProxyCluster == clusterAddr {
				out = append(out, svc)
			}
		}
	}
	return out, nil
}

// SynthesizeServiceForDomain resolves a single agent-network service by its
// public endpoint domain. It lists the (few) settings rows on the domain's
// cluster, matches the one whose endpoint equals the domain, and synthesises
// only that account — avoiding full per-account synthesis for every tenant on
// the cluster, which is what auth/session paths previously paid. Returns nil
// (no error) when no account owns the domain.
func SynthesizeServiceForDomain(ctx context.Context, s store.Store, domain string) (*rpservice.Service, error) {
	canonical, err := rpservice.CanonicalDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("canonicalize agent network service domain: %w", err)
	}
	domain = canonical
	cluster := clusterFromDomain(domain)
	if domain != "" && cluster != "" {
		settingsRows, err := s.GetAgentNetworkSettingsByCluster(ctx, store.LockingStrengthNone, cluster)
		if err != nil {
			return nil, fmt.Errorf("list agent network settings on cluster: %w", err)
		}
		for _, settings := range settingsRows {
			if settings == nil {
				continue
			}
			endpoint, err := rpservice.CanonicalDomain(settings.Endpoint())
			if err != nil || endpoint != domain {
				continue
			}
			services, serr := SynthesizeServices(ctx, s, settings.AccountID)
			if serr != nil {
				return nil, serr
			}
			for _, svc := range services {
				if svc == nil {
					continue
				}
				svcDomain, err := rpservice.CanonicalDomain(svc.Domain)
				if err == nil && svcDomain == domain {
					return svc, nil
				}
			}
			break
		}
	}
	return nil, nil //nolint:nilnil // optional lookup: no account owns the domain
}

// clusterFromDomain returns the cluster portion of an endpoint domain (every
// label after the first).
func clusterFromDomain(domain string) string {
	if i := strings.IndexByte(domain, '.'); i >= 0 {
		return domain[i+1:]
	}
	return ""
}

// SynthesizeServices builds the in-memory reverse-proxy service that
// fronts the account's agent-network gateway. Returns nil when the
// account has no settings row, no enabled providers, or no enabled
// policies — in any of those cases there's nothing useful to expose.
//
// One service per (account, settings.Cluster) is emitted. The router
// middleware encodes a denormalised model→provider routing table
// (auth headers + decrypted API keys baked in); the policy_check
// middleware encodes per-provider authorised group IDs derived from
// the account's enabled policies.
//
// Services are NEVER persisted — callers regenerate them on every
// network-map / proxy-mapping cycle from current state.
func SynthesizeServices(ctx context.Context, s store.Store, accountID string) ([]*rpservice.Service, error) {
	settings, ok, err := loadSettings(ctx, s, accountID)
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(settings.Cluster) == "" {
		return nil, nil
	}

	providers, err := s.GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("list agent network providers: %w", err)
	}
	enabledProviders := filterEnabledProviders(providers)
	if len(enabledProviders) == 0 {
		return nil, nil
	}

	policies, err := s.GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("list agent network policies: %w", err)
	}
	enabledPolicies := filterEnabledPolicies(policies)
	if len(enabledPolicies) == 0 {
		return nil, nil
	}

	// Backfill any missing session keypairs before deriving a
	// service-level keypair. Old rows pre-date the column; treating
	// the gap as a no-op produces an immediate dial failure, so we
	// fix it once here and persist for future cycles.
	for _, p := range enabledProviders {
		if p.SessionPrivateKey != "" && p.SessionPublicKey != "" {
			continue
		}
		if err := backfillProviderSessionKeys(ctx, s, p); err != nil {
			return nil, fmt.Errorf("backfill session keys for provider %s: %w", p.ID, err)
		}
	}

	guardrails, err := s.GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("list agent network guardrails: %w", err)
	}
	guardrailsByID := make(map[string]*types.Guardrail, len(guardrails))
	for _, g := range guardrails {
		if g != nil {
			guardrailsByID[g.ID] = g
		}
	}

	groupIndex := indexProviderGroups(enabledPolicies)

	routerCfgJSON, err := buildRouterConfigJSON(enabledProviders, groupIndex)
	if err != nil {
		return nil, err
	}

	identityInjectJSON, err := buildIdentityInjectConfigJSON(enabledProviders, groupIndex)
	if err != nil {
		return nil, err
	}

	mergedGuardrails := mergeGuardrails(enabledPolicies, guardrailsByID)
	applyAccountCollectionControls(&mergedGuardrails, settings)
	guardrailJSON, err := marshalGuardrailConfig(mergedGuardrails)
	if err != nil {
		return nil, err
	}

	// Use the merged decision (account settings OR policy-required redaction),
	// not the raw account flag, so a policy that mandates PII redaction is
	// honored by the capture parsers even when the account toggle is off.
	middlewares := buildMiddlewareChain(routerCfgJSON, identityInjectJSON, guardrailJSON, mergedGuardrails.PromptCapture.RedactPii, mergedGuardrails.PromptCapture.Enabled)

	priv, pub, err := pickServiceSessionKeys(enabledProviders)
	if err != nil {
		return nil, err
	}

	svc := buildAccountService(accountID, settings, enabledPolicies, middlewares, priv, pub)
	return []*rpservice.Service{svc}, nil
}

// loadSettings returns the account's agent-network settings row. The
// boolean reports whether a row exists; a status.NotFound surfaces as
// (nil, false, nil) so callers can treat "no settings" as "no
// synthesis" without inspecting error types themselves.
func loadSettings(ctx context.Context, s store.Store, accountID string) (*types.Settings, bool, error) {
	settings, err := s.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	if err == nil {
		return settings, true, nil
	}
	var sErr *status.Error
	if errors.As(err, &sErr) && sErr.Type() == status.NotFound {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("get agent network settings: %w", err)
}

// filterEnabledProviders returns the subset of enabled providers, sorted
// by created_at ascending so the router config is deterministic and
// first-match-wins is stable across synthesis cycles.
func filterEnabledProviders(providers []*types.Provider) []*types.Provider {
	out := make([]*types.Provider, 0, len(providers))
	for _, p := range providers {
		if p == nil || !p.Enabled {
			continue
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// filterEnabledPolicies returns the subset of enabled policies.
func filterEnabledPolicies(policies []*types.Policy) []*types.Policy {
	out := make([]*types.Policy, 0, len(policies))
	for _, p := range policies {
		if p == nil || !p.Enabled {
			continue
		}
		out = append(out, p)
	}
	return out
}

// backfillProviderSessionKeys mints an ed25519 session keypair on a
// provider row that doesn't have one yet (rows created before the
// keys were persistent fields) and persists it via the store so
// subsequent cycles get stable keys.
func backfillProviderSessionKeys(ctx context.Context, s store.Store, p *types.Provider) error {
	pair, err := sessionkey.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate session keys for provider %s: %w", p.ID, err)
	}
	p.SessionPrivateKey = pair.PrivateKey
	p.SessionPublicKey = pair.PublicKey
	if err := s.SaveAgentNetworkProvider(ctx, p); err != nil {
		return fmt.Errorf("persist backfilled session keys for provider %s: %w", p.ID, err)
	}
	return nil
}

// pickServiceSessionKeys returns the keypair the synthesised gateway
// service signs / verifies session JWTs with. The PoC reuses the first
// enabled provider's keypair so existing session cookies survive
// provider edits as long as the first-by-created_at provider stays in
// place. Returns an error when no provider has a usable keypair after
// backfill — that surfaces a misconfigured account loudly instead of
// emitting a service the proxy will reject as "invalid session public
// key size".
func pickServiceSessionKeys(providers []*types.Provider) (priv, pub string, err error) {
	for _, p := range providers {
		if p.SessionPrivateKey != "" && p.SessionPublicKey != "" {
			return p.SessionPrivateKey, p.SessionPublicKey, nil
		}
	}
	return "", "", fmt.Errorf("no provider with session keypair; update one provider to backfill")
}

// routerConfig mirrors the on-wire shape llm_router accepts. Kept
// private so the synthesiser owns the contract; the proxy-side factory
// JSON-decodes the same shape.
type routerConfig struct {
	Providers []routerProviderRoute `json:"providers"`
}

type routerProviderRoute struct {
	ID              string   `json:"id"`
	Vendor          string   `json:"vendor,omitempty"`
	Models          []string `json:"models"`
	UpstreamScheme  string   `json:"upstream_scheme"`
	UpstreamHost    string   `json:"upstream_host"`
	UpstreamPath    string   `json:"upstream_path,omitempty"`
	AuthHeaderName  string   `json:"auth_header_name"`
	AuthHeaderValue string   `json:"auth_header_value"`
	AllowedGroupIDs []string `json:"allowed_group_ids,omitempty"`
	// Vertex marks a Google Vertex AI provider, whose requests carry the
	// model in the URL path. The router selects it by path, bypassing the
	// model/vendor table.
	Vertex bool `json:"vertex,omitempty"`
	// Bedrock marks an AWS Bedrock provider, whose requests carry the model in
	// the URL path (/model/{id}/{action}). The router selects it by path,
	// bypassing the model/vendor table; auth is a static bearer token.
	Bedrock bool `json:"bedrock,omitempty"`
	// GCPServiceAccountKeyB64 carries a base64-encoded GCP service-account
	// JSON key (from a "keyfile::<base64>" api_key). When set, the proxy mints
	// + refreshes the OAuth token at request time instead of injecting a static
	// AuthHeaderValue.
	GCPServiceAccountKeyB64 string `json:"gcp_sa_key_b64,omitempty"`
	// SkipTLSVerify disables upstream TLS certificate verification when the
	// proxy dials this provider's upstream. For self-hosted / internal gateways
	// behind a private or self-signed certificate.
	SkipTLSVerify bool `json:"skip_tls_verify,omitempty"`
}

// indexProviderGroups walks the enabled policies and returns, per
// provider id, the sorted union of source group ids across every
// policy that authorises the provider. Providers with no authorising
// policy are absent from the map. The router consumes this to filter
// candidate routes by the caller's group memberships before the
// path-prefix tiebreak runs.
func indexProviderGroups(policies []*types.Policy) map[string][]string {
	sets := make(map[string]map[string]struct{})
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		for _, providerID := range policy.DestinationProviderIDs {
			if providerID == "" {
				continue
			}
			set, ok := sets[providerID]
			if !ok {
				set = make(map[string]struct{})
				sets[providerID] = set
			}
			for _, group := range policy.SourceGroups {
				if group != "" {
					set[group] = struct{}{}
				}
			}
		}
	}
	out := make(map[string][]string, len(sets))
	for providerID, set := range sets {
		groups := make([]string, 0, len(set))
		for g := range set {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		out[providerID] = groups
	}
	return out
}

// buildRouterConfigJSON denormalises the account's enabled providers
// into the router middleware's first-match-wins routing table.
// Providers are listed in created_at order so the table is
// deterministic and stable across synth cycles.
//
// AllowedGroupIDs is the union of source group ids across every enabled
// policy that authorises the provider. The router uses it as a hard
// filter — a route whose AllowedGroupIDs has no intersection with the
// caller's user groups is removed from the candidate list before the
// path-prefix tiebreak. Providers no enabled policy authorises
// (orphans) are intentionally OMITTED so the router never observes a
// route with an empty ACL.
func buildRouterConfigJSON(providers []*types.Provider, groupIndex map[string][]string) ([]byte, error) {
	cfg := routerConfig{Providers: make([]routerProviderRoute, 0, len(providers))}
	for _, p := range providers {
		groups, hasPolicy := groupIndex[p.ID]
		if !hasPolicy {
			// Orphan: skip. No enabled policy authorises this
			// provider, so it must not be reachable.
			continue
		}
		scheme, host, path, err := parseUpstreamHost(p.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("router config for provider %s: %w", p.ID, err)
		}
		headerName, headerValue, gcpSAKeyB64, err := providerAuthHeader(p)
		if err != nil {
			return nil, err
		}
		cfg.Providers = append(cfg.Providers, routerProviderRoute{
			ID:                      p.ID,
			Vendor:                  providerVendor(p),
			Models:                  providerModelIDs(p),
			UpstreamScheme:          scheme,
			UpstreamHost:            host,
			UpstreamPath:            path,
			AuthHeaderName:          headerName,
			AuthHeaderValue:         headerValue,
			AllowedGroupIDs:         groups,
			Vertex:                  catalog.IsVertexPathStyle(p.ProviderID),
			Bedrock:                 catalog.IsBedrockPathStyle(p.ProviderID),
			GCPServiceAccountKeyB64: gcpSAKeyB64,
			SkipTLSVerify:           p.SkipTLSVerification,
		})
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal llm_router middleware config: %w", err)
	}
	return out, nil
}

// providerVendor returns the parser surface ("openai", "anthropic", …)
// the provider speaks, sourced from its catalog entry's ParserID. The
// router uses it to keep a request the parser tagged with a vendor on a
// route of the same vendor — so e.g. an Anthropic /v1/messages call is
// never sent to an OpenAI-compatible gateway that also claims the model.
// Empty when the catalog entry is unknown or declares no parser surface;
// the router then falls back to model / path routing.
func providerVendor(p *types.Provider) string {
	entry, ok := catalog.Lookup(p.ProviderID)
	if !ok {
		return ""
	}
	return entry.ParserID
}

// providerModelIDs returns the model identifiers exposed by the
// provider, deduplicated and in the operator's declared order. Empty
// slice when no models are configured — the router treats that as
// "claim every model" so gateway-style providers (LiteLLM, custom
// OpenAI-compatible endpoints) work without the operator enumerating
// the upstream's full model catalog in NetBird.
func providerModelIDs(p *types.Provider) []string {
	if len(p.Models) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(p.Models))
	out := make([]string, 0, len(p.Models))
	for _, m := range p.Models {
		if m.ID == "" {
			continue
		}
		if _, dup := seen[m.ID]; dup {
			continue
		}
		seen[m.ID] = struct{}{}
		out = append(out, m.ID)
	}
	return out
}

// identityInjectConfig mirrors the on-wire shape llm_identity_inject
// accepts.
type identityInjectConfig struct {
	Providers []identityInjectProvider `json:"providers"`
}

// identityInjectProvider carries one provider's injection rule.
// Identity-stamping uses one of HeaderPair / JSONMetadata (mutually
// exclusive). ExtraHeaders is independent — a list of extra
// per-provider routing/config headers (catalog-declared, value lives
// on the provider record) the middleware stamps with anti-spoof
// (Remove + Add) on every matching request.
type identityInjectProvider struct {
	ProviderID   string                      `json:"provider_id"`
	HeaderPair   *identityInjectHeaderPair   `json:"header_pair,omitempty"`
	JSONMetadata *identityInjectJSONMetadata `json:"json_metadata,omitempty"`
	ExtraHeaders []identityInjectExtraHeader `json:"extra_headers,omitempty"`
}

type identityInjectExtraHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type identityInjectHeaderPair struct {
	EndUserIDHeader string `json:"end_user_id_header,omitempty"`
	TagsHeader      string `json:"tags_header,omitempty"`
	TagsInBody      bool   `json:"tags_in_body,omitempty"`
	EndUserIDInBody bool   `json:"end_user_id_in_body,omitempty"`
}

type identityInjectJSONMetadata struct {
	Header         string `json:"header"`
	UserKey        string `json:"user_key,omitempty"`
	GroupsKey      string `json:"groups_key,omitempty"`
	MaxValueLength int    `json:"max_value_length,omitempty"`
	Sanitize       bool   `json:"sanitize,omitempty"`
}

// buildIdentityInjectConfigJSON walks the enabled providers and emits
// one entry per provider whose catalog entry declares an
// IdentityInjection block. The middleware no-ops for any provider not
// in this list, so the chain is safe to ship to all targets even when
// no identity-stamping provider is configured.
//
// The caller passes groupIndex so we can mirror the synthesiser's own
// "drop orphans" rule — providers no enabled policy authorises don't
// reach the router, so injecting identity for them would never fire.
// We could leave them in for symmetry, but skipping is cheaper and
// clearer.
func buildIdentityInjectConfigJSON(providers []*types.Provider, groupIndex map[string][]string) ([]byte, error) {
	cfg := identityInjectConfig{Providers: make([]identityInjectProvider, 0)}
	for _, p := range providers {
		if _, hasPolicy := groupIndex[p.ID]; !hasPolicy {
			continue
		}
		entry, ok := catalog.Lookup(p.ProviderID)
		if !ok {
			continue
		}
		rule, ok := buildIdentityInjectRule(p, entry)
		if !ok {
			continue
		}
		cfg.Providers = append(cfg.Providers, rule)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal llm_identity_inject middleware config: %w", err)
	}
	return out, nil
}

// buildIdentityInjectRule assembles the injection rule for one provider
// from its record and catalog entry. The second return is false when the
// provider would emit nothing, so the caller can skip it entirely rather
// than carry an inert rule for it.
func buildIdentityInjectRule(p *types.Provider, entry catalog.Provider) (identityInjectProvider, bool) {
	rule := identityInjectProvider{ProviderID: p.ID}
	// Identity-stamping shape (one of HeaderPair / JSONMetadata). Skip the
	// shape silently when the catalog entry doesn't declare one, or when the
	// operator disabled metadata for this provider — extras can still apply,
	// see below. MetadataDisabled suppresses only the identity dimensions
	// (user + authorizing group), not the catalog's routing ExtraHeaders.
	if !p.MetadataDisabled && entry.IdentityInjection != nil {
		switch {
		case entry.IdentityInjection.HeaderPair != nil:
			rule.HeaderPair = buildIdentityHeaderPair(p, entry.IdentityInjection.HeaderPair)
		case entry.IdentityInjection.JSONMetadata != nil:
			rule.JSONMetadata = buildIdentityJSONMetadata(p, entry.IdentityInjection.JSONMetadata)
		}
	}
	rule.ExtraHeaders = buildIdentityExtraHeaders(p, entry.ExtraHeaders)
	if rule.HeaderPair == nil && rule.JSONMetadata == nil && len(rule.ExtraHeaders) == 0 {
		return identityInjectProvider{}, false
	}
	return rule, true
}

// buildIdentityHeaderPair resolves the header-pair injection shape,
// returning nil when nothing would be stamped. For Customizable shapes
// (Bifrost today) the wire header names come from the provider record
// verbatim; the catalog values are placeholder defaults shown by the
// dashboard, not authoritative. Empty operator value disables stamping
// for that dimension — applyHeaderPair already no-ops on empty header
// names. The body-inject flags stay catalog-owned because Customizable
// today only applies to gateways that read identity from headers (the
// flags would be no-ops anyway).
func buildIdentityHeaderPair(p *types.Provider, hp *catalog.HeaderPairInjection) *identityInjectHeaderPair {
	userHeader := hp.EndUserIDHeader
	tagsHeader := hp.TagsHeader
	if hp.Customizable {
		userHeader = p.IdentityHeaderUserID
		tagsHeader = p.IdentityHeaderGroups
	}
	if userHeader == "" && tagsHeader == "" && !hp.TagsInBody && !hp.EndUserIDInBody {
		return nil
	}
	return &identityInjectHeaderPair{
		EndUserIDHeader: userHeader,
		TagsHeader:      tagsHeader,
		TagsInBody:      hp.TagsInBody,
		EndUserIDInBody: hp.EndUserIDInBody,
	}
}

// buildIdentityJSONMetadata resolves the JSON-metadata injection shape,
// returning nil when the catalog entry carries no header. Customizable
// JSONMetadata reuses the same provider-record fields HeaderPair uses —
// IdentityHeaderUserID becomes the JSON key for the user dimension, and
// IdentityHeaderGroups becomes the JSON key for groups. Empty operator
// value is honored as "skip this key"; applyJSONMetadata already drops
// keys with empty names. Header itself is catalog-owned (e.g.
// cf-aig-metadata) — operators only override the keys inside the JSON,
// not the wire header that carries it.
func buildIdentityJSONMetadata(p *types.Provider, jm *catalog.JSONMetadataInjection) *identityInjectJSONMetadata {
	if jm.Header == "" {
		return nil
	}
	userKey := jm.UserKey
	groupsKey := jm.GroupsKey
	if jm.Customizable {
		userKey = p.IdentityHeaderUserID
		groupsKey = p.IdentityHeaderGroups
	}
	return &identityInjectJSONMetadata{
		Header:         jm.Header,
		UserKey:        userKey,
		GroupsKey:      groupsKey,
		MaxValueLength: jm.MaxValueLength,
		Sanitize:       jm.Sanitize,
	}
}

// buildIdentityExtraHeaders collects catalog-declared static headers (e.g.
// Portkey config id), emitting only entries whose value the operator has
// filled in on the provider record; missing/empty values are no-ops.
func buildIdentityExtraHeaders(p *types.Provider, extras []catalog.ExtraHeader) []identityInjectExtraHeader {
	var out []identityInjectExtraHeader
	for _, h := range extras {
		if h.Name == "" {
			continue
		}
		v := strings.TrimSpace(p.ExtraValues[h.Name])
		if v == "" {
			continue
		}
		out = append(out, identityInjectExtraHeader{Name: h.Name, Value: v})
	}
	return out
}

// buildMiddlewareChain assembles the per-target middleware chain that
// implements the Agent Network behaviour at the proxy. Slot order on
// the request leg is the slice order; on the response leg it runs in
// reverse, so cost_meter must come BEFORE llm_response_parser so the
// parser populates token counts before the cost meter reads them.
//
// Authorisation is fused into llm_router: the router carries
// AllowedGroupIDs per provider and filters candidates by the caller's
// user-groups before the path-prefix tiebreak. Per-policy
// enforcement (token / budget caps) lives in llm_limit_check, which
// runs after the router so it can read the resolved provider id;
// llm_limit_record on the response leg posts deltas back to
// management to keep the consumption counters fresh.
//
// llm_identity_inject runs immediately after the router so the
// resolved provider id is available; it stamps NetBird identity onto
// requests bound for gateways like LiteLLM that key budgets and
// attribution off request headers. CanMutate is required so its
// HeadersAdd / HeadersRemove pass the framework's mutation gate.
func buildMiddlewareChain(routerCfgJSON, identityInjectJSON, guardrailJSON []byte, redactPii, capturePromptContent bool) []rpservice.MiddlewareConfig {
	// Both parsers receive an explicit capture flag derived from the account's
	// enable_prompt_collection toggle; nil/unset would default to the legacy
	// "always emit" behavior in the middleware, which is precisely what we
	// must suppress when the operator hasn't opted in. The flag is duplicated
	// across both parsers under distinct field names (capture_prompt /
	// capture_completion) to keep each parser's config independently
	// auditable.
	requestParserCfg := buildParserConfigJSON("capture_prompt", redactPii, capturePromptContent)
	responseParserCfg := buildParserConfigJSON("capture_completion", redactPii, capturePromptContent)
	return []rpservice.MiddlewareConfig{
		{
			ID:         middlewareIDLLMRequestParser,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnRequest,
			ConfigJSON: requestParserCfg,
		},
		{
			ID:         middlewareIDLLMRouter,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnRequest,
			ConfigJSON: routerCfgJSON,
			// llm_router rewrites the request's headers (strip
			// client auth + inject provider auth) and the upstream
			// target via Mutations.RewriteUpstream. Both gated on
			// CanMutate; without this flag the chain framework
			// drops every mutation and the reverse proxy dials the
			// placeholder noop.invalid host (502).
			CanMutate: true,
		},
		{
			// llm_limit_check runs after the router so it knows the
			// resolved provider id, but before identity_inject so a
			// cap-deny doesn't pay the cost of stamping headers
			// we'll never use.
			ID:         middlewareIDLLMLimitCheck,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnRequest,
			ConfigJSON: []byte("{}"),
		},
		{
			ID:         middlewareIDLLMIdentityInject,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnRequest,
			ConfigJSON: identityInjectJSON,
			// CanMutate is required so HeadersAdd / HeadersRemove
			// emitted to stamp NetBird identity onto the upstream
			// request actually land — without it the framework
			// drops every header mutation.
			CanMutate: true,
		},
		{
			ID:         middlewareIDLLMGuardrail,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnRequest,
			ConfigJSON: guardrailJSON,
		},
		{
			// Response slot runs in reverse slice order at runtime:
			// limit_record sits FIRST in the response section so it
			// runs LAST, after llm_response_parser stamped tokens
			// and cost_meter computed cost — both of which the
			// recorder reads from the metadata bag.
			ID:         middlewareIDLLMLimitRecord,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnResponse,
			ConfigJSON: []byte("{}"),
		},
		{
			ID:         middlewareIDCostMeter,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnResponse,
			ConfigJSON: []byte("{}"),
		},
		{
			ID:         middlewareIDLLMResponseParser,
			Enabled:    true,
			Slot:       rpservice.MiddlewareSlotOnResponse,
			ConfigJSON: responseParserCfg,
		},
	}
}

// guardrailConfig is the JSON shape the proxy-side llm_guardrail
// middleware expects. Mirrors the proxy registration documented in
// the management→proxy contract.
type guardrailConfig struct {
	ModelAllowlist []string               `json:"model_allowlist,omitempty"`
	PromptCapture  guardrailPromptCapture `json:"prompt_capture"`
}

type guardrailPromptCapture struct {
	Enabled   bool `json:"enabled"`
	RedactPii bool `json:"redact_pii"`
}

// buildParserConfigJSON assembles the request- or response-parser config JSON.
// captureField names the parser-specific gate (capture_prompt for the request
// parser, capture_completion for the response parser); both are sourced from
// settings.EnablePromptCollection. redact_pii is only meaningful when capture
// is on (no content → nothing to redact) but we forward it verbatim so the
// proxy-side parser stays the only place that interprets the combination.
func buildParserConfigJSON(captureField string, redactPii, capture bool) []byte {
	payload := map[string]any{
		captureField: capture,
	}
	if redactPii {
		payload["redact_pii"] = true
	}
	out, err := json.Marshal(payload)
	if err != nil {
		// json.Marshal on a map[string]any of bools cannot fail; if it
		// somehow does, ship the static minimal config so synth keeps
		// working instead of panicking.
		return []byte(`{}`)
	}
	return out
}

// applyAccountCollectionControls folds the account-level collection master
// switches into the merged guardrail set. Prompt capture enablement is sourced
// SOLELY from the account toggle — the account-network setting is the master
// enable, and policies don't need to attach a capture-enabled guardrail to opt
// in. PII redaction is safe-additive: it applies when either the account or a
// policy guardrail enables it (OR).
func applyAccountCollectionControls(merged *MergedGuardrails, settings *types.Settings) {
	if settings == nil {
		return
	}
	merged.PromptCapture.Enabled = settings.EnablePromptCollection
	merged.PromptCapture.RedactPii = settings.RedactPii || merged.PromptCapture.RedactPii
}

func marshalGuardrailConfig(merged MergedGuardrails) ([]byte, error) {
	cfg := guardrailConfig{
		ModelAllowlist: merged.ModelAllowlist,
		PromptCapture: guardrailPromptCapture{
			Enabled:   merged.PromptCapture.Enabled,
			RedactPii: merged.PromptCapture.RedactPii,
		},
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal guardrail middleware config: %w", err)
	}
	return out, nil
}

// buildAccountService composes the per-account gateway Service. The
// target carries the noop placeholder URL — the router middleware
// rewrites every request to the matched provider's upstream before the
// proxy dials — alongside the full middleware chain and capture caps.
func buildAccountService(
	accountID string,
	settings *types.Settings,
	enabledPolicies []*types.Policy,
	middlewares []rpservice.MiddlewareConfig,
	sessionPriv, sessionPub string,
) *rpservice.Service {
	cluster := settings.Cluster
	domain := settings.Endpoint()
	serviceID := SynthesizedServiceIDPrefix + accountID

	return &rpservice.Service{
		ID:           serviceID,
		AccountID:    accountID,
		Name:         "agent-network-" + accountID,
		Domain:       domain,
		ProxyCluster: cluster,
		Mode:         rpservice.ModeHTTP,
		Enabled:      true,
		Private:      true,
		// AccessGroups gates tunnel-peer access (ValidateTunnelPeer) to the
		// synthesised agent-network endpoint. Agents reach the gateway over
		// the WireGuard tunnel and are authorised by their peer→user group
		// membership — the union of every enabled policy's source groups.
		AccessGroups:      unionSourceGroups(enabledPolicies),
		PassHostHeader:    false,
		RewriteRedirects:  false,
		SessionPrivateKey: sessionPriv,
		SessionPublicKey:  sessionPub,
		Targets: []*rpservice.Target{
			{
				AccountID:  accountID,
				ServiceID:  serviceID,
				TargetType: rpservice.TargetTypeCluster,
				TargetId:   cluster,
				Host:       noopUpstreamHost,
				Port:       noopUpstreamPort,
				Protocol:   noopUpstreamScheme,
				Enabled:    true,
				Options: rpservice.TargetOptions{
					DirectUpstream:          true,
					AgentNetwork:            true,
					DisableAccessLog:        !settings.EnableLogCollection,
					Middlewares:             middlewares,
					CaptureMaxRequestBytes:  agentNetworkRequestCaptureBytes,
					CaptureMaxResponseBytes: agentNetworkResponseCaptureBytes,
					CaptureContentTypes:     append([]string(nil), agentNetworkCaptureContentTypes...),
				},
			},
		},
	}
}

const (
	noopUpstreamScheme = "https"
	noopUpstreamHost   = "noop.invalid"
	noopUpstreamPort   = uint16(443)
)

// providerAuthHeader builds the upstream auth header pair for a
// provider from its catalog entry. The catalog declares which header
// name and template a provider's API expects; the synthesiser
// substitutes the provider's decrypted API key into the template and
// returns the (name, value) pair the router middleware injects after
// stripping the inbound vendor auth headers.
func providerAuthHeader(p *types.Provider) (name, value, gcpSAKeyB64 string, err error) {
	entry, ok := catalog.Lookup(p.ProviderID)
	if !ok {
		return "", "", "", fmt.Errorf("provider %s references unknown catalog id %q", p.ID, p.ProviderID)
	}
	if entry.AuthHeaderName == "" || entry.AuthHeaderTemplate == "" {
		return "", "", "", fmt.Errorf("catalog entry %q has no auth header configured", p.ProviderID)
	}
	if p.APIKey == "" {
		return "", "", "", fmt.Errorf("provider %s has no api key", p.ID)
	}
	// A "keyfile::<base64 json>" api_key is a GCP service-account key, not a
	// static bearer. The proxy mints + refreshes a short-lived OAuth token from
	// it at request time, so carry the key material on the route and emit no
	// static value.
	if rest, isKeyfile := strings.CutPrefix(p.APIKey, gcpKeyfilePrefix); isKeyfile {
		return entry.AuthHeaderName, "", strings.TrimSpace(rest), nil
	}
	value = strings.ReplaceAll(entry.AuthHeaderTemplate, apiKeyPlaceholder, p.APIKey)
	return entry.AuthHeaderName, value, "", nil
}

// parseUpstreamHost splits provider.UpstreamURL into (scheme, host, path)
// where host carries an explicit ":port" suffix when the URL set one
// and path is the URL's path component normalised by stripping a
// trailing slash. The router uses path to disambiguate providers that
// claim the same model. Used by the router config so the rewrite
// carries an authority the reverse proxy can dial verbatim.
func parseUpstreamHost(raw string) (scheme, host, path string, err error) {
	parsed, perr := url.Parse(strings.TrimSpace(raw))
	if perr != nil {
		return "", "", "", fmt.Errorf("parse upstream_url %q: %w", raw, perr)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		scheme = "http"
	case "https":
		scheme = "https"
	default:
		return "", "", "", fmt.Errorf("upstream_url scheme must be http or https, got %q", parsed.Scheme)
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return "", "", "", fmt.Errorf("upstream_url %q has no host", raw)
	}
	if port := parsed.Port(); port != "" {
		host = hostname + ":" + port
	} else {
		host = hostname
	}
	path = strings.TrimRight(parsed.Path, "/")
	return scheme, host, path, nil
}

// unionSourceGroups deduplicates source-group IDs across the policies
// pointing at any provider, in deterministic order.
func unionSourceGroups(policies []*types.Policy) []string {
	seen := make(map[string]struct{})
	for _, policy := range policies {
		for _, group := range policy.SourceGroups {
			if group == "" {
				continue
			}
			seen[group] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for group := range seen {
		out = append(out, group)
	}
	sort.Strings(out)
	return out
}

// MergedGuardrails is the JSON shape passed to the proxy via the
// guardrail middleware's config_json. Mirrors the proxy-side
// expectations and is intentionally distinct from
// types.GuardrailChecks so we can evolve either side independently.
type MergedGuardrails struct {
	ModelAllowlist []string            `json:"model_allowlist,omitempty"`
	TokenLimits    MergedTokenLimits   `json:"token_limits"`
	Budget         MergedBudget        `json:"budget"`
	PromptCapture  MergedPromptCapture `json:"prompt_capture"`
	Retention      MergedRetention     `json:"retention"`
}

type MergedTokenLimits struct {
	Hourly  *MergedTokenWindow `json:"hourly,omitempty"`
	Daily   *MergedTokenWindow `json:"daily,omitempty"`
	Monthly *MergedTokenWindow `json:"monthly,omitempty"`
}

type MergedTokenWindow struct {
	MaxInputTokens  int `json:"max_input_tokens,omitempty"`
	MaxOutputTokens int `json:"max_output_tokens,omitempty"`
}

type MergedBudget struct {
	Hourly  *MergedBudgetWindow `json:"hourly,omitempty"`
	Daily   *MergedBudgetWindow `json:"daily,omitempty"`
	Monthly *MergedBudgetWindow `json:"monthly,omitempty"`
}

type MergedBudgetWindow struct {
	SoftCapUSD float64 `json:"soft_cap_usd,omitempty"`
	HardCapUSD float64 `json:"hard_cap_usd,omitempty"`
}

type MergedPromptCapture struct {
	Enabled   bool `json:"enabled"`
	RedactPii bool `json:"redact_pii"`
}

type MergedRetention struct {
	Enabled bool `json:"enabled"`
	Days    int  `json:"days"`
}

// mergeGuardrails computes the effective guardrail spec applied at the
// proxy, given the referencing policies and the account's guardrail
// catalogue. Policy enabled-ness is the caller's responsibility — only
// enabled policies should be passed in.
//
// Merge rules:
//   - Model allowlist:   union of allowlists across policies that enable it.
//   - Token / Budget:    most-restrictive (min of non-zero caps) per window.
//   - Prompt capture:    enabled if any policy enables it; redact_pii sticks
//     if any enabling policy turns it on.
//   - Retention:         enabled if any enables it; smallest non-zero days wins.
func mergeGuardrails(policies []*types.Policy, byID map[string]*types.Guardrail) MergedGuardrails {
	merged := MergedGuardrails{}
	allowlist := make(map[string]struct{})
	allowlistEnabled := false

	for _, policy := range policies {
		for _, gID := range policy.GuardrailIDs {
			g, ok := byID[gID]
			if !ok || g == nil {
				continue
			}
			mergeGuardrail(g, &merged, allowlist, &allowlistEnabled)
		}
	}

	if allowlistEnabled {
		merged.ModelAllowlist = make([]string, 0, len(allowlist))
		for m := range allowlist {
			merged.ModelAllowlist = append(merged.ModelAllowlist, m)
		}
		sort.Strings(merged.ModelAllowlist)
	}
	return merged
}

// mergeGuardrail folds a single guardrail's enabled checks into the
// running merge: model-allowlist models join the shared set (and flip
// allowlistEnabled), and prompt-capture / redact-pii stick once any
// enabling guardrail turns them on.
//
// TokenLimits, Budget, and Retention have moved off guardrails — token
// and budget caps now live on the Policy itself (Policy.Limits) and
// retention moves to account-level Settings — so they are not merged here.
func mergeGuardrail(g *types.Guardrail, merged *MergedGuardrails, allowlist map[string]struct{}, allowlistEnabled *bool) {
	if g.Checks.ModelAllowlist.Enabled {
		*allowlistEnabled = true
		for _, m := range g.Checks.ModelAllowlist.Models {
			if m != "" {
				allowlist[m] = struct{}{}
			}
		}
	}
	if g.Checks.PromptCapture.Enabled {
		merged.PromptCapture.Enabled = true
		if g.Checks.PromptCapture.RedactPii {
			merged.PromptCapture.RedactPii = true
		}
	}
}

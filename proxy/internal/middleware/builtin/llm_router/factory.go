package llm_router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// ProviderRoute describes one upstream LLM provider the router can
// hand a request to. Models lists the model identifiers the provider
// claims; UpstreamScheme + UpstreamHost replace the synth target's
// placeholder URL on a match. UpstreamPath is the path component of
// the configured upstream URL — the router uses it to disambiguate
// providers that claim the same model: when more than one provider
// matches the model, the route whose UpstreamPath is a prefix of the
// incoming request path is preferred (longest match wins, empty path
// is the catchall). AuthHeaderName + AuthHeaderValue are the
// per-provider credential the router injects after stripping the
// vendor auth headers from the inbound request.
//
// AllowedGroupIDs is the union of source-group IDs across every
// enabled policy that authorises this provider. The router treats it
// as a hard filter: a route whose AllowedGroupIDs has no intersection
// with the caller's UserGroups is removed from the candidate list
// before the path-prefix tiebreak. A route with empty AllowedGroupIDs
// is unreachable; the synthesiser only emits policy-bound routes.
type ProviderRoute struct {
	ID string `json:"id"`
	// Vendor is the parser surface this provider speaks ("openai",
	// "anthropic", …), matching the llm.provider value llm_request_parser
	// emits from the request. When set, the router keeps a vendor-tagged
	// request on a same-vendor route so catch-all gateways of a different
	// vendor can't swallow it. Empty disables vendor filtering for this
	// route.
	Vendor string `json:"vendor,omitempty"`
	// Vendors lists every parser surface a multi-surface gateway accepts.
	// Vendor remains supported for existing single-surface configurations.
	Vendors         []string `json:"vendors,omitempty"`
	Models          []string `json:"models"`
	UpstreamScheme  string   `json:"upstream_scheme"`
	UpstreamHost    string   `json:"upstream_host"`
	UpstreamPath    string   `json:"upstream_path,omitempty"`
	AuthHeaderName  string   `json:"auth_header_name"`
	AuthHeaderValue string   `json:"auth_header_value"`
	AllowedGroupIDs []string `json:"allowed_group_ids"`
	// ModelPolicies carries, per authorising policy, the source groups it
	// binds and the models it permits. The router uses it to bound a model
	// listing to what THIS caller may use: a provider reachable by two groups
	// under different allowlists must not offer either group the other's
	// models. Empty means no policy restricts models on this route.
	ModelPolicies []ModelPolicyRule `json:"model_policies,omitempty"`
	// DiscoveryHost, when set, is the host that serves this provider's model
	// listing, for a vendor that does not serve it from the same host as
	// inference. Bedrock is why it exists: ListInferenceProfiles is a control
	// plane operation on bedrock.<region>, while InvokeModel must go to
	// bedrock-runtime.<region>, so one record genuinely needs two hosts.
	// Empty means the listing is served from UpstreamHost like everything else.
	DiscoveryHost string `json:"discovery_host,omitempty"`
	// Vertex marks a Google Vertex AI provider. Vertex requests carry the
	// model in the URL path, so the router selects this route by path
	// (isVertexPath) and bypasses the model/vendor table entirely.
	Vertex bool `json:"vertex,omitempty"`
	// Bedrock marks an AWS Bedrock provider. Bedrock requests carry the model
	// in the URL path (/model/{id}/{action}), so the router selects this route
	// by path (isBedrockPath) and bypasses the model/vendor table; auth is the
	// static AuthHeaderValue bearer token (no token minting).
	Bedrock bool `json:"bedrock,omitempty"`
	// GCPServiceAccountKeyB64 is a base64-encoded GCP service-account JSON
	// key. When set, the router mints + refreshes a short-lived OAuth2 access
	// token from it at request time and injects it as the auth header value
	// (instead of the static AuthHeaderValue) — so the gateway holds a durable
	// Vertex credential rather than a 1-hour token.
	GCPServiceAccountKeyB64 string `json:"gcp_sa_key_b64,omitempty"`
	// SkipTLSVerify disables upstream TLS certificate verification when dialing
	// this route's upstream. For self-hosted / internal gateways behind a
	// private or self-signed certificate.
	SkipTLSVerify bool `json:"skip_tls_verify,omitempty"`
}

// ModelPolicyRule is one authorising policy's contribution to what a caller
// may use on a route: the source groups it binds, and the models it permits.
//
// Models is nil when the policy sets no model allowlist — an unrestricted
// policy, which lifts the restriction for the groups it binds. That is why
// nil and empty must stay distinct: an empty list is a guardrail that permits
// nothing, and collapsing the two would let a listing fail open.
type ModelPolicyRule struct {
	GroupIDs []string `json:"group_ids"`
	Models   []string `json:"models"`
}

// Config is the on-wire configuration accepted by the factory. An
// empty Providers slice yields a router that denies every request as
// not-routable; the synthesiser is responsible for stamping the
// account's enabled providers into this slice.
type Config struct {
	Providers []ProviderRoute `json:"providers"`
}

// Factory builds llm_router instances from raw config bytes.
type Factory struct{}

// ID returns the registry identifier.
func (Factory) ID() string { return ID }

// New constructs a middleware instance. Empty, null, and {} configs
// yield a router with an empty Providers slice — every request denies
// with model_not_routable. Non-empty payloads must parse cleanly so
// misconfigurations surface at chain build time.
func (Factory) New(rawConfig []byte) (middleware.Middleware, error) {
	cfg := Config{}
	if !isEmptyJSON(rawConfig) {
		if err := json.Unmarshal(rawConfig, &cfg); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
	}
	return New(cfg), nil
}

// isEmptyJSON reports whether the payload is whitespace, null, or an
// empty object/array. The caller skips Unmarshal in that case so the
// zero-value Config flows through unchanged.
func isEmptyJSON(raw []byte) bool {
	trimmed := strings.TrimSpace(string(bytes.TrimSpace(raw)))
	switch trimmed {
	case "", "null", "{}", "[]":
		return true
	}
	return false
}

func init() {
	builtin.Register(Factory{})
}

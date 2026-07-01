// Package middleware defines the per-target middleware chain that runs
// inside the reverse proxy hot path. It is the only chain wired into
// the request path.
//
// Concepts:
//   - Slot: the position a middleware occupies in the chain. A
//     middleware lives in exactly one slot — separate concerns become
//     separate middlewares.
//   - Decision: the on_request slot can DENY; on_response and terminal
//     slots can only PASSTHROUGH. The dispatcher clamps decisions that
//     violate this contract.
//   - Metadata: the only side-channel between middlewares. Each
//     middleware declares an allowlist of keys it may emit; the merger
//     enforces caps and namespace rules.
package middleware

import "time"

// Slot identifies where in the request lifecycle a middleware runs.
// A middleware declares a single slot. Splitting per-purpose work
// (request parsing vs response parsing vs cost metering) into separate
// slot-keyed middlewares is the explicit architectural choice for the
// agent-network use case; no middleware participates in more than one
// slot.
type Slot int

const (
	// SlotOnRequest runs before the upstream call. Middlewares in this
	// slot may DENY the request, mutate headers/body (when permitted),
	// and emit metadata derived from the request envelope.
	SlotOnRequest Slot = 1
	// SlotOnResponse runs after the upstream returns. Middlewares in
	// this slot observe the response, emit metadata, and may mutate
	// response headers when permitted. They cannot DENY.
	SlotOnResponse Slot = 2
	// SlotTerminal runs after every SlotOnResponse middleware has
	// emitted. Terminal middlewares observe the full metadata bag and
	// ship it to external sinks (access log, metrics export). They
	// cannot DENY and cannot mutate the response.
	SlotTerminal Slot = 3
)

// FailMode controls how the dispatcher reacts when a middleware
// returns an error, times out, or panics. Observer middlewares default
// to FailOpen; policy middlewares should default to FailClosed.
type FailMode int

const (
	// FailOpen allows the request to proceed when a middleware fails.
	FailOpen FailMode = 0
	// FailClosed denies the request when a middleware fails. Only
	// meaningful for SlotOnRequest middlewares.
	FailClosed FailMode = 1
)

// Decision captures the outcome of a middleware invocation as observed
// by the dispatcher. Response-phase middlewares always return
// DecisionPassthrough; the dispatcher clamps any other value.
type Decision int

const (
	// DecisionAllow lets the request proceed.
	DecisionAllow Decision = 0
	// DecisionDeny stops the chain and returns a rendered deny
	// response. Only honoured in SlotOnRequest.
	DecisionDeny Decision = 1
	// DecisionPassthrough is the response-phase neutral outcome.
	DecisionPassthrough Decision = 2
)

// Resource limits enforced by the proxy at config apply time and by
// the dispatcher at runtime. Per-target values supplied by management
// are clamped to these bounds.
const (
	// MaxBodyCapBytes is the proxy-wide upper bound for per-direction
	// body capture. Sized to hold a full LLM streaming response (token
	// usage rides the trailing SSE event, so the captured prefix must
	// reach the end of the stream); a single response is bounded by the
	// model's max output tokens, so this is a real ceiling, not a
	// treadmill. Request capture stays well under this — oversized
	// requests use the tolerant routing scan instead of buffering.
	MaxBodyCapBytes int64 = 8 << 20
	// MinTimeout is the proxy-wide lower bound for per-middleware
	// Invoke timeouts.
	MinTimeout = 10 * time.Millisecond
	// MaxTimeout is the proxy-wide upper bound for per-middleware
	// Invoke timeouts.
	MaxTimeout = 5 * time.Second
	// DefaultTimeout is used when the per-target timeout is zero or
	// unset.
	DefaultTimeout = 500 * time.Millisecond

	// MaxMiddlewareMetadataBytes is the per-middleware metadata total
	// cap.
	MaxMiddlewareMetadataBytes = 16 << 10
	// MaxRequestMetadataBytes is the per-request metadata total cap
	// across all middlewares in the chain. Earlier middlewares win
	// when the budget is exhausted.
	MaxRequestMetadataBytes = 32 << 10
	// MaxMetadataKeyBytes is the maximum length of a metadata key.
	MaxMetadataKeyBytes = 96
	// MaxMetadataValueBytes is the maximum length of a metadata value.
	MaxMetadataValueBytes = 4 << 10
	// MaxMiddlewaresPerChain caps the number of middleware entries
	// accepted per chain at the proxy translator and the management
	// REST API. Mirrors the chain invocation cap so a misconfigured
	// mapping cannot push the chain clone cost beyond a known bound.
	MaxMiddlewaresPerChain = 16
)

// KV is the canonical header/metadata representation used across the
// middleware boundary. We use a slice of KV instead of http.Header
// because it preserves key order, is cheap to deep-copy per
// invocation, and is directly representable in a future protobuf
// envelope.
type KV struct {
	Key   string
	Value string
}

// Input is the immutable envelope handed to each middleware. The
// dispatcher deep-copies Headers, Body, Metadata, RespHeaders, and
// RespBody before each invocation so middlewares cannot mutate the
// shared in-flight copies; mutations must flow through Output.Mutations.
type Input struct {
	Slot             Slot
	RequestID        string
	TargetID         string
	Method           string
	URL              string
	Headers          []KV
	Body             []byte
	BodyTruncated    bool
	OriginalBodySize int64

	Status            int
	RespHeaders       []KV
	RespBody          []byte
	RespBodyTruncated bool
	OriginalRespSize  int64

	ServiceID string
	AccountID string
	UserID    string
	// UserEmail is the calling user's email address when the auth path
	// resolves a user record. Empty for non-OIDC schemes (PIN/Password/
	// Header) and for legacy session JWTs minted before the email claim
	// was introduced. Identity-stamping middlewares (e.g.
	// llm_identity_inject) prefer this over UserID for upstream gateways
	// that key budgets / attribution on a human-readable identifier.
	UserEmail  string
	AuthMethod string
	SourceIP   string
	// UserGroups captures the calling peer's group memberships at
	// request time, surfaced from the proxy's auth flow so policy-aware
	// middlewares can authorise without an extra management round-trip.
	UserGroups []string
	// UserGroupNames carries the human-readable display names paired
	// positionally with UserGroups (UserGroupNames[i] is the name of
	// UserGroups[i]). Identity-stamping middlewares prefer names for
	// upstream tags so attribution dashboards stay readable. Slice may
	// be shorter than UserGroups for tokens minted before names were
	// resolvable; consumers should fall back to ids for missing
	// positions.
	UserGroupNames []string
	Metadata       []KV

	// AgentNetwork is true when the target is a synthesised
	// agent-network service. Carried on the input so the access-log
	// terminal middleware can stamp the proto field without re-deriving
	// from the service ID.
	AgentNetwork bool
}

// DenyReason is the structured payload a middleware returns alongside
// a DecisionDeny. The proxy renders it through a fixed JSON template
// so middlewares cannot emit arbitrary bytes to the wire.
type DenyReason struct {
	Code    string
	Message string
	Details map[string]string
}

// Output is the value each middleware returns to the dispatcher. The
// dispatcher applies the output filter (clamp, mutations gate) before
// any side effect reaches the shared request.
type Output struct {
	Decision   Decision
	DenyStatus int
	DenyReason *DenyReason
	Metadata   []KV
	Mutations  *Mutations
}

// Mutations describes the deltas a middleware wants applied to the
// in-flight request. The dispatcher filters HeadersAdd/HeadersRemove
// through the compiled-in denylist and runs BodyReplace through the
// body policy before anything is applied. RewriteUpstream redirects
// the outbound target (scheme + host) for the request; the chain
// returns the latest non-nil rewrite to the reverse proxy.
type Mutations struct {
	HeadersAdd      []KV
	HeadersRemove   []string
	BodyReplace     []byte
	RewriteUpstream *UpstreamRewrite
}

// UpstreamRewrite redirects the request's outbound target. Only
// scheme+host are honoured; path, query, and body are untouched. The
// reverse proxy reads the rewrite (when non-nil) instead of the
// PathTarget URL configured by the synth, so a single shared synth
// service can fan out to many upstreams selected per request.
//
// AuthHeader and StripHeaders carry the upstream auth substitution
// the router needs. They bypass the framework's HeadersAdd /
// HeadersRemove denylist (which blocks Authorization, Cookie, etc.
// from middleware mutation) on the grounds that the proxy itself is
// the entity rewriting auth here, not an arbitrary middleware. The
// reverse proxy applies them directly to the upstream request after
// the chain's regular mutation phase, so a malicious or misconfigured
// middleware can still emit RewriteUpstream but only the proxy's
// trusted upstream-build path actually unpacks AuthHeader.
type UpstreamRewrite struct {
	Scheme string
	Host   string
	// Path, when non-empty, replaces the path component of the
	// proxy's effective upstream URL. The rewrite path is then joined
	// with the agent's request path by httputil.ProxyRequest.SetURL —
	// e.g. rewrite Path="/v1/{account}/{gateway}/compat" + agent
	// request "/chat/completions" → outbound
	// "/v1/{account}/{gateway}/compat/chat/completions". Used by
	// llm_router to honor the operator-configured upstream path on
	// gateways like Cloudflare AI Gateway whose URL contains
	// account / gateway segments that the agent's app doesn't know
	// about. Empty Path leaves the original target's path
	// untouched (the historical behavior).
	Path string
	// StripPathPrefix, when non-empty, is removed from the front of the agent's
	// request path before it is joined onto the upstream URL. Used for
	// gateway-namespace prefixes (e.g. a client addressing Bedrock as
	// "/bedrock/model/{id}/invoke") that must not reach the real upstream, whose
	// native path is "/model/{id}/invoke". Empty leaves the request path intact.
	StripPathPrefix string
	AuthHeader      *AuthHeader
	StripHeaders    []string
}

// AuthHeader is a single name/value pair the proxy injects on the
// upstream request after stripping the client's auth headers.
type AuthHeader struct {
	Name  string
	Value string
}

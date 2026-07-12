package llm_identity_inject

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// ProviderInjection describes one resolved provider's injection rule.
// Identity stamping uses one of HeaderPair / JSONMetadata; ExtraHeaders
// is independent — each entry is a static (operator-configured) header
// stamped on every matching request with anti-spoof. A rule with no
// shape AND no extras is dropped at New() time as a no-op.
type ProviderInjection struct {
	// ProviderID is the resolved provider id — matches the value
	// llm_router stamps under KeyLLMResolvedProviderID.
	ProviderID string `json:"provider_id"`
	// HeaderPair is the LiteLLM-style wire convention: separate
	// headers for end-user id and tags CSV.
	HeaderPair *HeaderPairRule `json:"header_pair,omitempty"`
	// JSONMetadata is the Portkey-style wire convention: a single
	// header carrying a JSON object keyed by reserved field names.
	JSONMetadata *JSONMetadataRule `json:"json_metadata,omitempty"`
	// ExtraHeaders is an operator-configured list of static headers
	// (e.g. "x-portkey-config: pc-...") that the middleware stamps
	// on every matching request. The synth pre-resolves the values
	// from the provider record's ExtraValues map; the middleware
	// just emits them. Each name is also added to HeadersRemove for
	// anti-spoof so a client can't smuggle their own value.
	ExtraHeaders []ExtraHeaderKV `json:"extra_headers,omitempty"`
}

// ExtraHeaderKV is one static header entry the middleware stamps as-is.
type ExtraHeaderKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HeaderPairRule emits identity through dedicated per-dimension
// headers. The two *InBody flags layer body-level identity on top: when
// TagsInBody is set the middleware also writes the tag list into the
// request body's metadata.tags array (required for LiteLLM tag-budget
// enforcement, which only inspects the body); when EndUserIDInBody is
// set the display identity is also written into the body's top-level
// "user" field (the OpenAI-standard end-user identifier — defense-in-
// depth and anti-spoof on top of the header path).
type HeaderPairRule struct {
	EndUserIDHeader string `json:"end_user_id_header,omitempty"`
	TagsHeader      string `json:"tags_header,omitempty"`
	TagsInBody      bool   `json:"tags_in_body,omitempty"`
	EndUserIDInBody bool   `json:"end_user_id_in_body,omitempty"`
}

// JSONMetadataRule emits identity through a single JSON-object header.
// Empty UserKey/GroupsKey skip that dimension at emit time. When
// MaxValueLength > 0 each emitted JSON value is truncated to that many
// bytes — Portkey enforces 128 chars per value.
type JSONMetadataRule struct {
	Header         string `json:"header"`
	UserKey        string `json:"user_key,omitempty"`
	GroupsKey      string `json:"groups_key,omitempty"`
	MaxValueLength int    `json:"max_value_length,omitempty"`
}

// Config is the on-wire configuration accepted by the factory. An
// empty Providers slice yields a no-op middleware (every resolved
// provider passes through unchanged).
type Config struct {
	Providers []ProviderInjection `json:"providers"`
}

// Factory builds llm_identity_inject instances from raw config bytes.
type Factory struct{}

// ID returns the registry identifier.
func (Factory) ID() string { return ID }

// New constructs a middleware instance. Empty, null, and {} configs
// yield a no-op middleware. Non-empty payloads must parse cleanly so
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
// empty object/array.
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

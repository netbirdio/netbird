// Package llm_identity_inject implements the SlotOnRequest middleware
// that stamps the caller's NetBird identity onto upstream LLM-gateway
// requests. It runs after llm_router (which resolves the provider) and
// looks up the resolved provider id against a per-account injection
// table built by the synthesiser from the catalog's IdentityInjection
// metadata.
//
// Two wire shapes are supported, dispatched per-rule:
//
//   - HeaderPair (LiteLLM-style): separate end-user-id and tags
//     headers; tags emitted as a CSV value.
//   - JSONMetadata (Portkey-style): one header carrying a JSON
//     object with reserved keys for user / groups; per-value byte
//     length capped when the rule sets MaxValueLength.
//
// In both cases, identity comes from Input.UserEmail (peer-attached
// user's email or peer.Name fallback) and groups come from the
// authorising-groups intersection llm_router emitted (with
// id→display-name translation via Input.UserGroups / UserGroupNames
// positional pairing). HeadersRemove runs before HeadersAdd in the
// framework, so a client can never spoof identity by stamping these
// headers themselves.
package llm_identity_inject

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// ID is the registry identifier for this middleware.
const ID = "llm_identity_inject"

// Version is reported via Middleware.Version().
const Version = "1.0.0"

// Middleware stamps NetBird identity onto upstream requests for the
// configured set of resolved providers.
type Middleware struct {
	cfg   Config
	byID  map[string]ProviderInjection
}

// New constructs a Middleware from the supplied configuration. A nil
// or empty Providers slice yields a no-op middleware.
func New(cfg Config) *Middleware {
	byID := make(map[string]ProviderInjection, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if p.ProviderID == "" {
			continue
		}
		// Drop entries that wouldn't inject anything — keeps the
		// runtime check tight. Also drop entries that set both
		// shapes (configuration error; refuse to guess which wins).
		// Extras alone are enough to keep the rule alive even if
		// neither identity shape is set.
		hasExtras := false
		for _, e := range p.ExtraHeaders {
			if e.Name != "" && e.Value != "" {
				hasExtras = true
				break
			}
		}
		switch {
		case p.HeaderPair != nil && p.JSONMetadata != nil:
			continue
		case p.HeaderPair != nil:
			if p.HeaderPair.EndUserIDHeader == "" && p.HeaderPair.TagsHeader == "" && !p.HeaderPair.TagsInBody && !p.HeaderPair.EndUserIDInBody && !hasExtras {
				continue
			}
		case p.JSONMetadata != nil:
			if p.JSONMetadata.Header == "" {
				continue
			}
			if p.JSONMetadata.UserKey == "" && p.JSONMetadata.GroupsKey == "" && !hasExtras {
				continue
			}
		default:
			if !hasExtras {
				continue
			}
		}
		byID[p.ProviderID] = p
	}
	return &Middleware{cfg: cfg, byID: byID}
}

// ID returns the registry identifier.
func (m *Middleware) ID() string { return ID }

// Version returns the implementation version.
func (m *Middleware) Version() string { return Version }

// Slot reports the chain slot the middleware lives in.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnRequest }

// AcceptedContentTypes returns nil — this middleware reads only
// metadata and identity fields on the Input envelope.
func (m *Middleware) AcceptedContentTypes() []string { return nil }

// MetadataKeys is empty: the middleware emits no metadata. Identity
// stamping is a header-only operation.
func (m *Middleware) MetadataKeys() []string { return nil }

// MutationsSupported reports that the middleware emits header
// mutations on the Output envelope.
func (m *Middleware) MutationsSupported() bool { return true }

// Close releases resources owned by the middleware. Stateless, so
// this is a no-op.
func (m *Middleware) Close() error { return nil }

// Invoke stamps identity headers when the resolved provider has an
// injection rule. Always Allow.
func (m *Middleware) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	out := &middleware.Output{Decision: middleware.DecisionAllow}
	if len(m.byID) == 0 || in == nil {
		return out, nil
	}
	resolved, ok := lookupMetadata(in.Metadata, middleware.KeyLLMResolvedProviderID)
	if !ok || resolved == "" {
		return out, nil
	}
	rule, ok := m.byID[resolved]
	if !ok {
		return out, nil
	}

	var mutations *middleware.Mutations
	switch {
	case rule.HeaderPair != nil:
		mutations = applyHeaderPair(rule.HeaderPair, in)
	case rule.JSONMetadata != nil:
		mutations = applyJSONMetadata(rule.JSONMetadata, in)
	}

	// ExtraHeaders are independent of the identity shape. Stamp each
	// non-empty entry with anti-spoof: Remove first (frame strips it
	// before our Add lands) so a client can't smuggle a value, then
	// Add our trusted one.
	if len(rule.ExtraHeaders) > 0 {
		if mutations == nil {
			mutations = &middleware.Mutations{}
		}
		for _, h := range rule.ExtraHeaders {
			if h.Name == "" || h.Value == "" {
				continue
			}
			mutations.HeadersRemove = append(mutations.HeadersRemove, h.Name)
			mutations.HeadersAdd = append(mutations.HeadersAdd, middleware.KV{
				Key:   h.Name,
				Value: h.Value,
			})
		}
	}

	if mutations == nil || (len(mutations.HeadersAdd) == 0 && len(mutations.HeadersRemove) == 0 && len(mutations.BodyReplace) == 0) {
		return out, nil
	}
	out.Mutations = mutations
	return out, nil
}

// applyHeaderPair builds the LiteLLM-style mutations: separate per-
// dimension headers, with anti-spoof Removes paired with trusted Adds.
func applyHeaderPair(rule *HeaderPairRule, in *middleware.Input) *middleware.Mutations {
	mutations := &middleware.Mutations{}

	if rule.EndUserIDHeader != "" {
		mutations.HeadersRemove = append(mutations.HeadersRemove, rule.EndUserIDHeader)
		// Prefer the email when the auth path carried it: gateways
		// like LiteLLM key per-user budgets and dashboards on a
		// human-readable identifier; the user_id is an opaque
		// management-server primary key. Fall back to user_id when
		// no email is available (non-OIDC schemes, legacy JWTs).
		if identity := identityFor(in); identity != "" {
			mutations.HeadersAdd = append(mutations.HeadersAdd, middleware.KV{
				Key:   rule.EndUserIDHeader,
				Value: identity,
			})
		}
	}

	if rule.TagsHeader != "" {
		mutations.HeadersRemove = append(mutations.HeadersRemove, rule.TagsHeader)
		if csv := authorisingTagsCSV(in); csv != "" {
			mutations.HeadersAdd = append(mutations.HeadersAdd, middleware.KV{
				Key:   rule.TagsHeader,
				Value: csv,
			})
		}
	}

	if rule.TagsInBody || rule.EndUserIDInBody {
		// Body-level identity unlocks gateway behaviour the header
		// path can't reach (LiteLLM's _tag_max_budget_check only
		// inspects the body; OpenAI direct only reads the body's
		// "user" field for attribution). The header path stays
		// intact, so we still get attribution + per-end-user budget
		// gating when body inject can't run (truncated body,
		// non-JSON, hostile metadata shape).
		var bodyTags []string
		if rule.TagsInBody {
			bodyTags = authorisingTagsSlice(in)
		}
		var bodyUser string
		if rule.EndUserIDInBody {
			bodyUser = identityFor(in)
		}
		if newBody, ok := injectIntoBody(in, bodyTags, bodyUser); ok {
			mutations.BodyReplace = newBody
		}
	}

	return mutations
}

// injectIntoBody parses the request body and writes the supplied
// identity dimensions into it. Tags land at metadata.tags (creating
// the metadata object when absent); the user identity lands at the
// top-level "user" field (OpenAI-standard end-user identifier).
// Returns the re-marshaled body and ok=true when at least one field
// was written. Returns ok=false (no mutation) when:
//
//   - both inputs are empty (nothing to write);
//   - the body is empty or truncated (we don't have the full document
//     to safely round-trip);
//   - the body isn't a JSON object (skip silently — this middleware
//     only knows how to inject into OpenAI-compatible JSON payloads).
//
// A non-object existing `metadata` field skips the tag write but
// still allows the user write to land — we don't clobber the client's
// non-object metadata, but the orthogonal user field is fair game.
// The header path emission still runs in skip cases, so spend tracking
// + header-resolved end-user budgets continue to work without body-
// level enforcement.
func injectIntoBody(in *middleware.Input, tags []string, userID string) ([]byte, bool) {
	wantTags := len(tags) > 0
	wantUser := userID != ""
	if !wantTags && !wantUser {
		return nil, false
	}
	if in == nil || len(in.Body) == 0 || in.BodyTruncated {
		return nil, false
	}
	var doc map[string]any
	if err := json.Unmarshal(in.Body, &doc); err != nil {
		return nil, false
	}
	injected := false
	if wantTags {
		var meta map[string]any
		if existing, ok := doc["metadata"]; ok {
			if typed, isObject := existing.(map[string]any); isObject {
				meta = typed
			}
			// non-object metadata: leave it; tags go unwritten so we
			// don't clobber the client's value. Header fallback covers
			// spend tracking.
		} else {
			meta = map[string]any{}
		}
		if meta != nil {
			meta["tags"] = tags
			doc["metadata"] = meta
			injected = true
		}
	}
	if wantUser {
		// Anti-spoof: overwrite any client-supplied "user" so the
		// gateway only sees our trusted identity.
		doc["user"] = userID
		injected = true
	}
	if !injected {
		return nil, false
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

// applyJSONMetadata builds the Portkey-style mutations: a single header
// carrying a JSON object keyed by the rule's reserved field names. Per-
// value byte length is capped at MaxValueLength when set (Portkey
// enforces 128 chars).
func applyJSONMetadata(rule *JSONMetadataRule, in *middleware.Input) *middleware.Mutations {
	mutations := &middleware.Mutations{}
	mutations.HeadersRemove = append(mutations.HeadersRemove, rule.Header)

	payload := map[string]string{}
	if rule.UserKey != "" {
		if identity := identityFor(in); identity != "" {
			payload[rule.UserKey] = truncate(identity, rule.MaxValueLength)
		}
	}
	if rule.GroupsKey != "" {
		if csv := authorisingTagsCSV(in); csv != "" {
			payload[rule.GroupsKey] = truncate(csv, rule.MaxValueLength)
		}
	}
	if len(payload) == 0 {
		return mutations
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return mutations
	}
	mutations.HeadersAdd = append(mutations.HeadersAdd, middleware.KV{
		Key:   rule.Header,
		Value: string(raw),
	})
	return mutations
}

// identityFor returns the caller's display identity. UserEmail wins
// (carries the user email when peer-attached, peer.Name otherwise);
// UserID falls in only as a defensive last resort.
func identityFor(in *middleware.Input) string {
	if in.UserEmail != "" {
		return in.UserEmail
	}
	return in.UserID
}

// authorisingTagsSlice returns the sorted, deduplicated slice of group
// display names the request was authorised under. Prefers the per-
// request authorising groups emitted by llm_router (intersection of the
// caller's UserGroups with the resolved route's AllowedGroupIDs) so the
// tags carry only the groups that actually authorise THIS request, not
// every group the peer happens to be in. Falls back to the full
// UserGroups when the router metadata key is absent.
func authorisingTagsSlice(in *middleware.Input) []string {
	ids := tagsIDsFromAuthorising(in.Metadata)
	if len(ids) == 0 {
		ids = in.UserGroups
	}
	return tagsNamedSlice(ids, in.UserGroups, in.UserGroupNames)
}

// authorisingTagsCSV is a convenience wrapper that joins
// authorisingTagsSlice with commas for HeaderPair-style emission.
func authorisingTagsCSV(in *middleware.Input) string {
	return strings.Join(authorisingTagsSlice(in), ",")
}

// truncate caps s to maxBytes bytes when maxBytes > 0. No-op when
// maxBytes <= 0 or s already fits. Truncation is byte-wise — sufficient
// for Portkey's 128-char ASCII limit. UTF-8 sequences could in theory
// be split, but the gateway treats the value as opaque bytes.
func truncate(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes]
}

// tagsIDsFromAuthorising reads llm_router's authorising-groups metadata
// (a CSV of group ids) and returns the parsed slice. Returns nil when
// the key is absent or empty so the caller can fall back to the full
// UserGroups.
func tagsIDsFromAuthorising(meta []middleware.KV) []string {
	v, ok := lookupMetadata(meta, middleware.KeyLLMAuthorisingGroups)
	if !ok {
		return nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// tagsNamedSlice returns the sorted, deduplicated list of group display
// names. ids carries the canonical group identifiers to emit;
// userGroups + userGroupNames provide the positional id→name
// translation table from the Input envelope. When a name is missing
// for a given id (slice shorter than userGroups, or id absent from the
// table), the id is used verbatim so the tag still attributes
// correctly. Sorted so the same caller produces the same header value
// across requests (helps gateway-side cache hits and log correlation).
func tagsNamedSlice(ids, userGroups, userGroupNames []string) []string {
	if len(ids) == 0 {
		return nil
	}
	idToName := make(map[string]string, len(userGroups))
	for i, id := range userGroups {
		if i < len(userGroupNames) {
			idToName[id] = userGroupNames[i]
		}
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		tag := idToName[id]
		if tag == "" {
			tag = id
		}
		if _, dup := seen[tag]; dup {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// lookupMetadata returns the value for key plus a presence flag.
func lookupMetadata(meta []middleware.KV, key string) (string, bool) {
	for _, kv := range meta {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

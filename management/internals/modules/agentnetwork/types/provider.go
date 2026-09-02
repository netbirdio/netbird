package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/util/crypt"
)

// ProviderModel is one row in the provider's models list. The operator
// pins the per-1k input/output price for cost tracking; ID is the
// model identifier the upstream provider expects on the wire.
//
// The three cache rates are pointers because absence is meaningful: nil
// means "inherit NetBird's default rate for this model" (folded in at
// synthesis time), while an explicit 0 means "no discount — bill this
// cache bucket at the input rate".
type ProviderModel struct {
	ID          string  `json:"id"`
	InputPer1k  float64 `json:"input_per_1k"`
	OutputPer1k float64 `json:"output_per_1k"`
	// CachedInputPer1k is the OpenAI-shape rate for cached prompt tokens
	// (a subset of input tokens).
	CachedInputPer1k *float64 `json:"cached_input_per_1k,omitempty"`
	// CacheReadPer1k is the Anthropic-shape rate for cache-read tokens
	// (additive to input tokens).
	CacheReadPer1k *float64 `json:"cache_read_per_1k,omitempty"`
	// CacheCreationPer1k is the Anthropic-shape rate for cache-creation
	// tokens (additive to input tokens).
	CacheCreationPer1k *float64 `json:"cache_creation_per_1k,omitempty"`
}

// Provider is an Agent Network AI provider record persisted per account.
// The proxy cluster fronting the account lives on the per-account
// agent-network Settings row, not on the Provider — every provider in
// an account routes through the same cluster.
type Provider struct {
	ID         string `gorm:"primaryKey"`
	AccountID  string `gorm:"index"`
	ProviderID string `gorm:"index:idx_agent_network_provider"`
	Name       string
	// UpstreamURL is the full upstream URL (e.g. https://api.openai.com)
	// the operator selected.
	UpstreamURL string `gorm:"column:upstream_url"`
	APIKey      string `gorm:"column:api_key"`
	// ExtraValues holds operator-typed values for catalog-declared
	// ExtraHeaders (see catalog.Provider.ExtraHeaders). Keyed by
	// header name (e.g. "x-portkey-config"); a non-empty value is
	// stamped on every upstream request to this provider via the
	// proxy's identity-inject middleware (anti-spoof Remove + Add).
	// Empty / missing keys = no header stamped. Stored as a JSON
	// blob so the schema doesn't grow per-catalog-entry.
	ExtraValues map[string]string `gorm:"serializer:json;column:extra_values"`
	// Models is the operator's curated list of models exposed by this
	// provider together with their per-1k input/output prices (USD).
	// Empty means all catalog models are allowed at catalog prices.
	Models  []ProviderModel `gorm:"serializer:json"`
	Enabled bool
	// SkipTLSVerification disables upstream TLS certificate verification for
	// this provider's URL. For self-hosted / internal gateways fronted by a
	// private or self-signed certificate. The synthesiser propagates it into
	// the router route so the proxy dials that provider's upstream insecurely.
	SkipTLSVerification bool `gorm:"column:skip_tls_verification"`
	// MetadataDisabled suppresses identity metadata injection for this provider.
	// Metadata (the caller's user + authorizing group) is injected by default;
	// when true the synthesiser omits the provider's identity-inject shape, so no
	// user/group headers (e.g. Bedrock's X-Amzn-Bedrock-Request-Metadata) are
	// stamped. Catalog ExtraHeaders (routing config) are unaffected.
	MetadataDisabled bool `gorm:"column:metadata_disabled"`
	// SessionPrivateKey + SessionPublicKey are the ed25519 keypair the
	// synthesised reverse-proxy service uses to sign / verify session
	// JWTs after a successful OIDC handshake. Generated once on
	// provider create and never rotated by the manager so existing
	// session cookies survive provider edits. SessionPrivateKey is
	// encrypted at rest via EncryptSensitiveData /
	// DecryptSensitiveData; SessionPublicKey is plain.
	SessionPrivateKey string `gorm:"column:session_private_key"`
	SessionPublicKey  string `gorm:"column:session_public_key"`
	// IdentityHeaderUserID + IdentityHeaderGroups are the operator-
	// chosen wire header names for HeaderPair-style identity
	// injection on catalog entries that flag the shape as
	// Customizable (e.g. Bifrost, where the operator picks between
	// the always-on x-bf-lh- log-metadata family and the
	// label-declared x-bf-dim- telemetry family). Empty value
	// disables stamping for that dimension; the inject middleware
	// already no-ops on empty header names. Catalog entries with
	// Customizable=false ignore these fields and use the static
	// header names defined in their HeaderPairInjection block.
	IdentityHeaderUserID string `gorm:"column:identity_header_user_id"`
	IdentityHeaderGroups string `gorm:"column:identity_header_groups"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// TableName uses an explicit name so the Agent Network provider rows live
// in their own table, separate from any future "providers"-named entity.
func (Provider) TableName() string { return "agent_network_providers" }

// NewProvider returns a new Provider with a freshly minted ID.
func NewProvider(accountID string) *Provider {
	now := time.Now().UTC()
	return &Provider{
		ID:        xid.New().String(),
		AccountID: accountID,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// FromAPIRequest applies the request payload onto the receiver. The api_key
// is only overwritten when the caller provided one — empty/nil leaves the
// existing key intact, so updates can omit it.
func (p *Provider) FromAPIRequest(req *api.AgentNetworkProviderRequest) {
	p.ProviderID = req.ProviderId
	p.Name = req.Name
	p.UpstreamURL = req.UpstreamUrl
	if req.ApiKey != nil && strings.TrimSpace(*req.ApiKey) != "" {
		p.APIKey = *req.ApiKey
	}
	if req.ExtraValues != nil {
		// Replace the whole map (rather than merge) so unsetting a
		// value on the dashboard actually clears it. Empty strings
		// are dropped so we don't waste a row on no-op values.
		next := make(map[string]string, len(*req.ExtraValues))
		for k, v := range *req.ExtraValues {
			v = strings.TrimSpace(v)
			if v != "" {
				next[k] = v
			}
		}
		if len(next) == 0 {
			p.ExtraValues = nil
		} else {
			p.ExtraValues = next
		}
	}
	p.Models = p.Models[:0]
	if req.Models != nil {
		for _, m := range *req.Models {
			p.Models = append(p.Models, ProviderModel{
				ID:                 m.Id,
				InputPer1k:         m.InputPer1k,
				OutputPer1k:        m.OutputPer1k,
				CachedInputPer1k:   copyFloatPtr(m.CachedInputPer1k),
				CacheReadPer1k:     copyFloatPtr(m.CacheReadPer1k),
				CacheCreationPer1k: copyFloatPtr(m.CacheCreationPer1k),
			})
		}
	}
	if p.Models == nil {
		p.Models = []ProviderModel{}
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	if req.SkipTlsVerification != nil {
		p.SkipTLSVerification = *req.SkipTlsVerification
	}
	if req.MetadataDisabled != nil {
		p.MetadataDisabled = *req.MetadataDisabled
	}
	// Identity-header overrides for catalogs flagged Customizable.
	// Empty or omitted disables stamping for this dimension.
	if req.IdentityHeaderUserId != nil {
		p.IdentityHeaderUserID = strings.TrimSpace(*req.IdentityHeaderUserId)
	}
	if req.IdentityHeaderGroups != nil {
		p.IdentityHeaderGroups = strings.TrimSpace(*req.IdentityHeaderGroups)
	}
}

// ToAPIResponse renders the provider as the API representation. The API
// key is intentionally never surfaced.
// RedactedForViewer returns a copy with the connection configuration
// blanked: upstream URL, operator-typed extra header values, identity
// header names, the TLS-verification override, and (defence in depth —
// they never reach the wire anyway) the sealed credentials. Read-only
// viewers such as usage_viewer only need the display surface — id,
// catalog id, name, enabled state, and the model list the usage filters
// resolve against — so their responses carry nothing about how the
// operator connects to the vendor.
func (p *Provider) RedactedForViewer() *Provider {
	c := *p
	c.UpstreamURL = ""
	c.APIKey = ""
	c.ExtraValues = nil
	c.IdentityHeaderUserID = ""
	c.IdentityHeaderGroups = ""
	c.SkipTLSVerification = false
	c.SessionPrivateKey = ""
	return &c
}

func (p *Provider) ToAPIResponse() *api.AgentNetworkProvider {
	models := make([]api.AgentNetworkProviderModel, 0, len(p.Models))
	for _, m := range p.Models {
		models = append(models, api.AgentNetworkProviderModel{
			Id:                 m.ID,
			InputPer1k:         m.InputPer1k,
			OutputPer1k:        m.OutputPer1k,
			CachedInputPer1k:   copyFloatPtr(m.CachedInputPer1k),
			CacheReadPer1k:     copyFloatPtr(m.CacheReadPer1k),
			CacheCreationPer1k: copyFloatPtr(m.CacheCreationPer1k),
		})
	}
	created := p.CreatedAt
	updated := p.UpdatedAt
	resp := &api.AgentNetworkProvider{
		Id:          p.ID,
		ProviderId:  p.ProviderID,
		Name:        p.Name,
		UpstreamUrl: p.UpstreamURL,
		Models:      models,
		// Always present on the wire so an explicitly cleared header
		// round-trips as "" instead of vanishing from the response.
		IdentityHeaderUserId: p.IdentityHeaderUserID,
		IdentityHeaderGroups: p.IdentityHeaderGroups,
		Enabled:              p.Enabled,
		SkipTlsVerification:  p.SkipTLSVerification,
		MetadataDisabled:     p.MetadataDisabled,
		CreatedAt:            &created,
		UpdatedAt:            &updated,
	}
	if len(p.ExtraValues) > 0 {
		out := make(map[string]string, len(p.ExtraValues))
		for k, v := range p.ExtraValues {
			out[k] = v
		}
		resp.ExtraValues = &out
	}
	return resp
}

// copyFloatPtr returns a fresh pointer to the same value, or nil. Keeps
// stored models and API payloads from aliasing each other's rate fields.
func copyFloatPtr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

// Copy returns a deep copy of the provider.
func (p *Provider) Copy() *Provider {
	clone := *p
	if p.Models != nil {
		clone.Models = make([]ProviderModel, len(p.Models))
		for i, m := range p.Models {
			m.CachedInputPer1k = copyFloatPtr(m.CachedInputPer1k)
			m.CacheReadPer1k = copyFloatPtr(m.CacheReadPer1k)
			m.CacheCreationPer1k = copyFloatPtr(m.CacheCreationPer1k)
			clone.Models[i] = m
		}
	}
	if p.ExtraValues != nil {
		clone.ExtraValues = make(map[string]string, len(p.ExtraValues))
		for k, v := range p.ExtraValues {
			clone.ExtraValues[k] = v
		}
	}
	return &clone
}

// EventMeta is the audit-log payload for activity events.
func (p *Provider) EventMeta() map[string]any {
	return map[string]any{
		"name":        p.Name,
		"provider_id": p.ProviderID,
	}
}

// EncryptSensitiveData encrypts the upstream API key and the session
// signing key in place.
func (p *Provider) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}
	if p.APIKey != "" {
		encrypted, err := enc.Encrypt(p.APIKey)
		if err != nil {
			return fmt.Errorf("encrypt agent network provider api key: %w", err)
		}
		p.APIKey = encrypted
	}
	if p.SessionPrivateKey != "" {
		encrypted, err := enc.Encrypt(p.SessionPrivateKey)
		if err != nil {
			return fmt.Errorf("encrypt agent network provider session key: %w", err)
		}
		p.SessionPrivateKey = encrypted
	}
	return nil
}

// DecryptSensitiveData decrypts the upstream API key and the session
// signing key in place.
func (p *Provider) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}
	if p.APIKey != "" {
		decrypted, err := enc.Decrypt(p.APIKey)
		if err != nil {
			return fmt.Errorf("decrypt agent network provider api key: %w", err)
		}
		p.APIKey = decrypted
	}
	if p.SessionPrivateKey != "" {
		decrypted, err := enc.Decrypt(p.SessionPrivateKey)
		if err != nil {
			return fmt.Errorf("decrypt agent network provider session key: %w", err)
		}
		p.SessionPrivateKey = decrypted
	}
	return nil
}

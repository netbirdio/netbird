package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// DefaultAccessLogRetentionDays is the retention applied to new accounts'
// agent-network access logs. Usage records are not subject to this — they are
// the long-term aggregate and are retained independently.
const DefaultAccessLogRetentionDays = 30

// Settings is the per-account agent-network configuration row. One row per
// account. Domain and ProxyAddress are assigned at bootstrap and immutable
// thereafter; a persisted row is always fully allocated — there is no "row
// exists, endpoint pending" state.
type Settings struct {
	AccountID string `gorm:"primaryKey"`

	// Domain is the gateway endpoint hostname agents call. Globally unique
	// across accounts. Sized explicitly because MySQL cannot index an
	// unbounded TEXT column; 255 covers the RFC 1035 253-octet bound.
	Domain string `gorm:"type:varchar(255);uniqueIndex:idx_agent_network_settings_domain"`

	// ProxyAddress is the declared cluster address of the proxy serving this
	// account's gateway. Either equal to Domain — a proxy dedicated to this
	// account, declaring the tenant's own hostname — or Domain's immediate
	// parent, with the endpoint one label beneath it on a shared cluster.
	ProxyAddress string `gorm:"type:varchar(255);index:idx_agent_network_settings_proxy_address"`

	// Account-level collection controls sourced by the synthesizer.
	// EnableLogCollection gates the per-request access-log trail and defaults
	// ON for new accounts. EnablePromptCollection is the master gate for
	// request/response prompt capture (AND-gated with the policy-level
	// guardrail). RedactPii enables PII redaction on captured prompts;
	// effective redaction is account OR policy.
	EnableLogCollection    bool
	EnablePromptCollection bool
	RedactPii              bool

	// AccessLogRetentionDays bounds how long full access-log rows are kept; a
	// periodic sweep deletes older rows. <= 0 means keep indefinitely. Usage
	// records are unaffected.
	AccessLogRetentionDays int

	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName puts the rows in their own table to keep the agent-network
// schema cohesive.
func (Settings) TableName() string { return "agent_network_settings" }

// DefaultSettings returns the settings an account observes before its row is
// bootstrapped: log collection on with the default retention, everything else
// off, and no domain or proxy address assigned yet. Bootstrap persists exactly
// these values plus the assigned domain and proxy address, so the
// pre-bootstrap read and the freshly bootstrapped row agree.
func DefaultSettings(accountID string) *Settings {
	return &Settings{
		AccountID:              accountID,
		EnableLogCollection:    true,
		AccessLogRetentionDays: DefaultAccessLogRetentionDays,
	}
}

// Endpoint returns the bare hostname agents reach this account at — the
// Domain column. Empty until the row is bootstrapped.
func (s *Settings) Endpoint() string { return s.Domain }

// Dedicated reports whether the account's gateway is served by a proxy
// dedicated to it — the self-addressed shape, where the serving proxy declares
// the endpoint hostname itself. The alternative (labeled) shape has the
// endpoint one label beneath a shared cluster's address.
func (s *Settings) Dedicated() bool { return s.Domain != "" && s.Domain == s.ProxyAddress }

// ToAPIResponse renders the settings as the API representation. The
// timestamps are omitted while zero — a default (not yet bootstrapped) view
// has no persisted row to date.
func (s *Settings) ToAPIResponse() *api.AgentNetworkSettings {
	retention := s.AccessLogRetentionDays
	resp := &api.AgentNetworkSettings{
		Endpoint:               s.Endpoint(),
		ProxyAddress:           s.ProxyAddress,
		Dedicated:              s.Dedicated(),
		EnableLogCollection:    s.EnableLogCollection,
		EnablePromptCollection: s.EnablePromptCollection,
		RedactPii:              s.RedactPii,
		AccessLogRetentionDays: &retention,
	}
	if !s.CreatedAt.IsZero() {
		created := s.CreatedAt
		resp.CreatedAt = &created
	}
	if !s.UpdatedAt.IsZero() {
		updated := s.UpdatedAt
		resp.UpdatedAt = &updated
	}
	return resp
}

// FromAPIRequest applies the update request onto the receiver: the mutable
// collection fields are always replaced with the request values. The identity
// fields (Domain, ProxyAddress) are assigned at bootstrap and are not part of
// the update schema at all — immutability by shape, not by rejection.
func (s *Settings) FromAPIRequest(req *api.AgentNetworkSettingsRequest) {
	s.EnableLogCollection = req.EnableLogCollection
	s.EnablePromptCollection = req.EnablePromptCollection
	s.RedactPii = req.RedactPii
	if req.AccessLogRetentionDays != nil {
		s.AccessLogRetentionDays = *req.AccessLogRetentionDays
	}
}

// FromAPICreateRequest applies the optional collection toggles of a bootstrap
// request onto the receiver (typically DefaultSettings), leaving defaults in
// place for omitted fields. The identity fields are resolved by the manager
// from the request's proxy_address / endpoint, not copied here.
func (s *Settings) FromAPICreateRequest(req *api.AgentNetworkSettingsCreateRequest) {
	if req.EnableLogCollection != nil {
		s.EnableLogCollection = *req.EnableLogCollection
	}
	if req.EnablePromptCollection != nil {
		s.EnablePromptCollection = *req.EnablePromptCollection
	}
	if req.RedactPii != nil {
		s.RedactPii = *req.RedactPii
	}
	if req.AccessLogRetentionDays != nil {
		s.AccessLogRetentionDays = *req.AccessLogRetentionDays
	}
}

// maxHostnameLength is the RFC 1035 bound on a full domain name.
const maxHostnameLength = 253

// NormalizeHostname lowercases and trims a caller-supplied hostname and
// validates its shape: non-empty DNS labels of letters, digits and inner
// hyphens, joined by single dots, within length bounds. Shapes that
// canonicalization cannot repair — leading/trailing dots, empty labels,
// whitespace inside the name — are rejected rather than guessed at, because
// the value lands in an immutable column.
func NormalizeHostname(raw string) (string, error) {
	hostname := strings.ToLower(strings.TrimSpace(raw))
	if hostname == "" {
		return "", fmt.Errorf("hostname is empty")
	}
	if len(hostname) > maxHostnameLength {
		return "", fmt.Errorf("hostname exceeds %d characters", maxHostnameLength)
	}
	for _, label := range strings.Split(hostname, ".") {
		if err := validateHostnameLabel(label); err != nil {
			return "", fmt.Errorf("invalid hostname %q: %w", hostname, err)
		}
	}
	return hostname, nil
}

func validateHostnameLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label (leading, trailing or doubled dot)")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q exceeds 63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q must not start or end with a hyphen", label)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return fmt.Errorf("label %q contains invalid character %q", label, r)
		}
	}
	return nil
}

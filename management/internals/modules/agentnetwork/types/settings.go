package types

import (
	"strings"
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// DefaultAccessLogRetentionDays is the retention applied to new accounts'
// agent-network access logs. Usage records are not subject to this — they are
// the long-term aggregate and are retained independently.
const DefaultAccessLogRetentionDays = 30

// Settings is the per-account agent-network configuration row. One
// row per account. Cluster + Subdomain are immutable once written and
// produce the public endpoint agents call (`<subdomain>.<cluster>`).
type Settings struct {
	AccountID string `gorm:"primaryKey"`
	Cluster   string
	Subdomain string `gorm:"index:idx_agent_network_settings_cluster_subdomain"`

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
// off, and no cluster/subdomain assigned yet. Bootstrap persists exactly these
// values plus the assigned cluster and subdomain, so the pre-bootstrap read
// and the freshly bootstrapped row agree.
func DefaultSettings(accountID string) *Settings {
	return &Settings{
		AccountID:              accountID,
		EnableLogCollection:    true,
		AccessLogRetentionDays: DefaultAccessLogRetentionDays,
	}
}

// Endpoint returns the bare hostname agents reach this account at:
// `<subdomain>.<cluster>`. Empty until both halves are assigned at bootstrap.
func (s *Settings) Endpoint() string {
	if s.Cluster == "" || s.Subdomain == "" {
		return ""
	}
	return s.Subdomain + "." + s.Cluster
}

// ToAPIResponse renders the settings as the API representation. The
// timestamps are omitted while zero — a default (not yet bootstrapped) view
// has no persisted row to date.
func (s *Settings) ToAPIResponse() *api.AgentNetworkSettings {
	retention := s.AccessLogRetentionDays
	resp := &api.AgentNetworkSettings{
		Cluster:                s.Cluster,
		Subdomain:              s.Subdomain,
		Endpoint:               s.Endpoint(),
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

// FromAPIRequest applies the request onto the receiver. The mutable
// collection fields are always replaced with the request values. Cluster
// participates only in bootstrap and the immutability check (see
// Manager.UpdateSettings); Subdomain is server-assigned and never taken
// from a request.
func (s *Settings) FromAPIRequest(req *api.AgentNetworkSettingsRequest) {
	if req.Cluster != nil {
		s.Cluster = strings.TrimSpace(*req.Cluster)
	}
	s.EnableLogCollection = req.EnableLogCollection
	s.EnablePromptCollection = req.EnablePromptCollection
	s.RedactPii = req.RedactPii
	if req.AccessLogRetentionDays != nil {
		s.AccessLogRetentionDays = *req.AccessLogRetentionDays
	}
}

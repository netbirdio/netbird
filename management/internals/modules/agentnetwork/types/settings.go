package types

import (
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

// Endpoint returns the bare hostname agents reach this account at:
// `<subdomain>.<cluster>`.
func (s *Settings) Endpoint() string {
	return s.Subdomain + "." + s.Cluster
}

// ToAPIResponse renders the settings as the API representation.
func (s *Settings) ToAPIResponse() *api.AgentNetworkSettings {
	created := s.CreatedAt
	updated := s.UpdatedAt
	retention := s.AccessLogRetentionDays
	return &api.AgentNetworkSettings{
		Cluster:                s.Cluster,
		Subdomain:              s.Subdomain,
		Endpoint:               s.Endpoint(),
		EnableLogCollection:    s.EnableLogCollection,
		EnablePromptCollection: s.EnablePromptCollection,
		RedactPii:              s.RedactPii,
		AccessLogRetentionDays: &retention,
		CreatedAt:              &created,
		UpdatedAt:              &updated,
	}
}

// FromAPIRequest applies the mutable settings fields from the request. Cluster
// and Subdomain are immutable and intentionally not touched here.
func (s *Settings) FromAPIRequest(req *api.AgentNetworkSettingsRequest) {
	s.EnableLogCollection = req.EnableLogCollection
	s.EnablePromptCollection = req.EnablePromptCollection
	s.RedactPii = req.RedactPii
	if req.AccessLogRetentionDays != nil {
		s.AccessLogRetentionDays = *req.AccessLogRetentionDays
	}
}

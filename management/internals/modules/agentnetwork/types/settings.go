package types

import (
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// DefaultAccessLogRetentionDays is the retention applied to new accounts'
// agent-network access logs. Usage records are not subject to this — they are
// the long-term aggregate and are retained independently.
const DefaultAccessLogRetentionDays = 30

// Settings is the per-account agent-network configuration row. One row per
// account. The public endpoint agents call is `<subdomain>.<zone>` when a
// zone is set, else `<subdomain>.<cluster>`. Cluster, Subdomain and Zone are
// immutable once written; ServingProxyAddress is the one mutable column,
// naming which proxy currently serves the account.
type Settings struct {
	AccountID string `gorm:"primaryKey"`
	Cluster   string
	Subdomain string `gorm:"index:idx_agent_network_settings_cluster_subdomain"`
	// Zone is the placement-independent parent zone the endpoint lives under,
	// captured from server config when the row is allocated. Immutable, like
	// Cluster and Subdomain.
	//
	// Empty means "legacy": the endpoint falls back to <subdomain>.<cluster>,
	// which embeds the serving proxy. Existing rows and any deployment that
	// configures no zone keep that behaviour unchanged.
	Zone string

	// ServingProxyAddress is the address of the proxy currently serving this
	// account's gateway. Empty means the account is served by the shared proxy
	// at Cluster; set means a dedicated proxy serves it, and the value is that
	// proxy's address — for a per-account proxy, the account's own gateway
	// hostname.
	//
	// This is the only mutable column on this row. Cluster, Subdomain and Zone
	// are fixed once written, but moving an account onto a dedicated proxy — and
	// moving it back — is exactly one write here. Nothing in this repository
	// writes it: it is set by whatever external process assigns dedicated
	// proxies, and its zero value preserves existing behaviour for every current
	// row and every deployment that assigns none.
	ServingProxyAddress string

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

// Endpoint returns the bare hostname agents reach this account at.
//
// With a Zone set this is `<subdomain>.<zone>` — deliberately independent of
// which proxy serves the account, so moving between a shared and a private
// proxy (or between clusters) is a DNS change only and never alters the
// tenant's address. With no Zone it falls back to the legacy
// `<subdomain>.<cluster>` form.
func (s *Settings) Endpoint() string {
	if s.Zone != "" {
		return s.Subdomain + "." + s.Zone
	}
	return s.Subdomain + "." + s.Cluster
}

// ServingProxy returns the address of the proxy that serves this account's
// gateway: the dedicated proxy when one has been assigned, otherwise the shared
// cluster. This is the value the synthesized service advertises as
// ProxyCluster, which is what mesh-DNS peer selection joins on.
func (s *Settings) ServingProxy() string {
	if s.ServingProxyAddress != "" {
		return s.ServingProxyAddress
	}
	return s.Cluster
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

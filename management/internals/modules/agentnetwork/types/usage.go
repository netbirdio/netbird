package types

import (
	"time"
)

// AgentNetworkUsage is the stripped, always-collected per-request usage record
// powering the Usage overview. Unlike AgentNetworkAccessLog it carries no
// request detail (host/path/source IP/prompt) — only the dimensions needed to
// aggregate and filter spend by user / group / provider / model over time.
//
// It is written unconditionally on every served agent-network request,
// independent of the account's EnableLogCollection toggle: when log collection
// is off the proxy ships a stripped, usage-only entry and management still
// records the usage row (but skips the full AgentNetworkAccessLog row).
type AgentNetworkUsage struct {
	ID                 string    `gorm:"primaryKey"`
	AccountID          string    `gorm:"index"`
	Timestamp          time.Time `gorm:"index"`
	UserID             string    `gorm:"index"`
	ResolvedProviderID string    `gorm:"index"`
	Provider           string    // vendor, e.g. "openai"
	Model              string    `gorm:"index"`
	SessionID          string    `gorm:"index"` // llm.session_id — groups a conversation / coding session
	InputTokens        int64
	OutputTokens       int64
	TotalTokens        int64
	CostUSD            float64
	CreatedAt          time.Time
}

// TableName keeps usage records in their own stripped table. Named
// distinctly (…_request_usage) to avoid colliding with any pre-existing
// agent_network_usage table in a shared database.
func (AgentNetworkUsage) TableName() string { return "agent_network_request_usage" }

// AgentNetworkUsageGroup is the normalised many-to-many row linking a usage
// record to one authorising group, mirroring AgentNetworkAccessLogGroup so the
// usage overview can filter by group with a `group_id IN (...)` join.
type AgentNetworkUsageGroup struct {
	UsageID   string `gorm:"primaryKey"`
	GroupID   string `gorm:"primaryKey;index"`
	AccountID string `gorm:"index"`
}

// TableName names the usage group child table.
func (AgentNetworkUsageGroup) TableName() string { return "agent_network_request_usage_group" }

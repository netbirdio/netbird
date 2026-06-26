package types

import (
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// AgentNetworkAccessLog is the dedicated, flattened agent-network access-log
// row. Unlike the shared reverse-proxy AccessLogEntry (which kept LLM data in
// an opaque metadata JSON blob), the LLM dimensions live in first-class,
// indexed columns so the access-log surface can filter server-side by
// user / group / provider / model / decision.
type AgentNetworkAccessLog struct {
	ID            string    `gorm:"primaryKey"`
	AccountID     string    `gorm:"index"`
	ServiceID     string    `gorm:"index"`
	Timestamp     time.Time `gorm:"index"`
	UserID        string    `gorm:"index"`
	SourceIP      string
	Method        string
	Host          string
	Path          string `gorm:"type:text"`
	Duration      time.Duration
	StatusCode    int `gorm:"index"`
	AuthMethod    string
	BytesUpload   int64
	BytesDownload int64

	// Flattened LLM dimensions (queryable). Sourced from proxy metadata keys.
	Provider           string `gorm:"index"` // vendor, e.g. "openai" (llm.provider)
	Model              string `gorm:"index"` // llm.model
	SessionID          string `gorm:"index"` // llm.session_id — groups a conversation / coding session
	ResolvedProviderID string `gorm:"index"` // llm.resolved_provider_id
	SelectedPolicyID   string `gorm:"index"` // llm.selected_policy_id
	Decision           string `gorm:"index"` // llm_policy.decision (allow/deny)
	DenyReason         string // llm_policy.reason (raw code, mapped in the UI)
	InputTokens        int64
	OutputTokens       int64
	TotalTokens        int64
	CostUSD            float64
	Stream             bool

	// Prompt capture. Only populated when prompt collection is enabled
	// (account master switch AND policy guardrail). Heavy free text.
	RequestPrompt      string `gorm:"type:text"`
	ResponseCompletion string `gorm:"type:text"`

	CreatedAt time.Time

	// GroupIDs is the authorising group ids for this entry, hydrated from the
	// group child table on read. Not a column.
	GroupIDs []string `gorm:"-"`
}

// TableName keeps agent-network access logs in their own table, separate from
// the reverse-proxy AccessLogEntry table.
func (AgentNetworkAccessLog) TableName() string { return "agent_network_access_log" }

// ToAPIResponse renders the flattened entry as the API representation.
func (a *AgentNetworkAccessLog) ToAPIResponse() api.AgentNetworkAccessLog {
	out := api.AgentNetworkAccessLog{
		Id:           a.ID,
		ServiceId:    a.ServiceID,
		Timestamp:    a.Timestamp,
		StatusCode:   a.StatusCode,
		DurationMs:   int(a.Duration.Milliseconds()),
		InputTokens:  a.InputTokens,
		OutputTokens: a.OutputTokens,
		TotalTokens:  a.TotalTokens,
		CostUsd:      a.CostUSD,
		Stream:       &a.Stream,
	}

	out.UserId = strPtr(a.UserID)
	out.SourceIp = strPtr(a.SourceIP)
	out.Method = strPtr(a.Method)
	out.Host = strPtr(a.Host)
	out.Path = strPtr(a.Path)
	out.Provider = strPtr(a.Provider)
	out.Model = strPtr(a.Model)
	out.SessionId = strPtr(a.SessionID)
	out.ResolvedProviderId = strPtr(a.ResolvedProviderID)
	out.SelectedPolicyId = strPtr(a.SelectedPolicyID)
	out.Decision = strPtr(a.Decision)
	out.DenyReason = strPtr(a.DenyReason)
	out.RequestPrompt = strPtr(a.RequestPrompt)
	out.ResponseCompletion = strPtr(a.ResponseCompletion)

	if len(a.GroupIDs) > 0 {
		groups := a.GroupIDs
		out.GroupIds = &groups
	}
	return out
}

// strPtr returns a pointer to s, or nil when s is empty — so empty optional
// fields are omitted from the JSON rather than serialised as "".
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// AgentNetworkAccessLogGroup is the normalised many-to-many row linking a log
// entry to one authorising group, so the access-log endpoint can filter by
// group with a simple `group_id IN (...)` join instead of substring-matching a
// CSV column.
type AgentNetworkAccessLogGroup struct {
	LogID     string `gorm:"primaryKey"`
	GroupID   string `gorm:"primaryKey;index"`
	AccountID string `gorm:"index"`
}

// TableName names the access-log group child table.
func (AgentNetworkAccessLogGroup) TableName() string { return "agent_network_access_log_group" }

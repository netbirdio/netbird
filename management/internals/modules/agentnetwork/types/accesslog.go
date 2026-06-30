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
	// The composite index idx_anal_acct_session_ts backs the session-grouped
	// listing (GROUP BY session_id ORDER BY MAX(timestamp) within an account);
	// the single-column indexes still back the flat filters/sorts.
	ID            string    `gorm:"primaryKey"`
	AccountID     string    `gorm:"index;index:idx_anal_acct_session_ts,priority:1"`
	ServiceID     string    `gorm:"index"`
	Timestamp     time.Time `gorm:"index;index:idx_anal_acct_session_ts,priority:3"`
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
	Provider           string `gorm:"index"`                                           // vendor, e.g. "openai" (llm.provider)
	Model              string `gorm:"index"`                                           // llm.model
	SessionID          string `gorm:"index;index:idx_anal_acct_session_ts,priority:2"` // llm.session_id — groups a conversation / coding session
	ResolvedProviderID string `gorm:"index"`                                           // llm.resolved_provider_id
	SelectedPolicyID   string `gorm:"index"`                                           // llm.selected_policy_id
	Decision           string `gorm:"index"`                                           // llm_policy.decision (allow/deny)
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

// AgentNetworkAccessLogSession is a session-grouped view of access-log entries:
// all requests sharing a session id (or, for a request the client sent no
// session id for, that single request keyed by its own row id) folded into one
// summary plus its ordered entries. Assembled in Go from a page of entries — it
// is not a stored table.
type AgentNetworkAccessLogSession struct {
	SessionID    string // empty for a session-less (singleton) request
	UserID       string
	GroupIDs     []string // union of the entries' authorising groups
	StartedAt    time.Time
	EndedAt      time.Time
	RequestCount int
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
	CostUSD      float64
	Providers    []string // distinct vendors seen in the session
	Models       []string // distinct models seen in the session
	Decision     string   // "deny" if any entry was denied, else "allow"
	Entries      []*AgentNetworkAccessLog
}

// sessionKey is the grouping key for an entry: its session id, or — when the
// client sent none — its own row id, so session-less requests each form their
// own singleton group. Must match the SQL group key
// COALESCE(NULLIF(session_id, ”), id).
func sessionKey(e *AgentNetworkAccessLog) string {
	if e.SessionID != "" {
		return e.SessionID
	}
	return e.ID
}

// FoldAccessLogSessions folds a page of entries into per-session summaries,
// preserving the order of orderedKeys (the already-sorted, already-paginated
// session keys from the store). Entries are expected pre-sorted by timestamp
// within each key. Aggregation (sums, distinct providers/models, deny rollup)
// happens here in Go rather than in SQL so the query stays engine-portable.
func FoldAccessLogSessions(orderedKeys []string, entries []*AgentNetworkAccessLog) []*AgentNetworkAccessLogSession {
	byKey := make(map[string]*AgentNetworkAccessLogSession, len(orderedKeys))
	order := make([]*AgentNetworkAccessLogSession, 0, len(orderedKeys))
	for _, k := range orderedKeys {
		if _, ok := byKey[k]; ok {
			continue
		}
		sess := &AgentNetworkAccessLogSession{Decision: "allow"}
		byKey[k] = sess
		order = append(order, sess)
	}

	type seen struct{ providers, models, groups map[string]struct{} }
	seenBy := make(map[string]*seen, len(orderedKeys))

	for _, e := range entries {
		k := sessionKey(e)
		sess, ok := byKey[k]
		if !ok {
			continue // entry outside the paged set; defensive
		}
		sk := seenBy[k]
		if sk == nil {
			sk = &seen{providers: map[string]struct{}{}, models: map[string]struct{}{}, groups: map[string]struct{}{}}
			seenBy[k] = sk
			sess.SessionID = e.SessionID
			sess.UserID = e.UserID
			sess.StartedAt = e.Timestamp
			sess.EndedAt = e.Timestamp
		}

		sess.RequestCount++
		sess.InputTokens += e.InputTokens
		sess.OutputTokens += e.OutputTokens
		sess.TotalTokens += e.TotalTokens
		sess.CostUSD += e.CostUSD
		if e.Timestamp.Before(sess.StartedAt) {
			sess.StartedAt = e.Timestamp
		}
		if e.Timestamp.After(sess.EndedAt) {
			sess.EndedAt = e.Timestamp
		}
		if sess.UserID == "" {
			sess.UserID = e.UserID
		}
		if e.Decision == "deny" {
			sess.Decision = "deny"
		}
		if e.Provider != "" {
			if _, dup := sk.providers[e.Provider]; !dup {
				sk.providers[e.Provider] = struct{}{}
				sess.Providers = append(sess.Providers, e.Provider)
			}
		}
		if e.Model != "" {
			if _, dup := sk.models[e.Model]; !dup {
				sk.models[e.Model] = struct{}{}
				sess.Models = append(sess.Models, e.Model)
			}
		}
		for _, g := range e.GroupIDs {
			if g == "" {
				continue
			}
			if _, dup := sk.groups[g]; !dup {
				sk.groups[g] = struct{}{}
				sess.GroupIDs = append(sess.GroupIDs, g)
			}
		}
		sess.Entries = append(sess.Entries, e)
	}

	out := make([]*AgentNetworkAccessLogSession, 0, len(order))
	for _, sess := range order {
		if sess.RequestCount > 0 {
			out = append(out, sess)
		}
	}
	return out
}

// ToAPIResponse renders the session summary (and its entries) as the API
// representation.
func (sess *AgentNetworkAccessLogSession) ToAPIResponse() api.AgentNetworkAccessLogSession {
	entries := make([]api.AgentNetworkAccessLog, 0, len(sess.Entries))
	for _, e := range sess.Entries {
		entries = append(entries, e.ToAPIResponse())
	}

	out := api.AgentNetworkAccessLogSession{
		StartedAt:    sess.StartedAt,
		EndedAt:      sess.EndedAt,
		RequestCount: sess.RequestCount,
		InputTokens:  sess.InputTokens,
		OutputTokens: sess.OutputTokens,
		TotalTokens:  sess.TotalTokens,
		CostUsd:      sess.CostUSD,
		Decision:     sess.Decision,
		Entries:      entries,
	}
	out.SessionId = strPtr(sess.SessionID)
	out.UserId = strPtr(sess.UserID)
	if len(sess.Providers) > 0 {
		providers := sess.Providers
		out.Providers = &providers
	}
	if len(sess.Models) > 0 {
		models := sess.Models
		out.Models = &models
	}
	if len(sess.GroupIDs) > 0 {
		groups := sess.GroupIDs
		out.GroupIds = &groups
	}
	return out
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

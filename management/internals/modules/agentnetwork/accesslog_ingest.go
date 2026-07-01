package agentnetwork

import (
	"context"
	"math"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/server/store"
)

// Metadata keys the proxy stamps on agent-network access-log entries. These
// mirror the constants in proxy/internal/middleware/keys.go and form the wire
// contract between the proxy and management; management flattens them into
// queryable columns. Keep in sync with the proxy side.
const (
	metaKeyProvider           = "llm.provider"
	metaKeyModel              = "llm.model"
	metaKeyResolvedProviderID = "llm.resolved_provider_id"
	metaKeySelectedPolicyID   = "llm.selected_policy_id"
	metaKeyPolicyDecision     = "llm_policy.decision"
	metaKeyPolicyReason       = "llm_policy.reason"
	metaKeyInputTokens        = "llm.input_tokens"  //nolint:gosec // metadata key name, not a credential
	metaKeyOutputTokens       = "llm.output_tokens" //nolint:gosec // metadata key name, not a credential
	metaKeyTotalTokens        = "llm.total_tokens"  //nolint:gosec // metadata key name, not a credential
	metaKeyCostUSDTotal       = "cost.usd_total"
	metaKeyStream             = "llm.stream"
	metaKeySessionID          = "llm.session_id"
	metaKeyAuthorisingGroups  = "llm.authorising_groups"
	metaKeyRequestPrompt      = "llm.request_prompt"
	metaKeyResponseCompletion = "llm.response_completion"
)

// IngestAccessLog flattens the metadata-bearing reverse-proxy access-log entry
// and persists it in the dedicated agent-network tables (instead of the shared
// reverse-proxy table), in two parts:
//
//   - The stripped usage record is written unconditionally — usage/cost is
//     collected on every request regardless of the account's log-collection
//     toggle (the proxy ships a usage-only entry when logging is disabled).
//   - The full access-log row (with request detail + prompt) is written only
//     when the account's EnableLogCollection setting is on. This setting read
//     is the authoritative gate; the proxy-side strip is defense in depth.
func IngestAccessLog(ctx context.Context, s store.Store, logEntry *accesslogs.AccessLogEntry) error {
	entry, groups := flattenAccessLog(logEntry)

	usage, usageGroups := usageFromFlattenedLog(entry, groups)
	if err := s.CreateAgentNetworkUsage(ctx, usage, usageGroups); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id": entry.AccountID,
			"model":      entry.Model,
		}).Errorf("failed to save agent-network usage: %v", err)
		return err
	}

	settings, err := s.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, entry.AccountID)
	if err != nil {
		// No settings row (or a transient read error) means we can't confirm
		// log collection is enabled — usage is already saved, so skip the full
		// row rather than fail the whole ingest.
		log.WithContext(ctx).Debugf("skipping full agent-network access-log row for account %s: %v", entry.AccountID, err)
		return nil
	}
	if !settings.EnableLogCollection {
		return nil
	}

	if err := s.CreateAgentNetworkAccessLog(ctx, entry, groups); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id": entry.AccountID,
			"service_id": entry.ServiceID,
			"model":      entry.Model,
			"status":     entry.StatusCode,
		}).Errorf("failed to save agent-network access log: %v", err)
		return err
	}
	return nil
}

// flattenAccessLog converts a reverse-proxy AccessLogEntry (whose LLM
// dimensions live in the opaque Metadata map) into the flattened
// agent-network row + authorising-group child rows.
func flattenAccessLog(e *accesslogs.AccessLogEntry) (*types.AgentNetworkAccessLog, []types.AgentNetworkAccessLogGroup) {
	meta := e.Metadata

	var sourceIP string
	if e.GeoLocation.ConnectionIP != nil {
		sourceIP = e.GeoLocation.ConnectionIP.String()
	}

	entry := &types.AgentNetworkAccessLog{
		ID:            e.ID,
		AccountID:     e.AccountID,
		ServiceID:     e.ServiceID,
		Timestamp:     e.Timestamp,
		UserID:        e.UserId,
		SourceIP:      sourceIP,
		Method:        e.Method,
		Host:          e.Host,
		Path:          e.Path,
		Duration:      e.Duration,
		StatusCode:    e.StatusCode,
		AuthMethod:    e.AuthMethodUsed,
		BytesUpload:   e.BytesUpload,
		BytesDownload: e.BytesDownload,

		Provider:           meta[metaKeyProvider],
		Model:              meta[metaKeyModel],
		SessionID:          meta[metaKeySessionID],
		ResolvedProviderID: meta[metaKeyResolvedProviderID],
		SelectedPolicyID:   meta[metaKeySelectedPolicyID],
		Decision:           meta[metaKeyPolicyDecision],
		DenyReason:         meta[metaKeyPolicyReason],
		InputTokens:        parseMetaInt(meta, metaKeyInputTokens),
		OutputTokens:       parseMetaInt(meta, metaKeyOutputTokens),
		TotalTokens:        parseMetaInt(meta, metaKeyTotalTokens),
		CostUSD:            parseMetaFloat(meta, metaKeyCostUSDTotal),
		Stream:             parseMetaBool(meta, metaKeyStream),
		RequestPrompt:      meta[metaKeyRequestPrompt],
		ResponseCompletion: meta[metaKeyResponseCompletion],
	}

	var groups []types.AgentNetworkAccessLogGroup
	for _, gid := range parseGroupCSV(meta[metaKeyAuthorisingGroups]) {
		groups = append(groups, types.AgentNetworkAccessLogGroup{
			LogID:     entry.ID,
			GroupID:   gid,
			AccountID: entry.AccountID,
		})
	}
	return entry, groups
}

// usageFromFlattenedLog derives the stripped usage record (and its group child
// rows) from an already-flattened access-log entry. The usage row shares the
// log's ID so the two correlate.
func usageFromFlattenedLog(e *types.AgentNetworkAccessLog, groups []types.AgentNetworkAccessLogGroup) (*types.AgentNetworkUsage, []types.AgentNetworkUsageGroup) {
	usage := &types.AgentNetworkUsage{
		ID:                 e.ID,
		AccountID:          e.AccountID,
		Timestamp:          e.Timestamp,
		UserID:             e.UserID,
		ResolvedProviderID: e.ResolvedProviderID,
		Provider:           e.Provider,
		Model:              e.Model,
		SessionID:          e.SessionID,
		InputTokens:        e.InputTokens,
		OutputTokens:       e.OutputTokens,
		TotalTokens:        e.TotalTokens,
		CostUSD:            e.CostUSD,
	}

	usageGroups := make([]types.AgentNetworkUsageGroup, 0, len(groups))
	for _, g := range groups {
		usageGroups = append(usageGroups, types.AgentNetworkUsageGroup{
			UsageID:   usage.ID,
			GroupID:   g.GroupID,
			AccountID: g.AccountID,
		})
	}
	return usage, usageGroups
}

// parseMetaInt parses a non-negative token count. Negative or unparseable
// values are clamped to 0 so a malformed metric can't persist a negative
// counter.
func parseMetaInt(meta map[string]string, key string) int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(meta[key]), 10, 64); err == nil && v >= 0 {
		return v
	}
	return 0
}

// parseMetaFloat parses a non-negative, finite cost. Negative, NaN, Inf, or
// unparseable values are clamped to 0 so a malformed metric can't poison the
// stored cost.
func parseMetaFloat(meta map[string]string, key string) float64 {
	if v, err := strconv.ParseFloat(strings.TrimSpace(meta[key]), 64); err == nil && v >= 0 && !math.IsInf(v, 0) {
		return v
	}
	return 0
}

func parseMetaBool(meta map[string]string, key string) bool {
	v, _ := strconv.ParseBool(strings.TrimSpace(meta[key]))
	return v
}

// parseGroupCSV splits the comma-separated authorising-group id list the proxy
// emits, trimming blanks and de-duplicating. Dedup matters because the group
// rows are keyed by (log_id, group_id) / (usage_id, group_id): a repeated id
// in the CSV would otherwise produce a duplicate primary key and fail the
// insert transaction.
func parseGroupCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

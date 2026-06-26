package manager

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	agentNetworkTypes "github.com/netbirdio/netbird/management/server/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
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

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	geo                geolocation.Geolocation
	cleanupCancel      context.CancelFunc
}

func NewManager(store store.Store, permissionsManager permissions.Manager, geo geolocation.Geolocation) accesslogs.Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		geo:                geo,
	}
}

// SaveAccessLog saves an access log entry to the database after enriching it.
// Agent-network entries are flattened into their own dedicated table (queryable
// LLM columns + group child rows) instead of the shared reverse-proxy table.
func (m *managerImpl) SaveAccessLog(ctx context.Context, logEntry *accesslogs.AccessLogEntry) error {
	if logEntry.AgentNetwork {
		return m.saveAgentNetworkAccessLog(ctx, logEntry)
	}

	if m.geo != nil && logEntry.GeoLocation.ConnectionIP != nil {
		location, err := m.geo.Lookup(logEntry.GeoLocation.ConnectionIP)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to get location for access log source IP [%s]: %v", logEntry.GeoLocation.ConnectionIP.String(), err)
		} else {
			logEntry.GeoLocation.CountryCode = location.Country.ISOCode
			logEntry.GeoLocation.CityName = location.City.Names.En
			logEntry.GeoLocation.GeoNameID = location.City.GeonameID
			if len(location.Subdivisions) > 0 {
				logEntry.SubdivisionCode = location.Subdivisions[0].ISOCode
			}
		}
	}

	if err := m.store.CreateAccessLog(ctx, logEntry); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"service_id": logEntry.ServiceID,
			"method":     logEntry.Method,
			"host":       logEntry.Host,
			"path":       logEntry.Path,
			"status":     logEntry.StatusCode,
		}).Errorf("failed to save access log: %v", err)
		return err
	}

	return nil
}

// saveAgentNetworkAccessLog flattens the metadata-bearing access-log entry and
// persists it in two parts:
//
//   - The stripped usage record is written unconditionally — usage/cost is
//     collected on every request regardless of the account's log-collection
//     toggle (the proxy ships a usage-only entry when logging is disabled).
//   - The full access-log row (with request detail + prompt) is written only
//     when the account's EnableLogCollection setting is on. This setting read
//     is the authoritative gate; the proxy-side strip is defense in depth.
func (m *managerImpl) saveAgentNetworkAccessLog(ctx context.Context, logEntry *accesslogs.AccessLogEntry) error {
	entry, groups := flattenAgentNetworkLog(logEntry)

	usage, usageGroups := usageFromFlattenedLog(entry, groups)
	if err := m.store.CreateAgentNetworkUsage(ctx, usage, usageGroups); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id": entry.AccountID,
			"model":      entry.Model,
		}).Errorf("failed to save agent-network usage: %v", err)
		return err
	}

	settings, err := m.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, entry.AccountID)
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

	if err := m.store.CreateAgentNetworkAccessLog(ctx, entry, groups); err != nil {
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

// flattenAgentNetworkLog converts a reverse-proxy AccessLogEntry (whose LLM
// dimensions live in the opaque Metadata map) into the flattened
// agent-network row + authorising-group child rows.
func flattenAgentNetworkLog(e *accesslogs.AccessLogEntry) (*agentNetworkTypes.AgentNetworkAccessLog, []agentNetworkTypes.AgentNetworkAccessLogGroup) {
	meta := e.Metadata

	var sourceIP string
	if e.GeoLocation.ConnectionIP != nil {
		sourceIP = e.GeoLocation.ConnectionIP.String()
	}

	entry := &agentNetworkTypes.AgentNetworkAccessLog{
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

	var groups []agentNetworkTypes.AgentNetworkAccessLogGroup
	for _, gid := range parseGroupCSV(meta[metaKeyAuthorisingGroups]) {
		groups = append(groups, agentNetworkTypes.AgentNetworkAccessLogGroup{
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
func usageFromFlattenedLog(e *agentNetworkTypes.AgentNetworkAccessLog, groups []agentNetworkTypes.AgentNetworkAccessLogGroup) (*agentNetworkTypes.AgentNetworkUsage, []agentNetworkTypes.AgentNetworkUsageGroup) {
	usage := &agentNetworkTypes.AgentNetworkUsage{
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

	usageGroups := make([]agentNetworkTypes.AgentNetworkUsageGroup, 0, len(groups))
	for _, g := range groups {
		usageGroups = append(usageGroups, agentNetworkTypes.AgentNetworkUsageGroup{
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

// GetAllAccessLogs retrieves access logs for an account with pagination and filtering
func (m *managerImpl) GetAllAccessLogs(ctx context.Context, accountID, userID string, filter *accesslogs.AccessLogFilter) ([]*accesslogs.AccessLogEntry, int64, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, 0, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, 0, status.NewPermissionDeniedError()
	}

	if err := m.resolveUserFilters(ctx, accountID, filter); err != nil {
		log.WithContext(ctx).Warnf("failed to resolve user filters: %v", err)
	}

	logs, totalCount, err := m.store.GetAccountAccessLogs(ctx, store.LockingStrengthNone, accountID, *filter)
	if err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

// CleanupOldAccessLogs deletes access logs older than the specified retention period
func (m *managerImpl) CleanupOldAccessLogs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		log.WithContext(ctx).Debug("access log cleanup skipped: retention days is 0 or negative")
		return 0, nil
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	deletedCount, err := m.store.DeleteOldAccessLogs(ctx, cutoffTime)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to cleanup old access logs: %v", err)
		return 0, err
	}

	if deletedCount > 0 {
		log.WithContext(ctx).Infof("cleaned up %d access logs older than %d days", deletedCount, retentionDays)
	}

	return deletedCount, nil
}

// StartPeriodicCleanup starts a background goroutine that periodically cleans up old access logs
func (m *managerImpl) StartPeriodicCleanup(ctx context.Context, retentionDays, cleanupIntervalHours int) {
	if retentionDays < 0 {
		log.WithContext(ctx).Debug("periodic access log cleanup disabled: retention days is negative")
		return
	}

	if retentionDays == 0 {
		retentionDays = 7
		log.WithContext(ctx).Debugf("no retention days specified for access log cleanup, defaulting to %d days", retentionDays)
	} else {
		log.WithContext(ctx).Debugf("access log retention period set to %d days", retentionDays)
	}

	if cleanupIntervalHours <= 0 {
		cleanupIntervalHours = 24
		log.WithContext(ctx).Debugf("no cleanup interval specified for access log cleanup, defaulting to %d hours", cleanupIntervalHours)
	} else {
		log.WithContext(ctx).Debugf("access log cleanup interval set to %d hours", cleanupIntervalHours)
	}

	cleanupCtx, cancel := context.WithCancel(ctx)
	m.cleanupCancel = cancel

	cleanupInterval := time.Duration(cleanupIntervalHours) * time.Hour
	ticker := time.NewTicker(cleanupInterval)

	go func() {
		defer ticker.Stop()

		// Run cleanup immediately on startup
		log.WithContext(cleanupCtx).Infof("starting access log cleanup routine (retention: %d days, interval: %d hours)", retentionDays, cleanupIntervalHours)
		if _, err := m.CleanupOldAccessLogs(cleanupCtx, retentionDays); err != nil {
			log.WithContext(cleanupCtx).Errorf("initial access log cleanup failed: %v", err)
		}

		for {
			select {
			case <-cleanupCtx.Done():
				log.WithContext(cleanupCtx).Info("stopping access log cleanup routine")
				return
			case <-ticker.C:
				if _, err := m.CleanupOldAccessLogs(cleanupCtx, retentionDays); err != nil {
					log.WithContext(cleanupCtx).Errorf("periodic access log cleanup failed: %v", err)
				}
			}
		}
	}()
}

// StopPeriodicCleanup stops the periodic cleanup routine
func (m *managerImpl) StopPeriodicCleanup() {
	if m.cleanupCancel != nil {
		m.cleanupCancel()
	}
}

// resolveUserFilters converts user email/name filters to user ID filter
func (m *managerImpl) resolveUserFilters(ctx context.Context, accountID string, filter *accesslogs.AccessLogFilter) error {
	if filter.UserEmail == nil && filter.UserName == nil {
		return nil
	}

	users, err := m.store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}

	var matchingUserIDs []string
	for _, user := range users {
		if filter.UserEmail != nil && strings.Contains(strings.ToLower(user.Email), strings.ToLower(*filter.UserEmail)) {
			matchingUserIDs = append(matchingUserIDs, user.Id)
			continue
		}
		if filter.UserName != nil && strings.Contains(strings.ToLower(user.Name), strings.ToLower(*filter.UserName)) {
			matchingUserIDs = append(matchingUserIDs, user.Id)
		}
	}

	if len(matchingUserIDs) > 0 {
		filter.UserID = &matchingUserIDs[0]
	}

	return nil
}

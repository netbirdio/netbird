package store

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// CreateAgentNetworkAccessLog persists a flattened agent-network access-log
// entry together with its authorising-group child rows in a single
// transaction.
func (s *SqlStore) CreateAgentNetworkAccessLog(ctx context.Context, entry *agentNetworkTypes.AgentNetworkAccessLog, groups []agentNetworkTypes.AgentNetworkAccessLogGroup) error {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Idempotent on the log id / (log_id, group_id) so a proxy resend of the
		// same entry can't fail the request.
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(entry).Error; err != nil {
			return err
		}
		if len(groups) > 0 {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&groups).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id": entry.AccountID,
			"service_id": entry.ServiceID,
			"model":      entry.Model,
		}).Errorf("failed to create agent-network access log entry in store: %v", err)
		return status.Errorf(status.Internal, "failed to create agent-network access log entry in store")
	}
	return nil
}

// DeleteOldAgentNetworkAccessLogs deletes an account's access-log rows (and
// their authorising-group child rows) older than the cutoff. Usage records are
// untouched — they are the long-term aggregate. Returns the number of log rows
// deleted.
func (s *SqlStore) DeleteOldAgentNetworkAccessLogs(ctx context.Context, accountID string, olderThan time.Time) (int64, error) {
	var deleted int64
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Remove group child rows for the soon-to-be-deleted logs first.
		if err := tx.Exec(
			"DELETE FROM agent_network_access_log_group WHERE account_id = ? AND log_id IN (SELECT id FROM agent_network_access_log WHERE account_id = ? AND timestamp < ?)",
			accountID, accountID, olderThan,
		).Error; err != nil {
			return err
		}
		res := tx.Where("account_id = ? AND timestamp < ?", accountID, olderThan).
			Delete(&agentNetworkTypes.AgentNetworkAccessLog{})
		if res.Error != nil {
			return res.Error
		}
		deleted = res.RowsAffected
		return nil
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to delete old agent-network access logs for account %s: %v", accountID, err)
		return 0, status.Errorf(status.Internal, "failed to delete old agent-network access logs")
	}
	return deleted, nil
}

// GetAgentNetworkAccessLogs retrieves flattened agent-network access logs for
// an account with server-side pagination, filtering and sorting. Authorising
// group ids are hydrated from the group child table for the returned page.
func (s *SqlStore) GetAgentNetworkAccessLogs(ctx context.Context, lockStrength LockingStrength, accountID string, filter agentNetworkTypes.AgentNetworkAccessLogFilter) ([]*agentNetworkTypes.AgentNetworkAccessLog, int64, error) {
	var logs []*agentNetworkTypes.AgentNetworkAccessLog
	var totalCount int64

	countQuery := s.applyAgentNetworkAccessLogFilters(
		s.db.Model(&agentNetworkTypes.AgentNetworkAccessLog{}).Where(accountIDCondition, accountID),
		filter,
	)
	if err := countQuery.Count(&totalCount).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to count agent-network access logs: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to count agent-network access logs")
	}

	query := s.applyAgentNetworkAccessLogFilters(
		s.db.Where(accountIDCondition, accountID),
		filter,
	).
		Order(filter.GetSortColumn() + " " + filter.GetSortOrder()).
		Limit(filter.GetLimit()).
		Offset(filter.GetOffset())

	if lockStrength != LockingStrengthNone {
		query = query.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	if err := query.Find(&logs).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get agent-network access logs from store: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to get agent-network access logs from store")
	}

	if err := s.hydrateAgentNetworkAccessLogGroups(ctx, accountID, logs); err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

// applyAgentNetworkAccessLogFilters applies the filter conditions to a query.
func (s *SqlStore) applyAgentNetworkAccessLogFilters(query *gorm.DB, filter agentNetworkTypes.AgentNetworkAccessLogFilter) *gorm.DB {
	if filter.Search != nil {
		p := "%" + *filter.Search + "%"
		query = query.Where(
			"id LIKE ? OR host LIKE ? OR path LIKE ? OR model LIKE ? OR user_id IN (SELECT id FROM users WHERE email LIKE ? OR name LIKE ?)",
			p, p, p, p, p, p,
		)
	}
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.SessionID != nil {
		query = query.Where("session_id = ?", *filter.SessionID)
	}
	if filter.Decision != nil {
		query = query.Where("decision = ?", *filter.Decision)
	}
	if filter.PathPrefix != nil {
		query = query.Where("path LIKE ?", *filter.PathPrefix+"%")
	}
	if len(filter.ProviderIDs) > 0 {
		query = query.Where("resolved_provider_id IN ?", filter.ProviderIDs)
	}
	if len(filter.Models) > 0 {
		query = query.Where("model IN ?", filter.Models)
	}
	if len(filter.GroupIDs) > 0 {
		query = query.Where(
			"id IN (SELECT log_id FROM agent_network_access_log_group WHERE group_id IN ?)",
			filter.GroupIDs,
		)
	}
	if filter.StartDate != nil {
		query = query.Where("timestamp >= ?", *filter.StartDate)
	}
	if filter.EndDate != nil {
		query = query.Where("timestamp <= ?", *filter.EndDate)
	}
	return query
}

// hydrateAgentNetworkAccessLogGroups loads the authorising group ids for the
// given page of entries and assigns them onto each entry's GroupIDs field.
func (s *SqlStore) hydrateAgentNetworkAccessLogGroups(ctx context.Context, accountID string, logs []*agentNetworkTypes.AgentNetworkAccessLog) error {
	if len(logs) == 0 {
		return nil
	}

	ids := make([]string, 0, len(logs))
	for _, l := range logs {
		ids = append(ids, l.ID)
	}

	var rows []agentNetworkTypes.AgentNetworkAccessLogGroup
	if err := s.db.
		Where(accountIDCondition, accountID).
		Where("log_id IN ?", ids).
		Find(&rows).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to hydrate agent-network access log groups: %v", err)
		return status.Errorf(status.Internal, "failed to hydrate agent-network access log groups")
	}

	byLog := make(map[string][]string, len(logs))
	for _, r := range rows {
		byLog[r.LogID] = append(byLog[r.LogID], r.GroupID)
	}
	for _, l := range logs {
		l.GroupIDs = byLog[l.ID]
	}
	return nil
}

// agentNetworkSessionKeyExpr is the SQL group key for session-grouped access
// logs: the row's session id, or — when the client sent none — the row id, so
// session-less requests each form their own singleton group. COALESCE/NULLIF
// are standard SQL, so this stays portable across SQLite and Postgres.
const agentNetworkSessionKeyExpr = "COALESCE(NULLIF(session_id, ''), id)"

// GetAgentNetworkAccessLogSessions retrieves agent-network access logs grouped
// by session, with server-side pagination, filtering and sorting at the session
// level. It paginates over the distinct session keys (ordered by the requested
// session-level aggregate), fetches every entry for the page's sessions, and
// folds them into per-session summaries. The returned count is the number of
// matching sessions. Filters apply to the entries, so a session's summary
// reflects only its filter-matching requests.
func (s *SqlStore) GetAgentNetworkAccessLogSessions(ctx context.Context, lockStrength LockingStrength, accountID string, filter agentNetworkTypes.AgentNetworkAccessLogFilter) ([]*agentNetworkTypes.AgentNetworkAccessLogSession, int64, error) {
	// Count distinct sessions via a grouped subquery — portable and avoids
	// relying on COUNT(DISTINCT <expr>) quoting quirks.
	sessionsSubquery := s.applyAgentNetworkAccessLogFilters(
		s.db.Model(&agentNetworkTypes.AgentNetworkAccessLog{}).Where(accountIDCondition, accountID),
		filter,
	).
		Select(agentNetworkSessionKeyExpr + " AS session_key").
		Group(agentNetworkSessionKeyExpr)

	var totalCount int64
	if err := s.db.Table("(?) AS sessions", sessionsSubquery).Count(&totalCount).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to count agent-network access-log sessions: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to count agent-network access-log sessions")
	}

	// The page of session keys, ordered by the session-level aggregate. The
	// session-key tiebreaker keeps pagination deterministic when the primary
	// aggregate ties.
	type sessionKeyRow struct {
		SessionKey string
	}
	var keyRows []sessionKeyRow
	keyQuery := s.applyAgentNetworkAccessLogFilters(
		s.db.Model(&agentNetworkTypes.AgentNetworkAccessLog{}).Where(accountIDCondition, accountID),
		filter,
	).
		Select(agentNetworkSessionKeyExpr + " AS session_key").
		Group(agentNetworkSessionKeyExpr).
		Order(filter.GetSessionSortExpr() + " " + filter.GetSortOrder()).
		Order("session_key ASC").
		Limit(filter.GetLimit()).
		Offset(filter.GetOffset())
	if err := keyQuery.Scan(&keyRows).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to list agent-network access-log session keys: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to list agent-network access-log session keys")
	}
	if len(keyRows) == 0 {
		return nil, totalCount, nil
	}

	keys := make([]string, 0, len(keyRows))
	for _, r := range keyRows {
		keys = append(keys, r.SessionKey)
	}

	// All entries for the page's sessions, contiguous per session and oldest
	// first within each — the fold relies on that ordering.
	var entries []*agentNetworkTypes.AgentNetworkAccessLog
	entriesQuery := s.applyAgentNetworkAccessLogFilters(
		s.db.Where(accountIDCondition, accountID),
		filter,
	).
		Where(agentNetworkSessionKeyExpr+" IN ?", keys).
		Order(agentNetworkSessionKeyExpr + ", timestamp ASC")

	if lockStrength != LockingStrengthNone {
		entriesQuery = entriesQuery.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	if err := entriesQuery.Find(&entries).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get agent-network access-log session entries: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to get agent-network access-log session entries")
	}

	if err := s.hydrateAgentNetworkAccessLogGroups(ctx, accountID, entries); err != nil {
		return nil, 0, err
	}

	return agentNetworkTypes.FoldAccessLogSessions(keys, entries), totalCount, nil
}

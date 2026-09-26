package store

import (
	"context"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// CreateAgentNetworkUsage persists a stripped agent-network usage record
// together with its authorising-group child rows in a single transaction.
func (s *SqlStore) CreateAgentNetworkUsage(ctx context.Context, usage *agentNetworkTypes.AgentNetworkUsage, groups []agentNetworkTypes.AgentNetworkUsageGroup) error {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Idempotent on the usage id / (usage_id, group_id) so a proxy resend of
		// the same entry can't fail the request.
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(usage).Error; err != nil {
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
			"account_id": usage.AccountID,
			"model":      usage.Model,
		}).Errorf("failed to create agent-network usage record in store: %v", err)
		return status.Errorf(status.Internal, "failed to create agent-network usage record in store")
	}
	return nil
}

// GetAgentNetworkUsageRows returns the stripped usage rows for an account that
// match the filter (date / user / group / provider / model). Aggregation into
// time buckets happens in the manager so granularities stay engine-portable.
func (s *SqlStore) GetAgentNetworkUsageRows(ctx context.Context, lockStrength LockingStrength, accountID string, filter agentNetworkTypes.AgentNetworkAccessLogFilter) ([]*agentNetworkTypes.AgentNetworkUsage, error) {
	var rows []*agentNetworkTypes.AgentNetworkUsage

	query := s.applyAgentNetworkUsageFilters(
		s.db.Where(accountIDCondition, accountID),
		filter,
	).Order("timestamp ASC")

	if lockStrength != LockingStrengthNone {
		query = query.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	if err := query.Find(&rows).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get agent-network usage rows from store: %v", err)
		return nil, status.Errorf(status.Internal, "failed to get agent-network usage rows from store")
	}
	return rows, nil
}

// applyAgentNetworkUsageFilters applies the shared access-log filter's
// date/user/group/provider/model conditions to a usage-table query. Pagination,
// sort and free-text search are ignored — the overview is an aggregate.
func (s *SqlStore) applyAgentNetworkUsageFilters(query *gorm.DB, filter agentNetworkTypes.AgentNetworkAccessLogFilter) *gorm.DB {
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.SessionID != nil {
		query = query.Where("session_id = ?", *filter.SessionID)
	}
	if len(filter.ProviderIDs) > 0 {
		query = query.Where("resolved_provider_id IN ?", filter.ProviderIDs)
	}
	if len(filter.Models) > 0 {
		query = query.Where("model IN ?", filter.Models)
	}
	if len(filter.GroupIDs) > 0 {
		query = query.Where(
			"id IN (SELECT usage_id FROM agent_network_request_usage_group WHERE group_id IN ?)",
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

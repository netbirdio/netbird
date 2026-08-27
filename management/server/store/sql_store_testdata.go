package store

import (
	"context"
	"time"

	"gorm.io/gorm"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// The deletes below exist for the Autonoma test-data endpoint
// (management/server/http/handlers/autonoma), which has to remove every row it
// seeded once a test run finishes. Deleting the account takes most of the graph
// with it, but these tables hang off an account without a GORM association, so
// nothing cascades into them. They are deliberately narrow - each one is scoped
// to a single account, or to a single row by a primary key the run itself
// generated - and none of them is on the Store interface, because production
// code has no reason to reach for them.
//
// Every one is idempotent: deleting a row that is already gone is a success, so
// teardown can run after a cascade already removed the row.

// DeletePeerJobForTestData removes one job belonging to an account.
func (s *SqlStore) DeletePeerJobForTestData(ctx context.Context, accountID, jobID string) error {
	result := s.db.WithContext(ctx).Delete(&types.Job{}, accountAndIDQueryCondition, accountID, jobID)
	if result.Error != nil {
		return status.Errorf(status.Internal, "delete peer job: %v", result.Error)
	}
	return nil
}

// DeleteProxyAccessTokenForTestData removes one proxy access token belonging to an account.
func (s *SqlStore) DeleteProxyAccessTokenForTestData(ctx context.Context, accountID, tokenID string) error {
	result := s.db.WithContext(ctx).Delete(&types.ProxyAccessToken{}, accountAndIDQueryCondition, accountID, tokenID)
	if result.Error != nil {
		return status.Errorf(status.Internal, "delete proxy access token: %v", result.Error)
	}
	return nil
}

// DeleteAccessLogForTestData removes one reverse-proxy access log entry belonging
// to an account, along with the agent-network rows flattened out of it.
func (s *SqlStore) DeleteAccessLogForTestData(ctx context.Context, accountID, logID string) error {
	// The agent-network rows are flattened out of the same entry and share its
	// id, so one id removes the whole trail: the usage ledger and the access
	// log plus the authorising-group child rows that hang off each.
	err := s.transaction(func(tx *gorm.DB) error {
		tx = tx.WithContext(ctx)
		if err := tx.Delete(&agentNetworkTypes.AgentNetworkUsageGroup{}, "account_id = ? and usage_id = ?", accountID, logID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&agentNetworkTypes.AgentNetworkAccessLogGroup{}, "account_id = ? and log_id = ?", accountID, logID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&agentNetworkTypes.AgentNetworkUsage{}, accountAndIDQueryCondition, accountID, logID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&agentNetworkTypes.AgentNetworkAccessLog{}, accountAndIDQueryCondition, accountID, logID).Error; err != nil {
			return err
		}
		return tx.Delete(&accesslogs.AccessLogEntry{}, accountAndIDQueryCondition, accountID, logID).Error
	})
	if err != nil {
		return status.Errorf(status.Internal, "delete access log: %v", err)
	}
	return nil
}

// DeleteAgentNetworkConsumptionForTestData removes one consumption counter.
func (s *SqlStore) DeleteAgentNetworkConsumptionForTestData(ctx context.Context, accountID string, kind agentNetworkTypes.ConsumptionDimension, dimID string, windowSeconds int64, windowStart time.Time) error {
	result := s.db.WithContext(ctx).Delete(&agentNetworkTypes.Consumption{},
		"account_id = ? and dim_kind = ? and dim_id = ? and window_seconds = ? and window_start_utc = ?",
		accountID, kind, dimID, windowSeconds, windowStart)
	if result.Error != nil {
		return status.Errorf(status.Internal, "delete agent network consumption: %v", result.Error)
	}
	return nil
}

// DeleteProxyForTestData removes one proxy registration by id and session.
func (s *SqlStore) DeleteProxyForTestData(ctx context.Context, proxyID, sessionID string) error {
	result := s.db.WithContext(ctx).Delete(&proxy.Proxy{}, "id = ? and session_id = ?", proxyID, sessionID)
	if result.Error != nil {
		return status.Errorf(status.Internal, "delete proxy: %v", result.Error)
	}
	return nil
}

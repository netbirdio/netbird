package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/status"
)

const targetSelectColumns = `id, account_id, service_id, path, host, port, protocol,
	target_id, target_type, enabled, proxy_protocol,
	skip_tls_verify, request_timeout, session_idle_timeout, path_rewrite, custom_headers,
	direct_upstream, middlewares, capture_max_request_bytes, capture_max_response_bytes,
	capture_content_types, agent_network, disable_access_log`

func (s *SqlStore) getServiceTargets(ctx context.Context, serviceIDs []string) ([]*rpservice.Target, error) {
	const targetsQuery = `SELECT ` + targetSelectColumns + ` FROM targets WHERE service_id = ANY($1)`

	rows, err := s.pool.Query(ctx, targetsQuery, serviceIDs)
	if err != nil {
		return nil, err
	}

	return pgx.CollectRows(rows, scanTarget)
}

func scanTarget(row pgx.CollectableRow) (*rpservice.Target, error) {
	var t rpservice.Target
	var path sql.NullString
	var pathRewrite sql.NullString
	var proxyProtocol, skipTLSVerify, directUpstream, agentNetwork, disableAccessLog sql.NullBool
	var requestTimeout, sessionIdleTimeout, captureMaxRequestBytes, captureMaxResponseBytes sql.NullInt64
	var customHeaders, middlewares, captureContentTypes []byte
	err := row.Scan(
		&t.ID,
		&t.AccountID,
		&t.ServiceID,
		&path,
		&t.Host,
		&t.Port,
		&t.Protocol,
		&t.TargetId,
		&t.TargetType,
		&t.Enabled,
		&proxyProtocol,
		&skipTLSVerify,
		&requestTimeout,
		&sessionIdleTimeout,
		&pathRewrite,
		&customHeaders,
		&directUpstream,
		&middlewares,
		&captureMaxRequestBytes,
		&captureMaxResponseBytes,
		&captureContentTypes,
		&agentNetwork,
		&disableAccessLog,
	)
	if err != nil {
		return nil, err
	}
	if path.Valid {
		t.Path = &path.String
	}

	t.ProxyProtocol = proxyProtocol.Bool
	t.Options.SkipTLSVerify = skipTLSVerify.Bool
	t.Options.RequestTimeout = time.Duration(requestTimeout.Int64)
	t.Options.SessionIdleTimeout = time.Duration(sessionIdleTimeout.Int64)
	t.Options.PathRewrite = rpservice.PathRewriteMode(pathRewrite.String)
	t.Options.DirectUpstream = directUpstream.Bool
	t.Options.CaptureMaxRequestBytes = captureMaxRequestBytes.Int64
	t.Options.CaptureMaxResponseBytes = captureMaxResponseBytes.Int64
	t.Options.AgentNetwork = agentNetwork.Bool
	t.Options.DisableAccessLog = disableAccessLog.Bool

	if len(customHeaders) > 0 {
		if err := json.Unmarshal(customHeaders, &t.Options.CustomHeaders); err != nil {
			return nil, fmt.Errorf("unmarshal custom_headers: %w", err)
		}
	}
	if len(middlewares) > 0 {
		if err := json.Unmarshal(middlewares, &t.Options.Middlewares); err != nil {
			return nil, fmt.Errorf("unmarshal middlewares: %w", err)
		}
	}
	if len(captureContentTypes) > 0 {
		if err := json.Unmarshal(captureContentTypes, &t.Options.CaptureContentTypes); err != nil {
			return nil, fmt.Errorf("unmarshal capture_content_types: %w", err)
		}
	}
	return &t, nil
}

func (s *SqlStore) DeleteTarget(ctx context.Context, accountID string, serviceID string, targetID uint) error {
	result := s.db.Delete(&rpservice.Target{}, "account_id = ? AND service_id = ? AND id = ?", accountID, serviceID, targetID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete target from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete target from store")
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "target not found for service %s", serviceID)
	}

	return nil
}

func (s *SqlStore) DeleteServiceTargets(ctx context.Context, accountID string, serviceID string) error {
	result := s.db.Delete(&rpservice.Target{}, "account_id = ? AND service_id = ?", accountID, serviceID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete targets from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete targets from store")
	}

	return nil
}

// GetTargetsByServiceID retrieves all targets for a given service
func (s *SqlStore) GetTargetsByServiceID(ctx context.Context, lockStrength LockingStrength, accountID string, serviceID string) ([]*rpservice.Target, error) {
	var targets []*rpservice.Target
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}
	result := tx.Where("account_id = ? AND service_id = ?", accountID, serviceID).Find(&targets)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get targets from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get targets from store")
	}

	return targets, nil
}

func (s *SqlStore) GetServiceTargetByTargetID(ctx context.Context, lockStrength LockingStrength, accountID string, targetID string) (*rpservice.Target, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var target *rpservice.Target
	result := tx.Take(&target, "account_id = ? AND target_id = ?", accountID, targetID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "service target with ID %s not found", targetID)
		}

		log.WithContext(ctx).Errorf("failed to get service target from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get service target from store")
	}

	return target, nil
}

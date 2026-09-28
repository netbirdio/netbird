package store

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/shared/management/status"
)

// CreateAccessLog creates a new access log entry in the database
func (s *SqlStore) CreateAccessLog(ctx context.Context, logEntry *accesslogs.AccessLogEntry) error {
	result := s.db.Create(logEntry)
	if result.Error != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"service_id": logEntry.ServiceID,
			"method":     logEntry.Method,
			"host":       logEntry.Host,
			"path":       logEntry.Path,
		}).Errorf("failed to create access log entry in store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to create access log entry in store")
	}
	return nil
}

// GetAccountAccessLogs retrieves access logs for a given account with pagination and filtering
func (s *SqlStore) GetAccountAccessLogs(ctx context.Context, lockStrength LockingStrength, accountID string, filter accesslogs.AccessLogFilter) ([]*accesslogs.AccessLogEntry, int64, error) {
	var logs []*accesslogs.AccessLogEntry
	var totalCount int64

	baseQuery := s.db.
		Model(&accesslogs.AccessLogEntry{}).
		Where(accountIDCondition, accountID)

	baseQuery = s.applyAccessLogFilters(baseQuery, filter)

	if err := baseQuery.Count(&totalCount).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to count access logs: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to count access logs")
	}

	query := s.db.
		Where(accountIDCondition, accountID)

	query = s.applyAccessLogFilters(query, filter)

	sortColumns := filter.GetSortColumn()
	sortOrder := strings.ToUpper(filter.GetSortOrder())

	var orderClauses []string
	for _, col := range strings.Split(sortColumns, ",") {
		col = strings.TrimSpace(col)
		if col != "" {
			orderClauses = append(orderClauses, col+" "+sortOrder)
		}
	}
	orderClause := strings.Join(orderClauses, ", ")

	query = query.
		Order(orderClause).
		Limit(filter.GetLimit()).
		Offset(filter.GetOffset())

	if lockStrength != LockingStrengthNone {
		query = query.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	result := query.Find(&logs)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get access logs from store: %v", result.Error)
		return nil, 0, status.Errorf(status.Internal, "failed to get access logs from store")
	}

	return logs, totalCount, nil
}

// DeleteOldAccessLogs deletes all access logs older than the specified time
func (s *SqlStore) DeleteOldAccessLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	result := s.db.
		Where("timestamp < ?", olderThan).
		Delete(&accesslogs.AccessLogEntry{})

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete old access logs: %v", result.Error)
		return 0, status.Errorf(status.Internal, "failed to delete old access logs")
	}

	return result.RowsAffected, nil
}

// applyAccessLogFilters applies filter conditions to the query
func (s *SqlStore) applyAccessLogFilters(query *gorm.DB, filter accesslogs.AccessLogFilter) *gorm.DB {
	if filter.Search != nil {
		searchPattern := "%" + *filter.Search + "%"
		query = query.Where(
			"id LIKE ? OR location_connection_ip LIKE ? OR host LIKE ? OR path LIKE ? OR CONCAT(host, path) LIKE ? OR user_id IN (SELECT id FROM users WHERE email LIKE ? OR name LIKE ?)",
			searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern,
		)
	}

	if filter.SourceIP != nil {
		query = query.Where("location_connection_ip = ?", *filter.SourceIP)
	}

	if filter.Host != nil {
		query = query.Where("host = ?", *filter.Host)
	}

	if filter.Path != nil {
		// Support LIKE pattern for path filtering
		query = query.Where("path LIKE ?", "%"+*filter.Path+"%")
	}

	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}

	if filter.Method != nil {
		query = query.Where("method = ?", *filter.Method)
	}

	if filter.Status != nil {
		switch *filter.Status {
		case "success":
			query = query.Where("status_code >= ? AND status_code < ?", 200, 400)
		case "failed":
			query = query.Where("status_code < ? OR status_code >= ?", 200, 400)
		}
	}

	if filter.StatusCode != nil {
		query = query.Where("status_code = ?", *filter.StatusCode)
	}

	if filter.StartDate != nil {
		query = query.Where("timestamp >= ?", *filter.StartDate)
	}

	if filter.EndDate != nil {
		query = query.Where("timestamp <= ?", *filter.EndDate)
	}

	return query
}

package manager

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/shared/management/status"
)

type sqlRepository struct {
	table *db.Table[accesslogs.AccessLogEntry]
}

func NewRepository(conn *db.Conn) accesslogs.Repository {
	return &sqlRepository{table: db.NewTable[accesslogs.AccessLogEntry](conn)}
}

func (r *sqlRepository) Create(ctx context.Context, tx *db.Tx, entry *accesslogs.AccessLogEntry) error {
	if err := r.table.Create(ctx, tx, entry); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"service_id": entry.ServiceID,
			"method":     entry.Method,
			"host":       entry.Host,
			"path":       entry.Path,
		}).Errorf("failed to create access log entry in store: %v", err)
		return status.Errorf(status.Internal, "failed to create access log entry in store")
	}
	return nil
}

// ListByAccount returns one page of an account's access logs together with the
// total number of entries matching the filter.
func (r *sqlRepository) ListByAccount(ctx context.Context, tx *db.Tx, lockStrength db.LockingStrength, accountID string, filter accesslogs.AccessLogFilter) ([]*accesslogs.AccessLogEntry, int64, error) {
	query := applyFilters(db.NewQuery().Where("account_id = ?", accountID), filter)

	totalCount, err := r.table.Count(ctx, tx, query)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to count access logs: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to count access logs")
	}

	sortOrder := strings.ToUpper(filter.GetSortOrder())
	for _, column := range strings.Split(filter.GetSortColumn(), ",") {
		if column = strings.TrimSpace(column); column != "" {
			query.Order(column + " " + sortOrder)
		}
	}
	query.Limit(filter.GetLimit()).Offset(filter.GetOffset()).Lock(lockStrength)

	logs, err := r.table.Find(ctx, tx, query)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get access logs from store: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to get access logs from store")
	}

	return logs, totalCount, nil
}

func (r *sqlRepository) DeleteOlderThan(ctx context.Context, tx *db.Tx, olderThan time.Time) (int64, error) {
	deleted, err := r.table.Delete(ctx, tx, db.NewQuery().Where("timestamp < ?", olderThan))
	if err != nil {
		log.WithContext(ctx).Errorf("failed to delete old access logs: %v", err)
		return 0, status.Errorf(status.Internal, "failed to delete old access logs")
	}
	return deleted, nil
}

func applyFilters(query *db.Query, filter accesslogs.AccessLogFilter) *db.Query {
	if filter.Search != nil {
		searchPattern := "%" + *filter.Search + "%"
		query.Where(
			"id LIKE ? OR location_connection_ip LIKE ? OR host LIKE ? OR path LIKE ? OR CONCAT(host, path) LIKE ? OR user_id IN (SELECT id FROM users WHERE email LIKE ? OR name LIKE ?)",
			searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern,
		)
	}

	if filter.SourceIP != nil {
		query.Where("location_connection_ip = ?", *filter.SourceIP)
	}

	if filter.Host != nil {
		query.Where("host = ?", *filter.Host)
	}

	if filter.Path != nil {
		query.Where("path LIKE ?", "%"+*filter.Path+"%")
	}

	if filter.UserID != nil {
		query.Where("user_id = ?", *filter.UserID)
	}

	if filter.Method != nil {
		query.Where("method = ?", *filter.Method)
	}

	if filter.Status != nil {
		switch *filter.Status {
		case "success":
			query.Where("status_code >= ? AND status_code < ?", 200, 400)
		case "failed":
			query.Where("status_code < ? OR status_code >= ?", 200, 400)
		}
	}

	if filter.StatusCode != nil {
		query.Where("status_code = ?", *filter.StatusCode)
	}

	if filter.StartDate != nil {
		query.Where("timestamp >= ?", *filter.StartDate)
	}

	if filter.EndDate != nil {
		query.Where("timestamp <= ?", *filter.EndDate)
	}

	return query
}

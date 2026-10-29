package manager

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/shared/management/status"
)

const deleteBatchSize = 10000

type sqlRepository struct {
	conn            *db.Conn
	db              *gorm.DB
	deleteBatchSize int
}

// NewRepository returns the access log repository backed by conn.
func NewRepository(conn *db.Conn) accesslogs.Repository {
	return &sqlRepository{conn: conn, db: conn.DB(nil), deleteBatchSize: deleteBatchSize}
}

func (r *sqlRepository) WithTx(tx *db.Tx) accesslogs.Repository {
	return &sqlRepository{conn: r.conn, db: r.conn.DB(tx), deleteBatchSize: r.deleteBatchSize}
}

func (r *sqlRepository) Create(ctx context.Context, entry *accesslogs.AccessLogEntry) error {
	if err := r.db.Create(entry).Error; err != nil {
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
func (r *sqlRepository) ListByAccount(ctx context.Context, lockStrength db.LockingStrength, accountID string, filter accesslogs.AccessLogFilter) ([]*accesslogs.AccessLogEntry, int64, error) {
	var totalCount int64
	countQuery := applyFilters(r.db.Model(&accesslogs.AccessLogEntry{}).Where("account_id = ?", accountID), filter)
	if err := countQuery.Count(&totalCount).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to count access logs: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to count access logs")
	}

	query := applyFilters(r.db.Where("account_id = ?", accountID), filter)
	sortOrder := strings.ToUpper(filter.GetSortOrder())
	for _, column := range strings.Split(filter.GetSortColumn(), ",") {
		if column = strings.TrimSpace(column); column != "" {
			query = query.Order(column + " " + sortOrder)
		}
	}
	query = query.Limit(filter.GetLimit()).Offset(filter.GetOffset())
	if lockStrength != db.LockingStrengthNone {
		query = query.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var logs []*accesslogs.AccessLogEntry
	if err := query.Find(&logs).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get access logs from store: %v", err)
		return nil, 0, status.Errorf(status.Internal, "failed to get access logs from store")
	}

	return logs, totalCount, nil
}

func (r *sqlRepository) DeleteOlderThan(ctx context.Context, olderThan time.Time) (int64, error) {
	var deleted int64
	for {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}

		batch := r.db.Model(&accesslogs.AccessLogEntry{}).
			Select("id").
			Where("timestamp < ?", olderThan).
			Order("timestamp").
			Limit(r.deleteBatchSize)
		result := r.db.Where("id IN (?)", batch).Delete(&accesslogs.AccessLogEntry{})
		if result.Error != nil {
			log.WithContext(ctx).Errorf("failed to delete old access logs: %v", result.Error)
			return deleted, status.Errorf(status.Internal, "failed to delete old access logs")
		}

		deleted += result.RowsAffected
		if result.RowsAffected < int64(r.deleteBatchSize) {
			return deleted, nil
		}
	}
}

func applyFilters(query *gorm.DB, filter accesslogs.AccessLogFilter) *gorm.DB {
	if filter.Search != nil {
		searchPattern := "%" + *filter.Search + "%"
		query = query.Where(
			"id LIKE ? OR location_connection_ip LIKE ? OR host LIKE ? OR path LIKE ? OR CONCAT(host, path) LIKE ?",
			searchPattern, searchPattern, searchPattern, searchPattern, searchPattern,
		)
	}

	if filter.SourceIP != nil {
		query = query.Where("location_connection_ip = ?", *filter.SourceIP)
	}

	if filter.Host != nil {
		query = query.Where("host = ?", *filter.Host)
	}

	if filter.Path != nil {
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
			query = query.Where("(status_code >= ? AND status_code < ?)", 200, 400)
		case "failed":
			query = query.Where("((status_code >= ? AND status_code < ?) OR status_code >= ?)", 100, 200, 400)
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

package accesslogs

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

//go:generate go tool mockgen -package accesslogs -destination=repository_mock.go -source=./repository.go -build_flags=-mod=mod

// Repository persists reverse proxy access log entries.
type Repository interface {
	Create(ctx context.Context, tx *db.Tx, entry *AccessLogEntry) error
	ListByAccount(ctx context.Context, tx *db.Tx, lockStrength db.LockingStrength, accountID string, filter AccessLogFilter) ([]*AccessLogEntry, int64, error)
	DeleteOlderThan(ctx context.Context, tx *db.Tx, olderThan time.Time) (int64, error)
}

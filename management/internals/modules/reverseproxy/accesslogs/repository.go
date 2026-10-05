package accesslogs

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

//go:generate go tool mockgen -package accesslogs -destination=repository_mock.go -source=./repository.go -build_flags=-mod=mod

// Repository persists reverse proxy access log entries.
type Repository interface {
	WithTx(tx *db.Tx) Repository
	Create(ctx context.Context, entry *AccessLogEntry) error
	ListByAccount(ctx context.Context, lockStrength db.LockingStrength, accountID string, filter AccessLogFilter) ([]*AccessLogEntry, int64, error)
	DeleteOlderThan(ctx context.Context, olderThan time.Time) (int64, error)
}

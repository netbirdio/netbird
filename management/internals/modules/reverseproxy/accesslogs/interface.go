package accesslogs

import (
	"context"
)

type Manager interface {
	SaveAccessLog(ctx context.Context, proxyLog *AccessLogEntry) error
	GetAllAccessLogs(ctx context.Context, accountID, userID string, filter *AccessLogFilter) ([]*AccessLogEntry, int64, error)
	CleanupOldAccessLogs(ctx context.Context, retentionDays int) (int64, error)
	StartPeriodicCleanup(ctx context.Context, retentionDays, cleanupIntervalHours int)
	StopPeriodicCleanup()
}

package accesslogs

import (
	"context"
)

type Manager interface {
	SaveAccessLog(ctx context.Context, proxyLog *AccessLogEntry) error
	GetAllAccessLogs(ctx context.Context, accountID, userID string) ([]*AccessLogEntry, error)
}

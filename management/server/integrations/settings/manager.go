package settings

import (
	"context"

	"github.com/netbirdio/netbird/management/server/account"
)

type Manager interface {
	GetExtraSettings(ctx context.Context, accountID string) (*account.ExtraSettings, error)
	UpdateExtraSettings(ctx context.Context, accountID string, extraSettings *account.ExtraSettings) error
}

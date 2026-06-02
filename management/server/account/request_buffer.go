package account

import (
	"context"

	"github.com/netbirdio/netbird/management/server/types"
)

type RequestBuffer interface {
	GetAccountWithBackpressure(ctx context.Context, accountID string) (*types.Account, error)
}

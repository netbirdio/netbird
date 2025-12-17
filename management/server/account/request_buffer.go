package account

import (
	"context"

	"github.com/netbirdio/netbird/management/server/types"
)

type RequestBuffer interface {
	// GetAccountLightWithBackpressure returns account without users, setup keys, and onboarding data with request buffering
	GetAccountLightWithBackpressure(ctx context.Context, accountID string) (*types.Account, error)
}

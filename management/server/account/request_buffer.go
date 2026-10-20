package account

import (
	"context"

	"github.com/netbirdio/netbird/management/server/types"
)

//go:generate go tool mockgen -package=account -source=./request_buffer.go -destination=request_buffer_mock.go

type RequestBuffer interface {
	GetAccountWithBackpressure(ctx context.Context, accountID string) (*types.Account, error)
}

package server

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/shared/requestbuffer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const defaultAccountBufferInterval = 100 * time.Millisecond

type AccountRequestBuffer struct {
	buffer *requestbuffer.Buffer[*types.Account]
}

func NewAccountRequestBuffer(ctx context.Context, store store.Store) *AccountRequestBuffer {
	interval := requestbuffer.Interval(ctx, "NB_GET_ACCOUNT_BUFFER_INTERVAL", defaultAccountBufferInterval)
	log.WithContext(ctx).Infof("set account request buffer interval to %s", interval)

	return &AccountRequestBuffer{
		buffer: requestbuffer.New(ctx, "account request buffer", interval, store.GetAccount),
	}
}

func (ac *AccountRequestBuffer) GetAccountWithBackpressure(ctx context.Context, accountID string) (*types.Account, error) {
	account, err := ac.buffer.Get(ctx, accountID)
	if err != nil || account == nil {
		return account, err
	}

	// Shallow copy the account so each caller gets its own struct value.
	// This prevents data races when callers mutate fields like Policies.
	accountCopy := *account
	return &accountCopy, nil
}

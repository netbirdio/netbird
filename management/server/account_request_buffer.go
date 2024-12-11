package server

import (
	"context"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// AccountRequest holds the result channel to return the requested account.
type AccountRequest struct {
	AccountID  string
	ResultChan chan *AccountResult
}

// AccountResult holds the account data or an error.
type AccountResult struct {
	Account *types.Account
	Err     error
}

type AccountRequestBuffer struct {
	store               store.Store
	getAccountRequests  map[string][]*AccountRequest
	mu                  sync.Mutex
	getAccountRequestCh chan *AccountRequest
	bufferInterval      time.Duration
}

func NewAccountRequestBuffer(ctx context.Context, store store.Store) *AccountRequestBuffer {
	bufferIntervalStr := os.Getenv("NB_GET_ACCOUNT_BUFFER_INTERVAL")
	bufferInterval, err := time.ParseDuration(bufferIntervalStr)
	if err != nil {
		if bufferIntervalStr != "" {
			log.WithContext(ctx).Warnf("failed to parse account request buffer interval: %s", err)
		}
		bufferInterval = 100 * time.Millisecond
	}

	log.WithContext(ctx).Infof("set account request buffer interval to %s", bufferInterval)

	ac := AccountRequestBuffer{
		store:               store,
		getAccountRequests:  make(map[string][]*AccountRequest),
		getAccountRequestCh: make(chan *AccountRequest),
		bufferInterval:      bufferInterval,
	}

	go ac.processGetAccountRequests(ctx)

	return &ac
}
func (ac *AccountRequestBuffer) GetAccountWithBackpressure(ctx context.Context, accountID string) (*types.Account, error) {
	req := &AccountRequest{
		AccountID:  accountID,
		ResultChan: make(chan *AccountResult, 1),
	}

	log.WithContext(ctx).Tracef("requesting account %s with backpressure", accountID)
	startTime := time.Now()
	ac.getAccountRequestCh <- req

	result := <-req.ResultChan
	log.WithContext(ctx).Tracef("got account with backpressure after %s", time.Since(startTime))
	return result.Account, result.Err
}

func (ac *AccountRequestBuffer) processGetAccountBatch(ctx context.Context, accountID string) {
	ac.mu.Lock()
	requests := ac.getAccountRequests[accountID]
	delete(ac.getAccountRequests, accountID)
	ac.mu.Unlock()

	if len(requests) == 0 {
		return
	}

	startTime := time.Now()
	account, err := ac.store.GetAccount(ctx, accountID)
	log.WithContext(ctx).Tracef("getting account %s in batch took %s", accountID, time.Since(startTime))
	result := &AccountResult{Account: account, Err: err}

	for _, req := range requests {
		req.ResultChan <- result
		close(req.ResultChan)
	}
}

func (ac *AccountRequestBuffer) processGetAccountRequests(ctx context.Context) {
	for {
		select {
		case req := <-ac.getAccountRequestCh:
			ac.mu.Lock()
			ac.getAccountRequests[req.AccountID] = append(ac.getAccountRequests[req.AccountID], req)
			if len(ac.getAccountRequests[req.AccountID]) == 1 {
				go func(ctx context.Context, accountID string) {
					time.Sleep(ac.bufferInterval)
					ac.processGetAccountBatch(ctx, accountID)
				}(ctx, req.AccountID)
			}
			ac.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

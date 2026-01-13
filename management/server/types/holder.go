package types

import (
	"context"
	"sync"
)

type Holder struct {
	mu       sync.RWMutex
	accounts map[string]*Account
}

func NewHolder() *Holder {
	return &Holder{
		accounts: make(map[string]*Account),
	}
}

func (h *Holder) GetAccount(id string) *Account {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.accounts[id]
}

func (h *Holder) AddAccount(account *Account) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.accounts[account.Id]
	if a != nil && a.Network.CurrentSerial() >= account.Network.CurrentSerial() {
		return
	}
	h.accounts[account.Id] = account
}

func (h *Holder) LoadOrStoreFunc(ctx context.Context, id string, accGetter func(context.Context, string) (*Account, error)) (*Account, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if acc, ok := h.accounts[id]; ok {
		return acc, nil
	}
	account, err := accGetter(ctx, id)
	if err != nil {
		return nil, err
	}
	h.accounts[id] = account
	return account, nil
}

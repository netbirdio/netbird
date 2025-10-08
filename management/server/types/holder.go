package types

import "sync"

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
	h.accounts[account.Id] = account
}

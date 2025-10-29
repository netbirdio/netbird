package server

import (
	"github.com/netbirdio/netbird/management/server/types"
)

func (am *DefaultAccountManager) enrichAccountFromHolder(account *types.Account) {
	a := am.holder.GetAccount(account.Id)
	if a == nil {
		am.holder.AddAccount(account)
		return
	}
	account.NetworkMapCache = a.NetworkMapCache
	if account.NetworkMapCache == nil {
		return
	}
	account.NetworkMapCache.UpdateAccountPointer(account)
	am.holder.AddAccount(account)
}

func (am *DefaultAccountManager) getAccountFromHolder(accountID string) *types.Account {
	return am.holder.GetAccount(accountID)
}

func (am *DefaultAccountManager) updateAccountInHolder(account *types.Account) {
	am.holder.AddAccount(account)
}

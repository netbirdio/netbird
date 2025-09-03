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
	account.NetworkMapCache.UpdateAccountPointer(account)
	am.holder.AddAccount(account)
}

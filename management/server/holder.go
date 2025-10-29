package server

import (
	"context"

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

func (am *DefaultAccountManager) getAccountFromHolderOrInit(accountID string) *types.Account {
	a := am.holder.GetAccount(accountID)
	if a != nil {
		return a
	}
	account, err := am.requestBuffer.GetAccountWithBackpressure(context.Background(), accountID)
	if err != nil {
		return nil
	}
	am.holder.AddAccount(account)
	return account
}

func (am *DefaultAccountManager) updateAccountInHolder(account *types.Account) {
	am.holder.AddAccount(account)
}

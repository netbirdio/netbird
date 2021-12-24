package server

import "github.com/rs/xid"

// Previously Account.Id was an Auth0 user id
// Conversion moved user id to Account.CreatedBy and generated a new Account.Id using xid
// It also adds a User with id = old Account.Id with a role Admin
func convert(oldStore *FileStore, newStore *FileStore) error {
	for _, account := range oldStore.Accounts {
		accountCopy := account.Copy()
		accountCopy.Id = xid.New().String()
		accountCopy.CreatedBy = account.Id
		accountCopy.Users[account.Id] = &User{
			Id:   account.Id,
			Role: UserRoleAdmin,
		}

		err := newStore.SaveAccount(accountCopy)
		if err != nil {
			return err
		}
	}

	return nil
}

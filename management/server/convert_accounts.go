package server

import "github.com/rs/xid"

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

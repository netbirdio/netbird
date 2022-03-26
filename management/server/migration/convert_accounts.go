package main

import (
	"flag"
	"fmt"
	"github.com/netbirdio/netbird/management/server"
	"github.com/rs/xid"
)

func main() {

	oldDir := flag.String("oldDir", "old store directory", "/var/wiretrustee/datadir")
	newDir := flag.String("newDir", "new store directory", "/var/wiretrustee/newdatadir")

	flag.Parse()

	oldStore, err := server.NewStore(*oldDir)
	if err != nil {
		panic(err)
	}

	newStore, err := server.NewStore(*newDir)
	if err != nil {
		panic(err)
	}

	err = Convert(oldStore, newStore)
	if err != nil {
		panic(err)
	}

	fmt.Println("successfully converted")
}

// Convert converts old store ato a new store
// Previously Account.Id was an Auth0 user id
// Conversion moved user id to Account.CreatedBy and generated a new Account.Id using xid
// It also adds a User with id = old Account.Id with a role Admin
func Convert(oldStore *server.FileStore, newStore *server.FileStore) error {
	for _, account := range oldStore.Accounts {
		accountCopy := account.Copy()
		accountCopy.Id = xid.New().String()
		accountCopy.CreatedBy = account.Id
		accountCopy.Users[account.Id] = &server.User{
			Id:   account.Id,
			Role: server.UserRoleAdmin,
		}

		err := newStore.SaveAccount(accountCopy)
		if err != nil {
			return err
		}
	}

	return nil
}

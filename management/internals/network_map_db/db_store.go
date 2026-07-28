package networkmapdb

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

type NetworkMapDBStore interface {
	GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, error)
}

type NetworkMapDBStoreImpl struct {
	store NetworkMapDBStore
}

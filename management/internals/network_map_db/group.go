package networkmapdb

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func (db *NetworkMapDBStoreImpl) GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, error) {
	return db.store.GetGroups(ctx, accountId)
}

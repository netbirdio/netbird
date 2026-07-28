package networkmapdb

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

type NetworkMapDBStore interface {
	GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, error) // TODO: join/populate peers
	GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, error)
	GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, error)
}

type NetworkMapDBStoreImpl struct {
	store NetworkMapDBStore
}

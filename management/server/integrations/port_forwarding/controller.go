package port_forwarding

import (
	"context"

	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

type Controller interface {
	SendUpdate(ctx context.Context, accountID string, affectedProxyID string, affectedPeerIDs []string)
	GetProxyNetworkMaps(ctx context.Context, accountID string) (map[string]*nbtypes.NetworkMap, error)
}

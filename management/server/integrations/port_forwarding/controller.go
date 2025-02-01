package port_forwarding

import (
	"context"

	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

type Controller interface {
	SendUpdate(ctx context.Context, accountID string, affectedProxyID string, affectedPeerIDs []string)
	GetProxyNetworkMaps(ctx context.Context, accountID string) (map[string]*nbtypes.NetworkMap, error)
}

type ControllerMock struct {
}

func NewControllerMock() *ControllerMock {
	return &ControllerMock{}
}

func (c *ControllerMock) SendUpdate(ctx context.Context, accountID string, affectedProxyID string, affectedPeerIDs []string) {
	// noop
}

func (c *ControllerMock) GetProxyNetworkMaps(ctx context.Context, accountID string) (map[string]*nbtypes.NetworkMap, error) {
	return make(map[string]*nbtypes.NetworkMap), nil
}

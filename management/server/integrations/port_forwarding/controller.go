package port_forwarding

import (
	"context"

	"github.com/netbirdio/netbird/management/server/peer"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

type Controller interface {
	SendUpdate(ctx context.Context, accountID string, affectedProxyID string, affectedPeerIDs []string, accountPeers map[string]*peer.Peer)
	GetProxyNetworkMaps(ctx context.Context, accountID, peerID string, accountPeers map[string]*peer.Peer) (map[string]*nbtypes.NetworkMap, error)
	GetProxyNetworkMapsAll(ctx context.Context, accountID string, accountPeers map[string]*peer.Peer) (map[string]*nbtypes.NetworkMap, error)
	IsPeerInIngressPorts(ctx context.Context, accountID, peerID string) (bool, error)
}

type ControllerMock struct {
}

func NewControllerMock() *ControllerMock {
	return &ControllerMock{}
}

func (c *ControllerMock) SendUpdate(ctx context.Context, accountID string, affectedProxyID string, affectedPeerIDs []string, accountPeers map[string]*peer.Peer) {
	// noop
}

func (c *ControllerMock) GetProxyNetworkMaps(ctx context.Context, accountID, peerID string, accountPeers map[string]*peer.Peer) (map[string]*nbtypes.NetworkMap, error) {
	return make(map[string]*nbtypes.NetworkMap), nil
}

func (c *ControllerMock) GetProxyNetworkMapsAll(ctx context.Context, accountID string, accountPeers map[string]*peer.Peer) (map[string]*nbtypes.NetworkMap, error) {
	return make(map[string]*nbtypes.NetworkMap), nil
}

func (c *ControllerMock) IsPeerInIngressPorts(ctx context.Context, accountID, peerID string) (bool, error) {
	return false, nil
}

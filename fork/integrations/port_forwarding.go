// SPDX-License-Identifier: BSD-3-Clause

package integrations

import (
	"context"

	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type controllerImpl struct {
	store store.Store
}

// NewController returns a no-op proxy controller, mirroring the original
// module: without ingress-port integrations there are no proxy network maps.
func NewController(store store.Store) port_forwarding.Controller {
	return &controllerImpl{
		store: store,
	}
}

// SendUpdate drops proxy update notifications, as nothing consumes them.
func (c *controllerImpl) SendUpdate(ctx context.Context, accountID string, affectedProxyID string, affectedPeerIDs []string, accountPeers map[string]*peer.Peer) {
}

// GetProxyNetworkMaps returns an empty set of proxy network maps for a peer.
func (c *controllerImpl) GetProxyNetworkMaps(ctx context.Context, accountID, peerID string, accountPeers map[string]*peer.Peer) (map[string]*types.NetworkMap, error) {
	return make(map[string]*types.NetworkMap), nil
}

// GetProxyNetworkMapsAll returns an empty set of proxy network maps for an account.
func (c *controllerImpl) GetProxyNetworkMapsAll(ctx context.Context, accountID string, accountPeers map[string]*peer.Peer) (map[string]*types.NetworkMap, error) {
	return make(map[string]*types.NetworkMap), nil
}

// IsPeerInIngressPorts reports peers participating in ingress ports; always
// false as ingress ports are not part of this fork.
func (c *controllerImpl) IsPeerInIngressPorts(ctx context.Context, accountID, peerID string) (bool, error) {
	return false, nil
}

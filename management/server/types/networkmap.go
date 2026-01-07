package types

import (
	"context"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

func (a *Account) initNetworkMapBuilder(validatedPeers map[string]struct{}) {
	if a.NetworkMapCache != nil {
		return
	}
	a.nmapInitOnce.Do(func() {
		a.NetworkMapCache = NewNetworkMapBuilder(a, validatedPeers)
	})
}

func (a *Account) InitNetworkMapBuilderIfNeeded(validatedPeers map[string]struct{}) {
	a.initNetworkMapBuilder(validatedPeers)
}

func (a *Account) GetPeerNetworkMapExp(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	accountZones []*zones.Zone,
	validatedPeers map[string]struct{},
	metrics *telemetry.AccountManagerMetrics,
) *NetworkMap {
	a.initNetworkMapBuilder(validatedPeers)
	return a.NetworkMapCache.GetPeerNetworkMap(ctx, peerID, peersCustomZone, accountZones, validatedPeers, metrics)
}

func (a *Account) OnPeerAddedUpdNetworkMapCache(peerId string) error {
	if a.NetworkMapCache == nil {
		return nil
	}
	return a.NetworkMapCache.OnPeerAddedIncremental(a, peerId)
}

func (a *Account) OnPeersAddedUpdNetworkMapCache(peerIds ...string) {
	if a.NetworkMapCache == nil {
		return
	}
	a.NetworkMapCache.EnqueuePeersForIncrementalAdd(a, peerIds...)
}

func (a *Account) OnPeerDeletedUpdNetworkMapCache(peerId string) error {
	if a.NetworkMapCache == nil {
		return nil
	}
	return a.NetworkMapCache.OnPeerDeleted(a, peerId)
}

func (a *Account) UpdatePeerInNetworkMapCache(peer *nbpeer.Peer) {
	if a.NetworkMapCache == nil {
		return
	}
	a.NetworkMapCache.UpdatePeer(peer)
}

func (a *Account) RecalculateNetworkMapCache(validatedPeers map[string]struct{}) {
	a.initNetworkMapBuilder(validatedPeers)
}

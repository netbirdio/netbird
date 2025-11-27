package types

import (
	"context"

	"gvisor.dev/gvisor/pkg/log"

	nbdns "github.com/netbirdio/netbird/dns"
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
	validatedPeers map[string]struct{},
	metrics *telemetry.AccountManagerMetrics,
) *NetworkMap {
	a.initNetworkMapBuilder(validatedPeers)
	nmap := a.NetworkMapCache.GetPeerNetworkMap(ctx, peerID, peersCustomZone, validatedPeers, metrics)
	if len(nmap.Peers) > 0 && len(nmap.FirewallRules) == 0 {
		log.Debugf("NetworkMapBuilder: generated network map for peer %s with peers but no firewall rules, network serial %d", peerID, nmap.Network.Serial)
		a.OnPeerDeletedUpdNetworkMapCache(peerID)
		a.OnPeerAddedUpdNetworkMapCache(peerID)
		nmap = a.NetworkMapCache.GetPeerNetworkMap(ctx, peerID, peersCustomZone, validatedPeers, metrics)
		if len(nmap.Peers) > 0 && len(nmap.FirewallRules) == 0 {
			log.Debugf("NetworkMapBuilder: regenerated network map for peer %s still has no firewall rules", peerID)
		}
	}
	return nmap
}

func (a *Account) OnPeerAddedUpdNetworkMapCache(peerId string) error {
	if a.NetworkMapCache == nil {
		return nil
	}
	return a.NetworkMapCache.OnPeerAddedIncremental(peerId)
}

func (a *Account) OnPeerDeletedUpdNetworkMapCache(peerId string) error {
	if a.NetworkMapCache == nil {
		return nil
	}
	return a.NetworkMapCache.OnPeerDeleted(peerId)
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

package types

import (
	"context"

	log "github.com/sirupsen/logrus"

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
	isRouter bool,
) *NetworkMap {
	a.initNetworkMapBuilder(validatedPeers)
	nmap := a.NetworkMapCache.GetPeerNetworkMap(ctx, peerID, peersCustomZone, validatedPeers, metrics)
	if isRouter && len(nmap.Peers) > 0 && len(nmap.RoutesFirewallRules) == 0 {
		log.WithContext(ctx).Debugf("NetworkMapBuilder: generated network map for peer %s with peers but no routes firewall rules, network serial %d", peerID, nmap.Network.Serial)
	}
	if !isRouter && len(nmap.Peers) > 0 && len(nmap.FirewallRules) == 0 {
		log.WithContext(ctx).Debugf("NetworkMapBuilder: generated network map for peer %s with peers but no firewall rules, network serial %d", peerID, nmap.Network.Serial)
	}
	return nmap
}

func (a *Account) OnPeerAddedUpdNetworkMapCache(peerId string) error {
	if a.NetworkMapCache == nil {
		return nil
	}
	return a.NetworkMapCache.OnPeerAddedIncremental(a, peerId)
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

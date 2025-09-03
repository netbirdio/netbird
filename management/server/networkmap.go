package server

import (
	"context"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
)

func (am *DefaultAccountManager) getPeerNetworkMapExp(
	ctx context.Context,
	account *types.Account,
	peerId string,
	validatedPeers map[string]struct{},
	customZone nbdns.CustomZone,
	metrics *telemetry.AccountManagerMetrics,
) *types.NetworkMap {
	am.enrichAccountFromHolder(account)
	return account.GetPeerNetworkMapExp(ctx, peerId, customZone, validatedPeers, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), metrics)
}

func (am *DefaultAccountManager) onPeerAddedUpdNetworkMapCache(account *types.Account, peerId string, validatedPeers map[string]struct{}) {
	am.enrichAccountFromHolder(account)
	account.OnPeerAddedUpdNetworkMapCache(peerId, validatedPeers)
}

func (am *DefaultAccountManager) onPeerDeletedUpdNetworkMapCache(account *types.Account, peerId string, validatedPeers map[string]struct{}) {
	am.enrichAccountFromHolder(account)
	account.OnPeerDeletedUpdNetworkMapCache(peerId, validatedPeers)
}

func (am *DefaultAccountManager) updatePeerInNetworkMapCache(account *types.Account, peer *nbpeer.Peer) {
	am.enrichAccountFromHolder(account)
	account.UpdatePeerInNetworkMapCache(peer)
}

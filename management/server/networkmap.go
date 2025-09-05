package server

import (
	"context"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
)

func (am *DefaultAccountManager) initNetworkMapBuilderIfNeeded(account *types.Account, validatedPeers map[string]struct{}) {
	am.enrichAccountFromHolder(account)
	account.InitNetworkMapBuilderIfNeeded(validatedPeers)
}

func (am *DefaultAccountManager) getPeerNetworkMapExp(
	ctx context.Context,
	account *types.Account,
	peerId string,
	validatedPeers map[string]struct{},
	customZone nbdns.CustomZone,
	metrics *telemetry.AccountManagerMetrics,
) *types.NetworkMap {
	am.enrichAccountFromHolder(account)
	return account.GetPeerNetworkMapExp(ctx, peerId, customZone, validatedPeers, metrics)
}

func (am *DefaultAccountManager) onPeerAddedUpdNetworkMapCache(account *types.Account, peerId string) error {
	am.enrichAccountFromHolder(account)
	return account.OnPeerAddedUpdNetworkMapCache(peerId)
}

func (am *DefaultAccountManager) onPeerDeletedUpdNetworkMapCache(account *types.Account, peerId string) error {
	am.enrichAccountFromHolder(account)
	return account.OnPeerDeletedUpdNetworkMapCache(peerId)
}

func (am *DefaultAccountManager) updatePeerInNetworkMapCache(account *types.Account, peer *nbpeer.Peer) {
	am.enrichAccountFromHolder(account)
	account.UpdatePeerInNetworkMapCache(peer)
}

func (am *DefaultAccountManager) recalculateNetworkMapCache(account *types.Account, validatedPeers map[string]struct{}) {
	account.RecalculateNetworkMapCache(validatedPeers)
	am.updateAccountInHolder(account)
}

func (am *DefaultAccountManager) RecalculateNetworkMapCache(ctx context.Context, accountId string) error {
	if am.expNewNetworkMap {
		account, err := am.Store.GetAccount(ctx, accountId)
		if err != nil {
			return err
		}
		validatedPeers, err := am.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, maps.Values(account.Groups), maps.Values(account.Peers), account.Settings.Extra)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to get validate peers: %v", err)
			return err
		}
		am.recalculateNetworkMapCache(account, validatedPeers)
	}
	return nil
}

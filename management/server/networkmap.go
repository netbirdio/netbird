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
	accountId string,
	peerId string,
	validatedPeers map[string]struct{},
	customZone nbdns.CustomZone,
	metrics *telemetry.AccountManagerMetrics,
) *types.NetworkMap {
	account := am.getAccountFromHolderOrInit(accountId)
	if account == nil {
		log.WithContext(ctx).Warnf("account %s not found in holder when getting peer network map", accountId)
		return &types.NetworkMap{
			Network: &types.Network{},
		}
	}
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

func (am *DefaultAccountManager) updatePeerInNetworkMapCache(accountId string, peer *nbpeer.Peer) {
	account := am.getAccountFromHolder(accountId)
	if account == nil {
		return
	}
	account.UpdatePeerInNetworkMapCache(peer)
}

func (am *DefaultAccountManager) recalculateNetworkMapCache(account *types.Account, validatedPeers map[string]struct{}) {
	account.RecalculateNetworkMapCache(validatedPeers)
	am.updateAccountInHolder(account)
}

func (am *DefaultAccountManager) RecalculateNetworkMapCache(ctx context.Context, accountId string) error {
	if am.experimentalNetworkMap(accountId) {
		account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountId)
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

func (am *DefaultAccountManager) experimentalNetworkMap(accountId string) bool {
	_, ok := am.expNewNetworkMapAIDs[accountId]
	return am.expNewNetworkMap || ok
}

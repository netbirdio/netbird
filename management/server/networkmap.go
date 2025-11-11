package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
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
	resourcePolicies map[string][]*types.Policy,
	routers map[string]map[string]*routerTypes.NetworkRouter,
) *types.NetworkMap {
	account := am.getAccountFromHolderOrInit(accountId)
	if account == nil {
		log.WithContext(ctx).Warnf("account %s not found in holder when getting peer network map", accountId)
		return &types.NetworkMap{
			Network: &types.Network{},
		}
	}

	legacyMap := account.GetPeerNetworkMap(ctx, peerId, customZone, validatedPeers, resourcePolicies, routers, nil)

	go func() {
		expMap := account.GetPeerNetworkMapExp(ctx, peerId, customZone, validatedPeers, metrics)
		am.compareAndSaveNetworkMaps(ctx, accountId, peerId, expMap, legacyMap)
	}()

	return legacyMap
}

func (am *DefaultAccountManager) compareAndSaveNetworkMaps(ctx context.Context, accountId, peerId string, expMap, legacyMap *types.NetworkMap) {
	expBytes, err := json.Marshal(expMap)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to marshal experimental network map: %v", err)
		return
	}

	legacyBytes, err := json.Marshal(legacyMap)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to marshal legacy network map: %v", err)
		return
	}

	if len(expBytes) == len(legacyBytes) {
		log.WithContext(ctx).Debugf("network maps are equal for peer %s in account %s (size: %d bytes)", peerId, accountId, len(expBytes))
		return
	}

	timestamp := time.Now().UnixMicro()
	baseDir := filepath.Join("debug_networkmaps", accountId, peerId)

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		log.WithContext(ctx).Warnf("failed to create debug directory %s: %v", baseDir, err)
		return
	}

	expFile := filepath.Join(baseDir, fmt.Sprintf("exp_networkmap_%d.json", timestamp))
	if err := os.WriteFile(expFile, expBytes, 0o644); err != nil {
		log.WithContext(ctx).Warnf("failed to write experimental network map to %s: %v", expFile, err)
		return
	}

	legacyFile := filepath.Join(baseDir, fmt.Sprintf("legacy_networkmap_%d.json", timestamp))
	if err := os.WriteFile(legacyFile, legacyBytes, 0o644); err != nil {
		log.WithContext(ctx).Warnf("failed to write legacy network map to %s: %v", legacyFile, err)
		return
	}

	log.WithContext(ctx).Infof("network maps differ for peer %s in account %s - saved to %s (exp: %d bytes, legacy: %d bytes)", peerId, accountId, baseDir, len(expBytes), len(legacyBytes))
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

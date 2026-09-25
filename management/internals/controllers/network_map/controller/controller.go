package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/mod/semver"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/internals/shared/requestbuffer"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	sharedgrpc "github.com/netbirdio/netbird/shared/management/grpc"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

const defaultNetworkMapDataBufferInterval = 100 * time.Millisecond

type Controller struct {
	repo    Repository
	metrics *metrics
	// This should not be here, but we need to maintain it for the time being
	accountManagerMetrics *telemetry.AccountManagerMetrics
	peersUpdateManager    network_map.PeersUpdateManager
	settingsManager       settings.Manager
	EphemeralPeersManager ephemeral.Manager

	accountUpdateLocks               sync.Map
	affectedPeerUpdateLocks          sync.Map
	updateAccountPeersBufferInterval atomic.Int64
	// dnsDomain is used for peer resolution. This is appended to the peer's name
	dnsDomain string
	config    *config.Config

	requestBuffer account.RequestBuffer

	proxyController port_forwarding.Controller

	integratedPeerValidator integrated_validator.IntegratedValidator

	serverSupportedSyncMessageVersion sharedgrpc.SyncMessageVersion

	perAccountServerSupportedSyncMessageVersions map[string]sharedgrpc.SyncMessageVersion

	nmdataStore  *networkmapdb.NetworkMapDBStoreImpl
	nmdataBuffer *requestbuffer.Buffer[*networkmap.NetworkMapData]
}

type bufferUpdate struct {
	mu     sync.Mutex
	next   *time.Timer
	update atomic.Bool
}

type bufferAffectedUpdate struct {
	sendMu  sync.Mutex
	dataMu  sync.Mutex
	next    *time.Timer
	peerIDs map[string]struct{}
}

var _ network_map.Controller = (*Controller)(nil)

func NewController(ctx context.Context, store store.Store, metrics telemetry.AppMetrics, peersUpdateManager network_map.PeersUpdateManager, requestBuffer account.RequestBuffer, integratedPeerValidator integrated_validator.IntegratedValidator, settingsManager settings.Manager, dnsDomain string, proxyController port_forwarding.Controller, ephemeralPeersManager ephemeral.Manager, config *config.Config, nmdataStore *networkmapdb.NetworkMapDBStoreImpl) *Controller {
	nMetrics, err := newMetrics(metrics.UpdateChannelMetrics())
	if err != nil {
		log.Fatal(fmt.Errorf("error creating metrics: %w", err))
	}

	c := &Controller{
		repo:                    newRepository(store),
		metrics:                 nMetrics,
		accountManagerMetrics:   metrics.AccountManagerMetrics(),
		peersUpdateManager:      peersUpdateManager,
		requestBuffer:           requestBuffer,
		integratedPeerValidator: integratedPeerValidator,
		settingsManager:         settingsManager,
		dnsDomain:               dnsDomain,
		config:                  config,

		proxyController:                              proxyController,
		EphemeralPeersManager:                        ephemeralPeersManager,
		serverSupportedSyncMessageVersion:            sharedgrpc.SyncMessageVersionFromConfig(config.HighestSupportedSyncMessageVersion),
		perAccountServerSupportedSyncMessageVersions: sharedgrpc.SyncMessageVersionsFromMap(config.PerAccountHighestSupportedSyncMessageVersion),
		nmdataStore:                                  nmdataStore,
	}

	if nmdataStore != nil {
		interval := requestbuffer.Interval(ctx, "NB_NETWORK_MAP_DATA_BUFFER_INTERVAL", defaultNetworkMapDataBufferInterval)
		log.WithContext(ctx).Infof("set network map data request buffer interval to %s", interval)
		c.nmdataBuffer = requestbuffer.New(ctx, "network map data request buffer", interval, c.fetchNetworkMapData)
	}

	return c
}

func (c *Controller) OnPeerConnected(ctx context.Context, accountID string, peerID string) (chan *network_map.UpdateMessage, error) {
	peer, err := c.repo.GetPeerByID(ctx, accountID, peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer %s: %v", peerID, err)
	}

	c.EphemeralPeersManager.OnPeerConnected(ctx, peer)

	return c.peersUpdateManager.CreateChannel(ctx, peerID), nil
}

func (c *Controller) OnPeerDisconnected(ctx context.Context, accountID string, peerID string) {
	c.peersUpdateManager.CloseChannel(ctx, peerID)
	peer, err := c.repo.GetPeerByID(ctx, accountID, peerID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get peer %s: %v", peerID, err)
		return
	}
	c.EphemeralPeersManager.OnPeerDisconnected(ctx, peer)
}

// injectAllProxyPolicies prepares an account for the per-peer network-map
// computation. It prepends the in-memory agent-network services synthesised
// from the account's current provider/policy state to account.Services, so the
// twin store built from the account carries them alongside the persisted
// reverse-proxy services and synthesises their ACLs. Synthesised services are
// never persisted; the account is loaded fresh per cycle so re-prepending is
// safe and idempotent. Accounts without agent-network providers get an empty
// synth slice — no behaviour change.
func (c *Controller) injectAllProxyPolicies(ctx context.Context, account *types.Account) {
	synth, err := c.repo.SynthesizeAgentNetworkServices(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Warnf("synthesise agent-network services for account %s: %v", account.Id, err)
	} else if len(synth) > 0 {
		account.Services = append(synth, account.Services...)
	}
}

// proxyServicesFromRepo is the store-path counterpart of
// injectAllProxyPolicies: the network-map store reads the policies table, which
// never holds the proxy ACLs, so the twin gets the services they are
// synthesised from — the synthesised agent-network ones first, exactly as the
// account path orders them.
func (c *Controller) proxyServicesFromRepo(ctx context.Context, accountID string) []*nmdata.Service {
	persisted, err := c.repo.GetAccountServices(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get services for account %s: %v", accountID, err)
		return nil
	}

	synth, err := c.repo.SynthesizeAgentNetworkServices(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Warnf("synthesise agent-network services for account %s: %v", accountID, err)
	}

	return types.TwinServices(append(synth, persisted...))
}

func (c *Controller) CountStreams() int {
	return c.peersUpdateManager.CountStreams()
}

func (c *Controller) sendUpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason) error {
	log.WithContext(ctx).Tracef("updating peers for account %s from %s", accountID, util.GetCallerName())

	if nmData := c.getNetworkMapData(ctx, accountID); nmData != nil {
		return c.sendUpdateAccountPeersFromData(ctx, accountID, reason, nmData)
	}

	account, err := c.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to get account: %v", err)
	}

	globalStart := time.Now()

	hasPeersConnected := false
	for _, peer := range account.Peers {
		if c.peersUpdateManager.HasChannel(peer.ID) {
			hasPeersConnected = true
			break
		}

	}

	if !hasPeersConnected {
		return nil
	}

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, types.TwinGroups(maps.Values(account.Groups)), types.TwinPeers(maps.Values(account.Peers)), account.Settings.Extra)
	if err != nil {
		return fmt.Errorf("failed to get validate peers: %v", err)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	c.injectAllProxyPolicies(ctx, account)
	account.PrecomputePostureValidation(ctx)
	dnsCache := &cache.DNSConfigCache{}
	dnsDomain := c.GetDNSDomain(account.Settings)
	peersCustomZone := account.GetPeersCustomZone(ctx, dnsDomain)
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	proxyNetworkMaps, err := c.proxyController.GetProxyNetworkMapsAll(ctx, accountID, account.Peers)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get proxy network maps: %v", err)
		return fmt.Errorf("failed to get proxy network maps: %v", err)
	}

	extraSetting, err := c.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to get flow enabled status: %v", err)
	}

	dnsFwdPort := computeForwarderPort(maps.Values(account.Peers), network_map.DnsForwarderPortMinVersion)

	accountZones, err := c.repo.GetAccountZones(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account zones: %v", err)
		return fmt.Errorf("failed to get account zones: %v", err)
	}

	for _, peer := range account.Peers {
		if !c.peersUpdateManager.HasChannel(peer.ID) {
			log.WithContext(ctx).Tracef("peer %s doesn't have a channel, skipping network map update", peer.ID)
			continue
		}

		if c.accountManagerMetrics != nil {
			c.accountManagerMetrics.CountNmapTriggered(string(reason.Resource), string(reason.Operation))
		}

		wg.Add(1)
		semaphore <- struct{}{}
		go func(p *nbpeer.Peer) {
			defer wg.Done()
			defer func() { <-semaphore }()

			start := time.Now()

			postureChecks, err := c.getPeerPostureChecks(account, p.ID)
			if err != nil {
				log.WithContext(ctx).Debugf("failed to get posture checks for peer %s: %v", p.ID, err)
				return
			}

			c.metrics.CountCalcPostureChecksDuration(time.Since(start))
			start = time.Now()

			peerGroups := account.GetPeerGroups(p.ID)
			proxyNetworkMap := proxyNetworkMaps[p.ID]
			var update *proto.SyncResponse

			commonSyncMessageVersion := sharedgrpc.HighestCommonSyncMessageVersion(
				c.perAccountOrGlobalSupportedSyncMessageVersions(accountID),
				sharedgrpc.SyncMessageVersionFromConfig(&peer.Meta.SyncMessageVersion))

			log.WithContext(ctx).
				WithFields(log.Fields{
					"sync_message_version":        commonSyncMessageVersion,
					"server_sync_message_version": c.perAccountOrGlobalSupportedSyncMessageVersions(peer.AccountID),
					"peer_sync_message_version":   sharedgrpc.SyncMessageVersionFromConfig(&peer.Meta.SyncMessageVersion),
				}).Debug("common highest sync message version")

			if commonSyncMessageVersion == sharedgrpc.ComponentNetworkMap {
				components := account.GetPeerNetworkMapComponents(
					ctx, p.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, groupIDToUserIDs)

				c.metrics.CountCalcPeerNetworkMapDuration(time.Since(start))

				start = time.Now()
				// proxyNetworkMap rides the envelope as a ProxyPatch sidecar;
				// the client merges it into Calculate()'s output the same
				// way the legacy server did via NetworkMap.Merge.
				update = grpc.ToComponentSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, types.TwinPeer(p), nil, nil, components, proxyNetworkMap, dnsDomain, postureChecks, types.TwinAccountSettings(account.Settings), extraSetting, maps.Keys(peerGroups), dnsFwdPort)
				c.metrics.CountToComponentSyncResponseDuration(time.Since(start))

				c.peersUpdateManager.SendUpdate(ctx, p.ID, &network_map.UpdateMessage{
					Update:      update,
					MessageType: network_map.MessageTypeNetworkMap,
				})

				return
			}

			nmap := account.GetPeerNetworkMapFromComponents(
				ctx, p.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, c.accountManagerMetrics, groupIDToUserIDs)

			c.metrics.CountCalcPeerNetworkMapDuration(time.Since(start))

			if proxyNetworkMap != nil {
				nmap.Merge(proxyNetworkMap)
			}

			start = time.Now()
			update = grpc.ToSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, types.TwinPeer(p), nil, nil, nmap, dnsDomain, postureChecks, dnsCache, types.TwinAccountSettings(account.Settings), extraSetting, maps.Keys(peerGroups), dnsFwdPort)
			c.metrics.CountToSyncResponseDuration(time.Since(start))

			c.peersUpdateManager.SendUpdate(ctx, p.ID, &network_map.UpdateMessage{
				Update:      update,
				MessageType: network_map.MessageTypeNetworkMap,
			})
		}(peer)
	}

	wg.Wait()
	if c.accountManagerMetrics != nil {
		c.accountManagerMetrics.CountUpdateAccountPeersDuration(time.Since(globalStart))
	}

	return nil
}

// sendUpdateAccountPeersFromData is the account-free variant of
// sendUpdateAccountPeers: everything is computed from the network-map DB
// store's twin data; only extra settings and validated peers are resolved at
// runtime. Proxy network maps and policy injection, private-service zones,
// group-to-user SSH mappings and forced routing-peer DNS resolution have no
// DB-backed source yet and are omitted.
func (c *Controller) sendUpdateAccountPeersFromData(ctx context.Context, accountID string, reason types.UpdateReason, nmData *networkmap.NetworkMapData) error {
	peersToUpdate := c.connectedPeersFromData(nmData, nil)
	if len(peersToUpdate) == 0 {
		return nil
	}
	return c.sendUpdatesFromData(ctx, accountID, nmData, peersToUpdate, &reason)
}

// sendUpdateForAffectedPeersFromData is the account-free variant of
// sendUpdateForAffectedPeers.
func (c *Controller) sendUpdateForAffectedPeersFromData(ctx context.Context, accountID string, peerIDs []string, nmData *networkmap.NetworkMapData) error {
	if len(peerIDs) == 0 {
		log.WithContext(ctx).Tracef("sendUpdateForAffectedPeersFromData: no affected peers")
		return nil
	}

	peersToUpdate := c.connectedPeersFromData(nmData, peerIDs)
	if len(peersToUpdate) == 0 {
		log.WithContext(ctx).Tracef("sendUpdateForAffectedPeersFromData: no peers to update (affected peers not found in data or no channels)")
		return nil
	}

	log.WithContext(ctx).Tracef("sendUpdateForAffectedPeersFromData: sending network map to %d connected peers", len(peersToUpdate))

	return c.sendUpdatesFromData(ctx, accountID, nmData, peersToUpdate, nil)
}

// connectedPeersFromData returns the peers with an open update channel. An
// empty affected list means all peers; a non-empty list restricts the result
// to those peer IDs.
func (c *Controller) connectedPeersFromData(nmData *networkmap.NetworkMapData, affected []string) []*nmdata.Peer {
	if len(affected) == 0 {
		result := make([]*nmdata.Peer, 0, len(nmData.Peers))
		for _, peer := range nmData.Peers {
			if c.peersUpdateManager.HasChannel(peer.ID) {
				result = append(result, peer)
			}
		}
		return result
	}

	result := make([]*nmdata.Peer, 0, len(affected))
	for _, peerID := range affected {
		peer := nmData.Peers[peerID]
		if peer == nil {
			continue
		}
		if c.peersUpdateManager.HasChannel(peerID) {
			result = append(result, peer)
		}
	}
	return result
}

func (c *Controller) sendUpdatesFromData(ctx context.Context, accountID string, nmData *networkmap.NetworkMapData, peersToUpdate []*nmdata.Peer, reason *types.UpdateReason) error {
	globalStart := time.Now()

	extraSettings, err := c.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to get flow enabled status: %v", err)
	}

	dnsCache := &cache.DNSConfigCache{}
	dnsDomain := c.getDNSDomainFromData(nmData.AccountSettings)
	peersCustomZone := networkmap.PeersCustomZone(ctx, accountID, dnsDomain, nmData.Peers, IPv6AllowedPeersFromData(nmData))

	dnsFwdPort := ComputeForwarderPortFromData(nmData.Peers, network_map.DnsForwarderPortMinVersion)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, peer := range peersToUpdate {
		if reason != nil && c.accountManagerMetrics != nil {
			c.accountManagerMetrics.CountNmapTriggered(string(reason.Resource), string(reason.Operation))
		}

		wg.Add(1)
		semaphore <- struct{}{}
		go func(p *nmdata.Peer) {
			defer wg.Done()
			defer func() { <-semaphore }()

			start := time.Now()

			postureChecks := peerPostureChecksFromData(nmData, p.ID)

			c.metrics.CountCalcPostureChecksDuration(time.Since(start))
			start = time.Now()

			peerGroups := maps.Keys(nmData.GetPeerGroups(p.ID))
			var update *proto.SyncResponse

			commonSyncMessageVersion := sharedgrpc.HighestCommonSyncMessageVersion(
				c.perAccountOrGlobalSupportedSyncMessageVersions(accountID),
				sharedgrpc.SyncMessageVersionFromConfig(&p.Meta.SyncMessageVersion))

			log.WithContext(ctx).
				WithFields(log.Fields{
					"sync_message_version":        commonSyncMessageVersion,
					"server_sync_message_version": c.perAccountOrGlobalSupportedSyncMessageVersions(accountID),
					"peer_sync_message_version":   sharedgrpc.SyncMessageVersionFromConfig(&p.Meta.SyncMessageVersion),
				}).Debug("common highest sync message version")

			if commonSyncMessageVersion == sharedgrpc.ComponentNetworkMap {
				components := nmData.GetPeerNetworkMapComponents(p.ID, peersCustomZone)

				c.metrics.CountCalcPeerNetworkMapDuration(time.Since(start))

				start = time.Now()
				update = grpc.ToComponentSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, p, nil, nil, components, nil, dnsDomain, postureChecks, nmData.AccountSettings, extraSettings, peerGroups, dnsFwdPort)
				c.metrics.CountToComponentSyncResponseDuration(time.Since(start))

				c.peersUpdateManager.SendUpdate(ctx, p.ID, &network_map.UpdateMessage{
					Update:      update,
					MessageType: network_map.MessageTypeNetworkMap,
				})

				return
			}

			nmap := NetworkMapFromData(ctx, nmData, p.ID, peersCustomZone, c.accountManagerMetrics)

			c.metrics.CountCalcPeerNetworkMapDuration(time.Since(start))

			start = time.Now()
			update = grpc.ToSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, p, nil, nil, nmap, dnsDomain, postureChecks, dnsCache, nmData.AccountSettings, extraSettings, peerGroups, dnsFwdPort)
			c.metrics.CountToSyncResponseDuration(time.Since(start))

			c.peersUpdateManager.SendUpdate(ctx, p.ID, &network_map.UpdateMessage{
				Update:      update,
				MessageType: network_map.MessageTypeNetworkMap,
			})
		}(peer)
	}

	wg.Wait()
	if c.accountManagerMetrics != nil {
		c.accountManagerMetrics.CountUpdateAccountPeersDuration(time.Since(globalStart))
	}

	return nil
}

func (c *Controller) getNetworkMapData(ctx context.Context, accountID string) *networkmap.NetworkMapData {
	if c.nmdataBuffer == nil {
		return nil
	}

	nmData, err := c.nmdataBuffer.Get(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get network map data for account %s, falling back to account-based computation: %v", accountID, err)
		return nil
	}

	return nmData
}

// fetchNetworkMapData reads the twin once per buffer window. Its result is
// shared by every waiter of that window, so the mutating steps run here, before
// it is handed out: the twin the callers see is read-only. Injected proxy
// policies carry no posture checks, so precomputing after the injection yields
// the same validation as precomputing before it.
func (c *Controller) fetchNetworkMapData(ctx context.Context, accountID string) (*networkmap.NetworkMapData, error) {
	nmData, err := c.nmdataStore.GetNetworkMapData(ctx, accountID)
	if err != nil {
		return nil, err
	}

	nmData.Services = c.proxyServicesFromRepo(ctx, accountID)
	nmData.BuildPrivateServiceCandidates()
	nmData.InjectProxyPolicies()
	nmData.PrecomputePostureValidation()

	return nmData, nil
}

func (c *Controller) getDNSDomainFromData(settings *nmdata.AccountSettingsInfo) string {
	if settings == nil || settings.DNSDomain == "" {
		return c.dnsDomain
	}
	return settings.DNSDomain
}

func IPv6AllowedPeersFromData(nmData *networkmap.NetworkMapData) map[string]struct{} {
	result := make(map[string]struct{})
	// An account with no IPv6-enabled group runs no overlay at all, so the
	// embedded-proxy carve-out below has nothing to reach and stays shut.
	if nmData.AccountSettings == nil || len(nmData.AccountSettings.IPv6EnabledGroups) == 0 {
		return result
	}
	for _, groupID := range nmData.AccountSettings.IPv6EnabledGroups {
		group := nmData.Groups[groupID]
		if group == nil {
			continue
		}
		for _, peerID := range group.Peers {
			result[peerID] = struct{}{}
		}
	}
	for id, p := range nmData.Peers {
		if p != nil && p.ProxyMeta.Embedded {
			result[id] = struct{}{}
		}
	}
	return result
}

func NetworkMapFromData(ctx context.Context, nmData *networkmap.NetworkMapData, peerID string, peersCustomZone nmdata.CustomZone, metrics *telemetry.AccountManagerMetrics) *types.NetworkMap {
	start := time.Now()

	components := nmData.GetPeerNetworkMapComponents(peerID, peersCustomZone)
	if components.IsEmpty() {
		return &types.NetworkMap{Network: components.Network}
	}
	nm := types.CalculateNetworkMapFromComponents(ctx, components)

	if metrics != nil {
		objectCount := int64(len(nm.Peers) + len(nm.OfflinePeers) + len(nm.Routes) + len(nm.FirewallRules) + len(nm.RoutesFirewallRules))
		metrics.CountNetworkMapObjects(objectCount)
		metrics.CountGetPeerNetworkMapDuration(time.Since(start))
	}

	return nm
}

// peerPostureChecksFromData mirrors getPeerPostureChecks on the twin store.
func peerPostureChecksFromData(nmData *networkmap.NetworkMapData, peerID string) []*nmdata.PostureChecks {
	if len(nmData.PostureChecks) == 0 {
		return nil
	}

	peerPostureChecks := make(map[string]*nmdata.PostureChecks)
	for _, policy := range nmData.Policies {
		if policy == nil || !policy.Enabled || len(policy.SourcePostureChecks) == 0 {
			continue
		}
		if !isPeerInPolicySourcesFromData(nmData, peerID, policy) {
			continue
		}
		for _, checkID := range policy.SourcePostureChecks {
			if twin := nmData.PostureChecks[checkID]; twin != nil {
				peerPostureChecks[checkID] = twin
			}
		}
	}

	return maps.Values(peerPostureChecks)
}

func isPeerInPolicySourcesFromData(nmData *networkmap.NetworkMapData, peerID string, policy *nmdata.Policy) bool {
	for _, rule := range policy.Rules {
		if rule == nil || !rule.Enabled {
			continue
		}
		if rule.SourceResource.Type == string(types.ResourceTypePeer) && rule.SourceResource.ID == peerID {
			return true
		}
		for _, groupID := range rule.Sources {
			if group := nmData.Groups[groupID]; group != nil && slices.Contains(group.Peers, peerID) {
				return true
			}
		}
	}
	return false
}

func (c *Controller) perAccountOrGlobalSupportedSyncMessageVersions(accountId string) sharedgrpc.SyncMessageVersion {
	if perAccount, ok := c.perAccountServerSupportedSyncMessageVersions[accountId]; ok {
		return perAccount
	}
	return c.serverSupportedSyncMessageVersion
}

// UpdatePeers updates all peers that belong to an account.
// Should be called when changes have to be synced to peers.
func (c *Controller) UpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason) error {
	if c.accountManagerMetrics != nil {
		c.accountManagerMetrics.CountUpdateAccountPeersTriggered(string(reason.Resource), string(reason.Operation))
	}
	return c.sendUpdateAccountPeers(ctx, accountID, reason)
}

// UpdateAffectedPeers updates only the specified peers that belong to an account.
func (c *Controller) UpdateAffectedPeers(ctx context.Context, accountID string, peerIDs []string) error {
	if len(peerIDs) == 0 {
		return nil
	}
	return c.sendUpdateForAffectedPeers(ctx, accountID, peerIDs)
}

func (c *Controller) sendUpdateForAffectedPeers(ctx context.Context, accountID string, peerIDs []string) error {
	log.WithContext(ctx).Tracef("sendUpdateForAffectedPeers: account %s, %d affected peers: %v (caller: %s)", accountID, len(peerIDs), peerIDs, util.GetCallerName())

	if !c.hasConnectedPeers(peerIDs) {
		log.WithContext(ctx).Tracef("sendUpdateForAffectedPeers: no connected peers among %v, skipping", peerIDs)
		return nil
	}

	if nmData := c.getNetworkMapData(ctx, accountID); nmData != nil {
		return c.sendUpdateForAffectedPeersFromData(ctx, accountID, peerIDs, nmData)
	}

	account, err := c.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to get account: %v", err)
	}

	globalStart := time.Now()

	peersToUpdate := c.filterConnectedAffectedPeers(account, peerIDs)
	if len(peersToUpdate) == 0 {
		log.WithContext(ctx).Tracef("sendUpdateForAffectedPeers: no peers to update (affected peers not found in account or no channels)")
		return nil
	}

	log.WithContext(ctx).Tracef("sendUpdateForAffectedPeers: sending network map to %d connected peers", len(peersToUpdate))

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, types.TwinGroups(maps.Values(account.Groups)), types.TwinPeers(maps.Values(account.Peers)), account.Settings.Extra)
	if err != nil {
		return fmt.Errorf("failed to get validate peers: %v", err)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	// The affected-peer path MUST mirror sendUpdateAccountPeers (line 171)
	// here: injectAllProxyPolicies prepends the synthesised agent-network
	// services BEFORE InjectProxyPolicies + private-service policies run.
	// Previously this path called only account.InjectProxyPolicies, which
	// skipped the synth-services prepend — so peer-level changes
	// (proxy restart, embedded peer connect/disconnect) propagated a
	// network map that omitted the synth DNS zone, and the agent kept
	// resolving against the stale or absent record.
	c.injectAllProxyPolicies(ctx, account)
	account.PrecomputePostureValidation(ctx)
	dnsCache := &cache.DNSConfigCache{}
	dnsDomain := c.GetDNSDomain(account.Settings)
	peersCustomZone := account.GetPeersCustomZone(ctx, dnsDomain)
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	proxyNetworkMaps, err := c.proxyController.GetProxyNetworkMapsAll(ctx, accountID, account.Peers)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get proxy network maps: %v", err)
		return fmt.Errorf("failed to get proxy network maps: %v", err)
	}

	extraSetting, err := c.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to get flow enabled status: %v", err)
	}

	dnsFwdPort := computeForwarderPort(maps.Values(account.Peers), network_map.DnsForwarderPortMinVersion)

	accountZones, err := c.repo.GetAccountZones(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account zones: %v", err)
		return fmt.Errorf("failed to get account zones: %v", err)
	}

	for _, peer := range peersToUpdate {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(p *nbpeer.Peer) {
			defer wg.Done()
			defer func() { <-semaphore }()

			start := time.Now()

			postureChecks, err := c.getPeerPostureChecks(account, p.ID)
			if err != nil {
				log.WithContext(ctx).Debugf("failed to get posture checks for peer %s: %v", p.ID, err)
				return
			}

			c.metrics.CountCalcPostureChecksDuration(time.Since(start))
			start = time.Now()

			peerGroups := account.GetPeerGroups(p.ID)
			proxyNetworkMap := proxyNetworkMaps[p.ID]
			var update *proto.SyncResponse

			commonSyncMessageVersion := sharedgrpc.HighestCommonSyncMessageVersion(
				c.perAccountOrGlobalSupportedSyncMessageVersions(accountID),
				sharedgrpc.SyncMessageVersionFromConfig(&peer.Meta.SyncMessageVersion))

			log.WithContext(ctx).
				WithFields(log.Fields{
					"sync_message_version":        commonSyncMessageVersion,
					"server_sync_message_version": c.perAccountOrGlobalSupportedSyncMessageVersions(peer.AccountID),
					"peer_sync_message_version":   sharedgrpc.SyncMessageVersionFromConfig(&peer.Meta.SyncMessageVersion),
				}).Debug("common highest sync message version")

			if commonSyncMessageVersion == sharedgrpc.ComponentNetworkMap {
				components := account.GetPeerNetworkMapComponents(
					ctx, p.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, groupIDToUserIDs)

				c.metrics.CountCalcPeerNetworkMapDuration(time.Since(start))

				start = time.Now()
				// proxyNetworkMap rides the envelope as a ProxyPatch sidecar;
				// the client merges it into Calculate()'s output the same
				// way the legacy server did via NetworkMap.Merge.
				update = grpc.ToComponentSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, types.TwinPeer(p), nil, nil, components, proxyNetworkMap, dnsDomain, postureChecks, types.TwinAccountSettings(account.Settings), extraSetting, maps.Keys(peerGroups), dnsFwdPort)
				c.metrics.CountToComponentSyncResponseDuration(time.Since(start))

				c.peersUpdateManager.SendUpdate(ctx, p.ID, &network_map.UpdateMessage{
					Update:      update,
					MessageType: network_map.MessageTypeNetworkMap,
				})

				return
			}

			nmap := account.GetPeerNetworkMapFromComponents(
				ctx, p.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, c.accountManagerMetrics, groupIDToUserIDs)

			c.metrics.CountCalcPeerNetworkMapDuration(time.Since(start))

			if proxyNetworkMap != nil {
				nmap.Merge(proxyNetworkMap)
			}

			start = time.Now()
			update = grpc.ToSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, types.TwinPeer(p), nil, nil, nmap, dnsDomain, postureChecks, dnsCache, types.TwinAccountSettings(account.Settings), extraSetting, maps.Keys(peerGroups), dnsFwdPort)
			c.metrics.CountToSyncResponseDuration(time.Since(start))

			c.peersUpdateManager.SendUpdate(ctx, p.ID, &network_map.UpdateMessage{
				Update:      update,
				MessageType: network_map.MessageTypeNetworkMap,
			})
		}(peer)
	}

	wg.Wait()
	if c.accountManagerMetrics != nil {
		c.accountManagerMetrics.CountUpdateAccountPeersDuration(time.Since(globalStart))
	}

	return nil
}

func (c *Controller) hasConnectedPeers(peerIDs []string) bool {
	for _, id := range peerIDs {
		if c.peersUpdateManager.HasChannel(id) {
			return true
		}
	}
	return false
}

func (c *Controller) filterConnectedAffectedPeers(account *types.Account, peerIDs []string) []*nbpeer.Peer {
	affected := make(map[string]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		affected[id] = struct{}{}
	}

	var result []*nbpeer.Peer
	for _, peer := range account.Peers {
		if _, ok := affected[peer.ID]; ok && c.peersUpdateManager.HasChannel(peer.ID) {
			result = append(result, peer)
		}
	}
	return result
}

func (c *Controller) UpdateAccountPeer(ctx context.Context, accountId string, peerId string) error {
	if !c.peersUpdateManager.HasChannel(peerId) {
		return fmt.Errorf("peer %s doesn't have a channel, skipping network map update", peerId)
	}

	account, err := c.requestBuffer.GetAccountWithBackpressure(ctx, accountId)
	if err != nil {
		return fmt.Errorf("failed to send out updates to peer %s: %v", peerId, err)
	}

	peer := account.GetPeer(peerId)
	if peer == nil {
		return fmt.Errorf("peer %s doesn't exists in account %s", peerId, accountId)
	}

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, types.TwinGroups(maps.Values(account.Groups)), types.TwinPeers(maps.Values(account.Peers)), account.Settings.Extra)
	if err != nil {
		return fmt.Errorf("failed to get validated peers: %v", err)
	}

	c.injectAllProxyPolicies(ctx, account)
	dnsCache := &cache.DNSConfigCache{}
	dnsDomain := c.GetDNSDomain(account.Settings)
	peersCustomZone := account.GetPeersCustomZone(ctx, dnsDomain)
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	postureChecks, err := c.getPeerPostureChecks(account, peerId)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to send update to peer %s, failed to get posture checks: %v", peerId, err)
		return fmt.Errorf("failed to get posture checks for peer %s: %v", peerId, err)
	}

	proxyNetworkMaps, err := c.proxyController.GetProxyNetworkMaps(ctx, account.Id, peer.ID, account.Peers)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get proxy network maps: %v", err)
		return err
	}

	accountZones, err := c.repo.GetAccountZones(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account zones: %v", err)
		return err
	}

	proxyNetworkMap := proxyNetworkMaps[peer.ID]
	extraSettings, err := c.settingsManager.GetExtraSettings(ctx, peer.AccountID)
	if err != nil {
		return fmt.Errorf("failed to get extra settings: %v", err)
	}

	peerGroups := account.GetPeerGroups(peerId)
	dnsFwdPort := computeForwarderPort(maps.Values(account.Peers), network_map.DnsForwarderPortMinVersion)

	var update *proto.SyncResponse

	commonSyncMessageVersion := sharedgrpc.HighestCommonSyncMessageVersion(
		c.perAccountOrGlobalSupportedSyncMessageVersions(accountId),
		sharedgrpc.SyncMessageVersionFromConfig(&peer.Meta.SyncMessageVersion))

	log.WithContext(ctx).
		WithFields(log.Fields{
			"sync_message_version":        commonSyncMessageVersion,
			"server_sync_message_version": c.perAccountOrGlobalSupportedSyncMessageVersions(peer.AccountID),
			"peer_sync_message_version":   sharedgrpc.SyncMessageVersionFromConfig(&peer.Meta.SyncMessageVersion),
		}).Debug("common highest sync message version")

	if commonSyncMessageVersion == sharedgrpc.ComponentNetworkMap {
		components := account.GetPeerNetworkMapComponents(
			ctx, peer.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, groupIDToUserIDs)

		// proxyNetworkMap rides the envelope as a ProxyPatch sidecar;
		// the client merges it into Calculate()'s output the same
		// way the legacy server did via NetworkMap.Merge.
		update = grpc.ToComponentSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, types.TwinPeer(peer), nil, nil, components, proxyNetworkMap, dnsDomain, postureChecks, types.TwinAccountSettings(account.Settings), extraSettings, maps.Keys(peerGroups), dnsFwdPort)

		c.peersUpdateManager.SendUpdate(ctx, peer.ID, &network_map.UpdateMessage{
			Update:      update,
			MessageType: network_map.MessageTypeNetworkMap,
		})

		return nil
	}

	nmap := account.GetPeerNetworkMapFromComponents(
		ctx, peer.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, c.accountManagerMetrics, groupIDToUserIDs)

	if proxyNetworkMap != nil {
		nmap.Merge(proxyNetworkMap)
	}

	update = grpc.ToSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, types.TwinPeer(peer), nil, nil, nmap, dnsDomain, postureChecks, dnsCache, types.TwinAccountSettings(account.Settings), extraSettings, maps.Keys(peerGroups), dnsFwdPort)

	c.peersUpdateManager.SendUpdate(ctx, peer.ID, &network_map.UpdateMessage{
		Update:      update,
		MessageType: network_map.MessageTypeNetworkMap,
	})

	return nil
}

func (c *Controller) BufferUpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason) error {
	log.WithContext(ctx).Tracef("buffer updating peers for account %s from %s", accountID, util.GetCallerName())

	if c.accountManagerMetrics != nil {
		c.accountManagerMetrics.CountUpdateAccountPeersTriggered(string(reason.Resource), string(reason.Operation))
	}

	bufUpd, _ := c.accountUpdateLocks.LoadOrStore(accountID, &bufferUpdate{})
	b := bufUpd.(*bufferUpdate)

	if !b.mu.TryLock() {
		b.update.Store(true)
		return nil
	}

	if b.next != nil {
		b.next.Stop()
	}

	go func() {
		defer b.mu.Unlock()
		_ = c.sendUpdateAccountPeers(ctx, accountID, reason)
		if !b.update.Load() {
			return
		}
		b.update.Store(false)
		if b.next == nil {
			b.next = time.AfterFunc(time.Duration(c.updateAccountPeersBufferInterval.Load()), func() {
				_ = c.sendUpdateAccountPeers(ctx, accountID, reason)
			})
			return
		}
		b.next.Reset(time.Duration(c.updateAccountPeersBufferInterval.Load()))
	}()

	return nil
}

// GetValidatedPeerWithComponents is the components-format counterpart of
// GetValidatedPeerWithMap. It returns raw NetworkMapComponents for capable
// peers along with the proxy NetworkMap fragment (BYOP / port-forwarding
// data the legacy server folds in via NetworkMap.Merge). The gRPC layer
// encodes both into the wire envelope. Callers must gate on capability
// themselves before dispatching here — this method does NOT branch on it.
func (c *Controller) GetValidatedPeerWithComponents(ctx context.Context, isRequiresApproval bool, accountID string, peer *nbpeer.Peer) (*nbpeer.Peer, *types.NetworkMapComponents, *types.NetworkMap, []*nmdata.PostureChecks, int64, error) {
	if isRequiresApproval {
		network, err := c.repo.GetAccountNetwork(ctx, accountID)
		if err != nil {
			return nil, nil, nil, nil, 0, err
		}
		return peer, &types.NetworkMapComponents{Network: types.TwinNetwork(network)}, nil, nil, 0, nil
	}

	if nmData := c.getNetworkMapData(ctx, accountID); nmData != nil {
		return c.getValidatedPeerWithComponentsFromData(ctx, accountID, peer, nmData)
	}

	account, err := c.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}

	// it's possible that the peer gets deleted between the call to "sendInitialSync()" and here, bail out in this case
	if _, ok := account.Peers[peer.ID]; !ok {
		return nil, nil, nil, nil, 0, fmt.Errorf("peer '%s' no longer exists", peer.ID)
	}

	c.injectAllProxyPolicies(ctx, account)

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, types.TwinGroups(maps.Values(account.Groups)), types.TwinPeers(maps.Values(account.Peers)), account.Settings.Extra)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}

	postureChecks, err := c.getPeerPostureChecks(account, peer.ID)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}

	accountZones, err := c.repo.GetAccountZones(ctx, account.Id)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}

	// Fetch the proxy network map fragment for this peer alongside the
	// components — same single-account-load path the streaming controller
	// uses, so initial-sync delivers BYOP/forwarding patches synchronously
	// instead of waiting for the next streaming push.
	proxyNetworkMaps, err := c.proxyController.GetProxyNetworkMaps(ctx, account.Id, peer.ID, account.Peers)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get proxy network maps: %v", err)
		return nil, nil, nil, nil, 0, err
	}

	dnsDomain := c.GetDNSDomain(account.Settings)
	peersCustomZone := account.GetPeersCustomZone(ctx, dnsDomain)

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()
	components := account.GetPeerNetworkMapComponents(ctx, peer.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, groupIDToUserIDs)
	dnsFwdPort := computeForwarderPort(maps.Values(account.Peers), network_map.DnsForwarderPortMinVersion)

	return peer, components, proxyNetworkMaps[peer.ID], postureChecks, dnsFwdPort, nil
}

// getValidatedPeerWithComponentsFromData is the account-free variant of
// GetValidatedPeerWithComponents. The proxy network map fragment is omitted
// like on the other nmdata paths.
func (c *Controller) getValidatedPeerWithComponentsFromData(ctx context.Context, accountID string, peer *nbpeer.Peer, nmData *networkmap.NetworkMapData) (*nbpeer.Peer, *types.NetworkMapComponents, *types.NetworkMap, []*nmdata.PostureChecks, int64, error) {
	postureChecks := peerPostureChecksFromData(nmData, peer.ID)

	dnsDomain := c.getDNSDomainFromData(nmData.AccountSettings)
	peersCustomZone := networkmap.PeersCustomZone(ctx, accountID, dnsDomain, nmData.Peers, IPv6AllowedPeersFromData(nmData))

	components := nmData.GetPeerNetworkMapComponents(peer.ID, peersCustomZone)
	dnsFwdPort := ComputeForwarderPortFromData(nmData.Peers, network_map.DnsForwarderPortMinVersion)

	return peer, components, nil, postureChecks, dnsFwdPort, nil
}

// BufferUpdateAffectedPeers accumulates peer IDs and flushes them after the buffer interval.
func (c *Controller) BufferUpdateAffectedPeers(ctx context.Context, accountID string, peerIDs []string, reason types.UpdateReason) error {
	if len(peerIDs) == 0 {
		return nil
	}

	if c.accountManagerMetrics != nil {
		c.accountManagerMetrics.CountUpdateAccountPeersTriggered(string(reason.Resource), string(reason.Operation))
	}

	log.WithContext(ctx).Tracef("buffer updating %d affected peers for account %s from %s with reason %s/%s", len(peerIDs), accountID, util.GetCallerName(), reason.Operation, reason.Resource)

	bufUpd, _ := c.affectedPeerUpdateLocks.LoadOrStore(accountID, &bufferAffectedUpdate{
		peerIDs: make(map[string]struct{}),
	})
	b := bufUpd.(*bufferAffectedUpdate)

	b.addPeerIDs(peerIDs)

	if !b.sendMu.TryLock() {
		// Another goroutine is already sending; it will pick up our IDs on its next drain.
		return nil
	}

	b.stopTimer()

	// The send and the debounced timer outlive the calling request, so detach from
	// its context to avoid sending with a cancelled context once the handler returns.
	bgCtx := context.WithoutCancel(ctx)

	collected := b.drainPeerIDs()
	go func() {
		defer b.sendMu.Unlock()
		_ = c.sendUpdateForAffectedPeers(bgCtx, accountID, collected)

		// Check if more peer IDs accumulated while we were sending.
		if !b.hasPending() {
			return
		}

		// Schedule a debounced flush for the newly accumulated IDs.
		b.setTimer(time.Duration(c.updateAccountPeersBufferInterval.Load()), func() {
			ids := b.drainPeerIDs()
			if len(ids) > 0 {
				_ = c.sendUpdateForAffectedPeers(bgCtx, accountID, ids)
			}
		})
	}()

	return nil
}

func (b *bufferAffectedUpdate) addPeerIDs(ids []string) {
	b.dataMu.Lock()
	for _, id := range ids {
		b.peerIDs[id] = struct{}{}
	}
	b.dataMu.Unlock()
}

func (b *bufferAffectedUpdate) drainPeerIDs() []string {
	b.dataMu.Lock()
	defer b.dataMu.Unlock()
	if len(b.peerIDs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(b.peerIDs))
	for id := range b.peerIDs {
		ids = append(ids, id)
	}
	b.peerIDs = make(map[string]struct{})
	return ids
}

func (b *bufferAffectedUpdate) hasPending() bool {
	b.dataMu.Lock()
	defer b.dataMu.Unlock()
	return len(b.peerIDs) > 0
}

func (b *bufferAffectedUpdate) stopTimer() {
	b.dataMu.Lock()
	defer b.dataMu.Unlock()
	if b.next != nil {
		b.next.Stop()
	}
}

func (b *bufferAffectedUpdate) setTimer(d time.Duration, f func()) {
	b.dataMu.Lock()
	defer b.dataMu.Unlock()
	if b.next == nil {
		b.next = time.AfterFunc(d, f)
		return
	}
	b.next.Reset(d)
}

func (c *Controller) GetValidatedPeerWithMap(ctx context.Context, isRequiresApproval bool, accountID string, peerID string) (*types.NetworkMap, []*nmdata.PostureChecks, int64, error) {
	if isRequiresApproval {
		network, err := c.repo.GetAccountNetwork(ctx, accountID)
		if err != nil {
			return nil, nil, 0, err
		}

		emptyMap := &types.NetworkMap{
			Network: types.TwinNetwork(network),
		}
		return emptyMap, nil, 0, nil
	}

	if nmData := c.getNetworkMapData(ctx, accountID); nmData != nil {
		return c.getValidatedPeerWithMapFromData(ctx, accountID, peerID, nmData)
	}

	account, err := c.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, nil, 0, err
	}

	c.injectAllProxyPolicies(ctx, account)

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, types.TwinGroups(maps.Values(account.Groups)), types.TwinPeers(maps.Values(account.Peers)), account.Settings.Extra)
	if err != nil {
		return nil, nil, 0, err
	}

	postureChecks, err := c.getPeerPostureChecks(account, peerID)
	if err != nil {
		return nil, nil, 0, err
	}

	accountZones, err := c.repo.GetAccountZones(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account zones: %v", err)
		return nil, nil, 0, err
	}

	dnsDomain := c.GetDNSDomain(account.Settings)
	peersCustomZone := account.GetPeersCustomZone(ctx, dnsDomain)

	proxyNetworkMaps, err := c.proxyController.GetProxyNetworkMaps(ctx, account.Id, peerID, account.Peers)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get proxy network maps: %v", err)
		return nil, nil, 0, err
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()
	networkMap := account.GetPeerNetworkMapFromComponents(ctx, peerID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, c.accountManagerMetrics, groupIDToUserIDs)

	proxyNetworkMap, ok := proxyNetworkMaps[peerID]
	if ok {
		networkMap.Merge(proxyNetworkMap)
	}

	dnsFwdPort := computeForwarderPort(maps.Values(account.Peers), network_map.DnsForwarderPortMinVersion)

	return networkMap, postureChecks, dnsFwdPort, nil
}

// getValidatedPeerWithMapFromData is the account-free variant of
// GetValidatedPeerWithMap. The proxy network map fragment is omitted like on
// the other nmdata paths.
func (c *Controller) getValidatedPeerWithMapFromData(ctx context.Context, accountID string, peerID string, nmData *networkmap.NetworkMapData) (*types.NetworkMap, []*nmdata.PostureChecks, int64, error) {
	postureChecks := peerPostureChecksFromData(nmData, peerID)

	dnsDomain := c.getDNSDomainFromData(nmData.AccountSettings)
	peersCustomZone := networkmap.PeersCustomZone(ctx, accountID, dnsDomain, nmData.Peers, IPv6AllowedPeersFromData(nmData))

	networkMap := NetworkMapFromData(ctx, nmData, peerID, peersCustomZone, c.accountManagerMetrics)
	dnsFwdPort := ComputeForwarderPortFromData(nmData.Peers, network_map.DnsForwarderPortMinVersion)

	return networkMap, postureChecks, dnsFwdPort, nil
}

// GetDNSDomain returns the configured dnsDomain
func (c *Controller) GetDNSDomain(settings *types.Settings) string {
	if settings == nil {
		return c.dnsDomain
	}
	if settings.DNSDomain == "" {
		return c.dnsDomain
	}

	return settings.DNSDomain
}

// getPeerPostureChecks returns the posture checks applied for a given peer.
func (c *Controller) getPeerPostureChecks(account *types.Account, peerID string) ([]*nmdata.PostureChecks, error) {
	peerPostureChecks := make(map[string]*posture.Checks)

	if len(account.PostureChecks) == 0 {
		return nil, nil
	}

	for _, policy := range account.Policies {
		if !policy.Enabled || len(policy.SourcePostureChecks) == 0 {
			continue
		}

		if err := addPolicyPostureChecks(account, peerID, policy, peerPostureChecks); err != nil {
			return nil, err
		}
	}

	return types.TwinPostureChecksList(maps.Values(peerPostureChecks)), nil
}

func (c *Controller) StartWarmup(ctx context.Context) {
	var initialInterval int64
	intervalStr := os.Getenv("NB_PEER_UPDATE_INTERVAL_MS")
	interval, err := strconv.Atoi(intervalStr)
	if err != nil {
		initialInterval = 1
		log.WithContext(ctx).Warnf("failed to parse peer update interval, using default value %dms: %v", initialInterval, err)
	} else {
		initialInterval = int64(interval) * 10
		go func() {
			startupPeriodStr := os.Getenv("NB_PEER_UPDATE_STARTUP_PERIOD_S")
			startupPeriod, err := strconv.Atoi(startupPeriodStr)
			if err != nil {
				startupPeriod = 1
				log.WithContext(ctx).Warnf("failed to parse peer update startup period, using default value %ds: %v", startupPeriod, err)
			}
			time.Sleep(time.Duration(startupPeriod) * time.Second)
			c.updateAccountPeersBufferInterval.Store(int64(time.Duration(interval) * time.Millisecond))
			log.WithContext(ctx).Infof("set peer update buffer interval to %dms", interval)
		}()
	}
	c.updateAccountPeersBufferInterval.Store(int64(time.Duration(initialInterval) * time.Millisecond))
	log.WithContext(ctx).Infof("set peer update buffer interval to %dms", initialInterval)

}

// computeForwarderPort checks if all peers in the account have updated to a specific version or newer.
// If all peers have the required version, it returns the new well-known port (22054), otherwise returns 0.
func computeForwarderPort(peers []*nbpeer.Peer, requiredVersion string) int64 {
	versions := make([]string, 0, len(peers))
	for _, peer := range peers {
		versions = append(versions, peer.Meta.WtVersion)
	}
	return computeForwarderPortFromVersions(versions, requiredVersion)
}

func ComputeForwarderPortFromData(peers map[string]*nmdata.Peer, requiredVersion string) int64 {
	versions := make([]string, 0, len(peers))
	for _, peer := range peers {
		versions = append(versions, peer.Meta.WtVersion)
	}
	return computeForwarderPortFromVersions(versions, requiredVersion)
}

func computeForwarderPortFromVersions(wtVersions []string, requiredVersion string) int64 {
	if len(wtVersions) == 0 {
		return int64(network_map.OldForwarderPort)
	}

	reqVer := semver.Canonical(requiredVersion)

	// Check if all peers have the required version or newer
	for _, wtVersion := range wtVersions {

		// Development version is always supported
		if version.IsDevelopmentVersion(wtVersion) {
			continue
		}
		peerVersion := semver.Canonical("v" + wtVersion)
		if peerVersion == "" {
			// If any peer doesn't have version info, return 0
			return int64(network_map.OldForwarderPort)
		}

		// Compare versions
		if semver.Compare(peerVersion, reqVer) < 0 {
			return int64(network_map.OldForwarderPort)
		}
	}

	// All peers have the required version or newer
	return int64(network_map.DnsForwarderPort)
}

// addPolicyPostureChecks adds posture checks from a policy to the peer posture checks map if the peer is in the policy's source groups.
func addPolicyPostureChecks(account *types.Account, peerID string, policy *types.Policy, peerPostureChecks map[string]*posture.Checks) error {
	isInGroup, err := isPeerInPolicySources(account, peerID, policy)
	if err != nil {
		return err
	}

	if !isInGroup {
		return nil
	}

	for _, sourcePostureCheckID := range policy.SourcePostureChecks {
		postureCheck := account.GetPostureChecks(sourcePostureCheckID)
		if postureCheck == nil {
			return errors.New("failed to add policy posture checks: posture checks not found")
		}
		peerPostureChecks[sourcePostureCheckID] = postureCheck
	}

	return nil
}

// isPeerInPolicySources checks if a peer is a source of the policy, directly or through a source group.
func isPeerInPolicySources(account *types.Account, peerID string, policy *types.Policy) (bool, error) {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID == peerID {
			return true, nil
		}

		for _, sourceGroup := range rule.Sources {
			group := account.GetGroup(sourceGroup)
			if group == nil {
				return false, fmt.Errorf("failed to check peer in policy source group: group not found")
			}

			if slices.Contains(group.Peers, peerID) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (c *Controller) OnPeersUpdated(ctx context.Context, accountID string, peerIDs []string, affectedPeerIDs []string) error {
	if len(affectedPeerIDs) == 0 {
		log.WithContext(ctx).Tracef("no affected peers for peer update in account %s, skipping", accountID)
		return nil
	}
	return c.BufferUpdateAffectedPeers(ctx, accountID, affectedPeerIDs, types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationUpdate})
}

func (c *Controller) OnPeersAdded(ctx context.Context, accountID string, peerIDs []string, affectedPeerIDs []string) error {
	log.WithContext(ctx).Debugf("OnPeersAdded call to add peers: %v", peerIDs)
	if len(affectedPeerIDs) == 0 {
		log.WithContext(ctx).Tracef("no affected peers for peer add in account %s, skipping", accountID)
		return nil
	}
	return c.BufferUpdateAffectedPeers(ctx, accountID, affectedPeerIDs, types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationCreate})
}

func (c *Controller) OnPeersDeleted(ctx context.Context, accountID string, peerIDs []string, affectedPeerIDs []string) error {
	network, err := c.repo.GetAccountNetwork(ctx, accountID)
	if err != nil {
		return err
	}

	peers, err := c.repo.GetAccountPeers(ctx, accountID)
	if err != nil {
		return err
	}

	dnsFwdPort := computeForwarderPort(peers, network_map.DnsForwarderPortMinVersion)
	for _, peerID := range peerIDs {
		c.peersUpdateManager.SendUpdate(ctx, peerID, &network_map.UpdateMessage{
			Update: &proto.SyncResponse{
				RemotePeers:        []*proto.RemotePeerConfig{},
				RemotePeersIsEmpty: true,
				NetworkMap: &proto.NetworkMap{
					Serial:               network.CurrentSerial(),
					RemotePeers:          []*proto.RemotePeerConfig{},
					RemotePeersIsEmpty:   true,
					FirewallRules:        []*proto.FirewallRule{},
					FirewallRulesIsEmpty: true,
					DNSConfig: &proto.DNSConfig{
						ForwarderPort: dnsFwdPort, //nolint:staticcheck
					},
				},
			},
			MessageType: network_map.MessageTypeNetworkMap,
		})
		c.peersUpdateManager.CloseChannel(ctx, peerID)
	}

	if len(affectedPeerIDs) == 0 {
		log.WithContext(ctx).Tracef("no affected peers for peer delete in account %s, skipping", accountID)
		return nil
	}
	return c.BufferUpdateAffectedPeers(ctx, accountID, affectedPeerIDs, types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationDelete})
}

// GetNetworkMap returns Network map for a given peer (omits original peer from the Peers result)
func (c *Controller) GetNetworkMap(ctx context.Context, peerID string) (*types.NetworkMap, error) {
	account, err := c.repo.GetAccountByPeerID(ctx, peerID)
	if err != nil {
		return nil, err
	}

	peer := account.GetPeer(peerID)
	if peer == nil {
		return nil, status.Errorf(status.NotFound, "peer with ID %s not found", peerID)
	}

	groups := make(map[string][]string)
	for groupID, group := range account.Groups {
		groups[groupID] = group.Peers
	}

	extraSettings, err := c.settingsManager.GetExtraSettings(ctx, account.Id)
	if err != nil {
		return nil, err
	}

	validatedPeers, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, types.TwinGroups(maps.Values(account.Groups)), types.TwinPeers(maps.Values(account.Peers)), extraSettings)
	if err != nil {
		return nil, err
	}

	accountZones, err := c.repo.GetAccountZones(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account zones: %v", err)
		return nil, err
	}

	dnsDomain := c.GetDNSDomain(account.Settings)
	peersCustomZone := account.GetPeersCustomZone(ctx, dnsDomain)

	proxyNetworkMaps, err := c.proxyController.GetProxyNetworkMaps(ctx, account.Id, peerID, account.Peers)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get proxy network maps: %v", err)
		return nil, err
	}

	c.injectAllProxyPolicies(ctx, account)
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()
	networkMap := account.GetPeerNetworkMapFromComponents(ctx, peer.ID, peersCustomZone, accountZones, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)

	proxyNetworkMap, ok := proxyNetworkMaps[peer.ID]
	if ok {
		networkMap.Merge(proxyNetworkMap)
	}

	return networkMap, nil
}

func (c *Controller) DisconnectPeers(ctx context.Context, accountId string, peerIDs []string) {
	c.peersUpdateManager.CloseChannels(ctx, peerIDs)
}

func (c *Controller) TrackEphemeralPeer(ctx context.Context, peer *nbpeer.Peer) {
	c.EphemeralPeersManager.OnPeerDisconnected(ctx, peer)
}

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
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util"
)

type Controller struct {
	repo    Repository
	metrics *metrics
	// This should not be here, but we need to maintain it for the time being
	accountManagerMetrics *telemetry.AccountManagerMetrics
	peersUpdateManager    network_map.PeersUpdateManager
	settingsManager       settings.Manager
	EphemeralPeersManager ephemeral.Manager

	accountUpdateLocks               sync.Map
	sendAccountUpdateLocks           sync.Map
	updateAccountPeersBufferInterval atomic.Int64
	// dnsDomain is used for peer resolution. This is appended to the peer's name
	dnsDomain string
	config    *config.Config

	requestBuffer account.RequestBuffer

	proxyController port_forwarding.Controller

	integratedPeerValidator integrated_validator.IntegratedValidator
}

type bufferUpdate struct {
	mu     sync.Mutex
	next   *time.Timer
	update atomic.Bool
}

var _ network_map.Controller = (*Controller)(nil)

func NewController(ctx context.Context, store store.Store, metrics telemetry.AppMetrics, peersUpdateManager network_map.PeersUpdateManager, requestBuffer account.RequestBuffer, integratedPeerValidator integrated_validator.IntegratedValidator, settingsManager settings.Manager, dnsDomain string, proxyController port_forwarding.Controller, ephemeralPeersManager ephemeral.Manager, config *config.Config) *Controller {
	nMetrics, err := newMetrics(metrics.UpdateChannelMetrics())
	if err != nil {
		log.Fatal(fmt.Errorf("error creating metrics: %w", err))
	}

	return &Controller{
		repo:                    newRepository(store),
		metrics:                 nMetrics,
		accountManagerMetrics:   metrics.AccountManagerMetrics(),
		peersUpdateManager:      peersUpdateManager,
		requestBuffer:           requestBuffer,
		integratedPeerValidator: integratedPeerValidator,
		settingsManager:         settingsManager,
		dnsDomain:               dnsDomain,
		config:                  config,

		proxyController:       proxyController,
		EphemeralPeersManager: ephemeralPeersManager,
	}
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

func (c *Controller) CountStreams() int {
	return c.peersUpdateManager.CountStreams()
}

func (c *Controller) sendUpdateAccountPeers(ctx context.Context, accountID string) error {
	log.WithContext(ctx).Tracef("updating peers for account %s from %s", accountID, util.GetCallerName())
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

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, maps.Values(account.Groups), maps.Values(account.Peers), account.Settings.Extra)
	if err != nil {
		return fmt.Errorf("failed to get validate peers: %v", err)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	account.InjectProxyPolicies(ctx)
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

	// Phase 3.7i: build once, share read-only across goroutines.
	groupNamesByPeerID := grpc.BuildGroupNamesByPeerID(account.Groups)

	for _, peer := range account.Peers {
		if !c.peersUpdateManager.HasChannel(peer.ID) {
			log.WithContext(ctx).Tracef("peer %s doesn't have a channel, skipping network map update", peer.ID)
			continue
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

			remotePeerNetworkMap := account.GetPeerNetworkMapFromComponents(ctx, p.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, c.accountManagerMetrics, groupIDToUserIDs)

			c.metrics.CountCalcPeerNetworkMapDuration(time.Since(start))

			proxyNetworkMap, ok := proxyNetworkMaps[peer.ID]
			if ok {
				remotePeerNetworkMap.Merge(proxyNetworkMap)
			}

			peerGroups := account.GetPeerGroups(p.ID)
			start = time.Now()
			update := grpc.ToSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, p, nil, nil, remotePeerNetworkMap, dnsDomain, postureChecks, dnsCache, account.Settings, extraSetting, maps.Keys(peerGroups), dnsFwdPort, groupNamesByPeerID)
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

func (c *Controller) bufferSendUpdateAccountPeers(ctx context.Context, accountID string) error {
	log.WithContext(ctx).Tracef("buffer sending update peers for account %s from %s", accountID, util.GetCallerName())

	bufUpd, _ := c.sendAccountUpdateLocks.LoadOrStore(accountID, &bufferUpdate{})
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
		_ = c.sendUpdateAccountPeers(ctx, accountID)
		if !b.update.Load() {
			return
		}
		b.update.Store(false)
		if b.next == nil {
			b.next = time.AfterFunc(time.Duration(c.updateAccountPeersBufferInterval.Load()), func() {
				_ = c.sendUpdateAccountPeers(ctx, accountID)
			})
			return
		}
		b.next.Reset(time.Duration(c.updateAccountPeersBufferInterval.Load()))
	}()

	return nil
}

// UpdatePeers updates all peers that belong to an account.
// Should be called when changes have to be synced to peers.
func (c *Controller) UpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason) error {
	if c.accountManagerMetrics != nil {
		c.accountManagerMetrics.CountUpdateAccountPeersTriggered(string(reason.Resource), string(reason.Operation))
	}
	return c.sendUpdateAccountPeers(ctx, accountID)
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

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, maps.Values(account.Groups), maps.Values(account.Peers), account.Settings.Extra)
	if err != nil {
		return fmt.Errorf("failed to get validated peers: %v", err)
	}

	account.InjectProxyPolicies(ctx)
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

	remotePeerNetworkMap := account.GetPeerNetworkMapFromComponents(ctx, peerId, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, c.accountManagerMetrics, groupIDToUserIDs)

	proxyNetworkMap, ok := proxyNetworkMaps[peer.ID]
	if ok {
		remotePeerNetworkMap.Merge(proxyNetworkMap)
	}

	extraSettings, err := c.settingsManager.GetExtraSettings(ctx, peer.AccountID)
	if err != nil {
		return fmt.Errorf("failed to get extra settings: %v", err)
	}

	peerGroups := account.GetPeerGroups(peerId)
	dnsFwdPort := computeForwarderPort(maps.Values(account.Peers), network_map.DnsForwarderPortMinVersion)
	// Phase 3.7i: build group names map for remote-peer annotations.
	groupNamesByPeerID := grpc.BuildGroupNamesByPeerID(account.Groups)

	update := grpc.ToSyncResponse(ctx, nil, c.config.HttpConfig, c.config.DeviceAuthorizationFlow, peer, nil, nil, remotePeerNetworkMap, dnsDomain, postureChecks, dnsCache, account.Settings, extraSettings, maps.Keys(peerGroups), dnsFwdPort, groupNamesByPeerID)
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
		_ = c.sendUpdateAccountPeers(ctx, accountID)
		if !b.update.Load() {
			return
		}
		b.update.Store(false)
		if b.next == nil {
			b.next = time.AfterFunc(time.Duration(c.updateAccountPeersBufferInterval.Load()), func() {
				_ = c.sendUpdateAccountPeers(ctx, accountID)
			})
			return
		}
		b.next.Reset(time.Duration(c.updateAccountPeersBufferInterval.Load()))
	}()

	return nil
}

func (c *Controller) GetValidatedPeerWithMap(ctx context.Context, isRequiresApproval bool, accountID string, peer *nbpeer.Peer) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error) {
	if isRequiresApproval {
		network, err := c.repo.GetAccountNetwork(ctx, accountID)
		if err != nil {
			return nil, nil, nil, 0, err
		}

		emptyMap := &types.NetworkMap{
			Network: network.Copy(),
		}
		return peer, emptyMap, nil, 0, nil
	}

	account, err := c.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	account.InjectProxyPolicies(ctx)

	approvedPeersMap, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, maps.Values(account.Groups), maps.Values(account.Peers), account.Settings.Extra)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	startPosture := time.Now()
	postureChecks, err := c.getPeerPostureChecks(account, peer.ID)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	log.WithContext(ctx).Debugf("getPeerPostureChecks took %s", time.Since(startPosture))

	accountZones, err := c.repo.GetAccountZones(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account zones: %v", err)
		return nil, nil, nil, 0, err
	}

	dnsDomain := c.GetDNSDomain(account.Settings)
	peersCustomZone := account.GetPeersCustomZone(ctx, dnsDomain)

	proxyNetworkMaps, err := c.proxyController.GetProxyNetworkMaps(ctx, account.Id, peer.ID, account.Peers)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get proxy network maps: %v", err)
		return nil, nil, nil, 0, err
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()
	networkMap := account.GetPeerNetworkMapFromComponents(ctx, peer.ID, peersCustomZone, accountZones, approvedPeersMap, resourcePolicies, routers, c.accountManagerMetrics, groupIDToUserIDs)

	proxyNetworkMap, ok := proxyNetworkMaps[peer.ID]
	if ok {
		networkMap.Merge(proxyNetworkMap)
	}

	dnsFwdPort := computeForwarderPort(maps.Values(account.Peers), network_map.DnsForwarderPortMinVersion)

	return peer, networkMap, postureChecks, dnsFwdPort, nil
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
func (c *Controller) getPeerPostureChecks(account *types.Account, peerID string) ([]*posture.Checks, error) {
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

	return maps.Values(peerPostureChecks), nil
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
	if len(peers) == 0 {
		return int64(network_map.OldForwarderPort)
	}

	reqVer := semver.Canonical(requiredVersion)

	// Check if all peers have the required version or newer
	for _, peer := range peers {

		// Development version is always supported
		if peer.Meta.WtVersion == "development" {
			continue
		}
		peerVersion := semver.Canonical("v" + peer.Meta.WtVersion)
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
	isInGroup, err := isPeerInPolicySourceGroups(account, peerID, policy)
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

// isPeerInPolicySourceGroups checks if a peer is present in any of the policy rule source groups.
func isPeerInPolicySourceGroups(account *types.Account, peerID string, policy *types.Policy) (bool, error) {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
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

func (c *Controller) OnPeersUpdated(ctx context.Context, accountID string, peerIDs []string) error {
	err := c.bufferSendUpdateAccountPeers(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to buffer update account peers for peer update in account %s: %v", accountID, err)
	}

	return nil
}

func (c *Controller) OnPeersAdded(ctx context.Context, accountID string, peerIDs []string) error {
	log.WithContext(ctx).Debugf("OnPeersAdded call to add peers: %v", peerIDs)
	return c.bufferSendUpdateAccountPeers(ctx, accountID)
}

func (c *Controller) OnPeersDeleted(ctx context.Context, accountID string, peerIDs []string) error {
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
						ForwarderPort: dnsFwdPort,
					},
				},
			},
			MessageType: network_map.MessageTypeNetworkMap,
		})
		c.peersUpdateManager.CloseChannel(ctx, peerID)
	}

	return c.bufferSendUpdateAccountPeers(ctx, accountID)
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

	validatedPeers, err := c.integratedPeerValidator.GetValidatedPeers(ctx, account.Id, maps.Values(account.Groups), maps.Values(account.Peers), account.Settings.Extra)
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

	account.InjectProxyPolicies(ctx)
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

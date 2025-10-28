package server

import (
	"context"
	"slices"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	dnsForwarderPort = nbdns.ForwarderServerPort
	oldForwarderPort = nbdns.ForwarderClientPort
)

const dnsForwarderPortMinVersion = "v0.59.0"

// DNSConfigCache is a thread-safe cache for DNS configuration components
type DNSConfigCache struct {
	NameServerGroups sync.Map
}

// GetNameServerGroup retrieves a cached name server group
func (c *DNSConfigCache) GetNameServerGroup(key string) (*proto.NameServerGroup, bool) {
	if c == nil {
		return nil, false
	}
	if value, ok := c.NameServerGroups.Load(key); ok {
		return value.(*proto.NameServerGroup), true
	}
	return nil, false
}

// SetNameServerGroup stores a name server group in the cache
func (c *DNSConfigCache) SetNameServerGroup(key string, value *proto.NameServerGroup) {
	if c == nil {
		return
	}
	c.NameServerGroups.Store(key, value)
}

// GetDNSSettings validates a user role and returns the DNS settings for the provided account ID
func (am *DefaultAccountManager) GetDNSSettings(ctx context.Context, accountID string, userID string) (*types.DNSSettings, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountDNSSettings(ctx, store.LockingStrengthNone, accountID)
}

// SaveDNSSettings validates a user role and updates the account's DNS settings
func (am *DefaultAccountManager) SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *types.DNSSettings) error {
	if dnsSettingsToSave == nil {
		return status.Errorf(status.InvalidArgument, "the dns settings provided are nil")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var updateAccountPeers bool
	var eventsToStore []func()

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateDNSSettings(ctx, transaction, accountID, dnsSettingsToSave); err != nil {
			return err
		}

		oldSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return err
		}

		addedGroups := util.Difference(dnsSettingsToSave.DisabledManagementGroups, oldSettings.DisabledManagementGroups)
		removedGroups := util.Difference(oldSettings.DisabledManagementGroups, dnsSettingsToSave.DisabledManagementGroups)

		updateAccountPeers, err = areDNSSettingChangesAffectPeers(ctx, transaction, accountID, addedGroups, removedGroups)
		if err != nil {
			return err
		}

		events := am.prepareDNSSettingsEvents(ctx, transaction, accountID, userID, addedGroups, removedGroups)
		eventsToStore = append(eventsToStore, events...)

		if err = transaction.SaveDNSSettings(ctx, accountID, dnsSettingsToSave); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// prepareDNSSettingsEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareDNSSettingsEvents(ctx context.Context, transaction store.Store, accountID, userID string, addedGroups, removedGroups []string) []func() {
	var eventsToStore []func()

	modifiedGroups := slices.Concat(addedGroups, removedGroups)
	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, modifiedGroups)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get groups for dns settings events: %v", err)
		return nil
	}

	for _, groupID := range addedGroups {
		group, ok := groups[groupID]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding group: %s GroupAddedToDisabledManagementGroups activity", groupID)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{"group": group.Name, "group_id": group.ID}
			am.StoreEvent(ctx, userID, accountID, accountID, activity.GroupAddedToDisabledManagementGroups, meta)
		})

	}

	for _, groupID := range removedGroups {
		group, ok := groups[groupID]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding group: %s GroupRemovedFromDisabledManagementGroups activity", groupID)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{"group": group.Name, "group_id": group.ID}
			am.StoreEvent(ctx, userID, accountID, accountID, activity.GroupRemovedFromDisabledManagementGroups, meta)
		})
	}

	return eventsToStore
}

// areDNSSettingChangesAffectPeers checks if the DNS settings changes affect any peers.
func areDNSSettingChangesAffectPeers(ctx context.Context, transaction store.Store, accountID string, addedGroups, removedGroups []string) (bool, error) {
	hasPeers, err := anyGroupHasPeersOrResources(ctx, transaction, accountID, addedGroups)
	if err != nil {
		return false, err
	}

	if hasPeers {
		return true, nil
	}

	return anyGroupHasPeersOrResources(ctx, transaction, accountID, removedGroups)
}

// validateDNSSettings validates the DNS settings.
func validateDNSSettings(ctx context.Context, transaction store.Store, accountID string, settings *types.DNSSettings) error {
	if len(settings.DisabledManagementGroups) == 0 {
		return nil
	}

	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, settings.DisabledManagementGroups)
	if err != nil {
		return err
	}

	return validateGroups(settings.DisabledManagementGroups, groups)
}

// computeForwarderPort checks if all peers in the account have updated to a specific version or newer.
// If all peers have the required version, it returns the new well-known port (22054), otherwise returns 0.
func computeForwarderPort(peers []*nbpeer.Peer, requiredVersion string) int64 {
	if len(peers) == 0 {
		return int64(oldForwarderPort)
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
			return int64(oldForwarderPort)
		}

		// Compare versions
		if semver.Compare(peerVersion, reqVer) < 0 {
			return int64(oldForwarderPort)
		}
	}

	// All peers have the required version or newer
	return int64(dnsForwarderPort)
}

// toProtocolDNSConfig converts nbdns.Config to proto.DNSConfig using the cache
func toProtocolDNSConfig(update nbdns.Config, cache *DNSConfigCache, forwardPort int64) *proto.DNSConfig {
	protoUpdate := &proto.DNSConfig{
		ServiceEnable:    update.ServiceEnable,
		CustomZones:      make([]*proto.CustomZone, 0, len(update.CustomZones)),
		NameServerGroups: make([]*proto.NameServerGroup, 0, len(update.NameServerGroups)),
		ForwarderPort:    forwardPort,
	}

	for _, zone := range update.CustomZones {
		protoZone := convertToProtoCustomZone(zone)
		protoUpdate.CustomZones = append(protoUpdate.CustomZones, protoZone)
	}

	for _, nsGroup := range update.NameServerGroups {
		cacheKey := nsGroup.ID
		if cachedGroup, exists := cache.GetNameServerGroup(cacheKey); exists {
			protoUpdate.NameServerGroups = append(protoUpdate.NameServerGroups, cachedGroup)
		} else {
			protoGroup := convertToProtoNameServerGroup(nsGroup)
			cache.SetNameServerGroup(cacheKey, protoGroup)
			protoUpdate.NameServerGroups = append(protoUpdate.NameServerGroups, protoGroup)
		}
	}

	return protoUpdate
}

// Helper function to convert nbdns.CustomZone to proto.CustomZone
func convertToProtoCustomZone(zone nbdns.CustomZone) *proto.CustomZone {
	protoZone := &proto.CustomZone{
		Domain:  zone.Domain,
		Records: make([]*proto.SimpleRecord, 0, len(zone.Records)),
	}
	for _, record := range zone.Records {
		protoZone.Records = append(protoZone.Records, &proto.SimpleRecord{
			Name:  record.Name,
			Type:  int64(record.Type),
			Class: record.Class,
			TTL:   int64(record.TTL),
			RData: record.RData,
		})
	}
	return protoZone
}

// Helper function to convert nbdns.NameServerGroup to proto.NameServerGroup
func convertToProtoNameServerGroup(nsGroup *nbdns.NameServerGroup) *proto.NameServerGroup {
	protoGroup := &proto.NameServerGroup{
		Primary:              nsGroup.Primary,
		Domains:              nsGroup.Domains,
		SearchDomainsEnabled: nsGroup.SearchDomainsEnabled,
		NameServers:          make([]*proto.NameServer, 0, len(nsGroup.NameServers)),
	}
	for _, ns := range nsGroup.NameServers {
		protoGroup.NameServers = append(protoGroup.NameServers, &proto.NameServer{
			IP:     ns.IP.String(),
			Port:   int64(ns.Port),
			NSType: int64(ns.NSType),
		})
	}
	return protoGroup
}

package server

import (
	"context"
	"slices"
	"sync"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
)

// DNSConfigCache is a thread-safe cache for DNS configuration components
type DNSConfigCache struct {
	CustomZones      sync.Map
	NameServerGroups sync.Map
}

// GetCustomZone retrieves a cached custom zone
func (c *DNSConfigCache) GetCustomZone(key string) (*proto.CustomZone, bool) {
	if c == nil {
		return nil, false
	}
	if value, ok := c.CustomZones.Load(key); ok {
		return value.(*proto.CustomZone), true
	}
	return nil, false
}

// SetCustomZone stores a custom zone in the cache
func (c *DNSConfigCache) SetCustomZone(key string, value *proto.CustomZone) {
	if c == nil {
		return
	}
	c.CustomZones.Store(key, value)
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
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetAccountDNSSettings(ctx, store.LockingStrengthShare, accountID)
}

// SaveDNSSettings validates a user role and updates the account's DNS settings
func (am *DefaultAccountManager) SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *types.DNSSettings) error {
	if dnsSettingsToSave == nil {
		return status.Errorf(status.InvalidArgument, "the dns settings provided are nil")
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if !user.HasAdminPower() {
		return status.NewAdminPermissionError()
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

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveDNSSettings(ctx, store.LockingStrengthUpdate, accountID, dnsSettingsToSave)
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
	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, modifiedGroups)
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

	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, settings.DisabledManagementGroups)
	if err != nil {
		return err
	}

	return validateGroups(settings.DisabledManagementGroups, groups)
}

// toProtocolDNSConfig converts nbdns.Config to proto.DNSConfig using the cache
func toProtocolDNSConfig(update nbdns.Config, cache *DNSConfigCache) *proto.DNSConfig {
	protoUpdate := &proto.DNSConfig{
		ServiceEnable:    update.ServiceEnable,
		CustomZones:      make([]*proto.CustomZone, 0, len(update.CustomZones)),
		NameServerGroups: make([]*proto.NameServerGroup, 0, len(update.NameServerGroups)),
	}

	for _, zone := range update.CustomZones {
		cacheKey := zone.Domain
		if cachedZone, exists := cache.GetCustomZone(cacheKey); exists {
			protoUpdate.CustomZones = append(protoUpdate.CustomZones, cachedZone)
		} else {
			protoZone := convertToProtoCustomZone(zone)
			cache.SetCustomZone(cacheKey, protoZone)
			protoUpdate.CustomZones = append(protoUpdate.CustomZones, protoZone)
		}
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

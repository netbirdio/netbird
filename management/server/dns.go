package server

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
)

const defaultTTL = 300

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

type lookupMap map[string]struct{}

// DNSSettings defines dns settings at the account level
type DNSSettings struct {
	// DisabledManagementGroups groups whose DNS management is disabled
	DisabledManagementGroups []string `gorm:"serializer:json"`
}

// Copy returns a copy of the DNS settings
func (d DNSSettings) Copy() DNSSettings {
	settings := DNSSettings{
		DisabledManagementGroups: make([]string, len(d.DisabledManagementGroups)),
	}
	copy(settings.DisabledManagementGroups, d.DisabledManagementGroups)
	return settings
}

// GetDNSSettings validates a user role and returns the DNS settings for the provided account ID
func (am *DefaultAccountManager) GetDNSSettings(ctx context.Context, accountID string, userID string) (*DNSSettings, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetAccountDNSSettings(ctx, LockingStrengthShare, accountID)
}

// SaveDNSSettings validates a user role and updates the account's DNS settings
func (am *DefaultAccountManager) SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *DNSSettings) error {
	if dnsSettingsToSave == nil {
		return status.Errorf(status.InvalidArgument, "the dns settings provided are nil")
	}

	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
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

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = validateDNSSettings(ctx, transaction, accountID, dnsSettingsToSave); err != nil {
			return err
		}

		oldSettings, err := transaction.GetAccountDNSSettings(ctx, LockingStrengthUpdate, accountID)
		if err != nil {
			return err
		}

		addedGroups := difference(dnsSettingsToSave.DisabledManagementGroups, oldSettings.DisabledManagementGroups)
		removedGroups := difference(oldSettings.DisabledManagementGroups, dnsSettingsToSave.DisabledManagementGroups)

		updateAccountPeers, err = areDNSSettingChangesAffectPeers(ctx, transaction, accountID, addedGroups, removedGroups)
		if err != nil {
			return err
		}

		events := am.prepareDNSSettingsEvents(ctx, transaction, accountID, userID, addedGroups, removedGroups)
		eventsToStore = append(eventsToStore, events...)

		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveDNSSettings(ctx, LockingStrengthUpdate, accountID, dnsSettingsToSave)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// prepareDNSSettingsEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareDNSSettingsEvents(ctx context.Context, transaction Store, accountID, userID string, addedGroups, removedGroups []string) []func() {
	var eventsToStore []func()

	modifiedGroups := slices.Concat(addedGroups, removedGroups)
	groups, err := transaction.GetGroupsByIDs(ctx, LockingStrengthShare, accountID, modifiedGroups)
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
func areDNSSettingChangesAffectPeers(ctx context.Context, transaction Store, accountID string, addedGroups, removedGroups []string) (bool, error) {
	hasPeers, err := anyGroupHasPeers(ctx, transaction, accountID, addedGroups)
	if err != nil {
		return false, err
	}

	if hasPeers {
		return true, nil
	}

	return anyGroupHasPeers(ctx, transaction, accountID, removedGroups)
}

// validateDNSSettings validates the DNS settings.
func validateDNSSettings(ctx context.Context, transaction Store, accountID string, settings *DNSSettings) error {
	if len(settings.DisabledManagementGroups) == 0 {
		return nil
	}

	groups, err := transaction.GetGroupsByIDs(ctx, LockingStrengthShare, accountID, settings.DisabledManagementGroups)
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

func getPeerNSGroups(account *Account, peerID string) []*nbdns.NameServerGroup {
	groupList := account.getPeerGroups(peerID)

	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range account.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := groupList[gID]
			if found {
				if !peerIsNameserver(account.GetPeer(peerID), nsGroup) {
					peerNSGroups = append(peerNSGroups, nsGroup.Copy())
					break
				}
			}
		}
	}

	return peerNSGroups
}

// peerIsNameserver returns true if the peer is a nameserver for a nsGroup
func peerIsNameserver(peer *nbpeer.Peer, nsGroup *nbdns.NameServerGroup) bool {
	for _, ns := range nsGroup.NameServers {
		if peer.IP.Equal(ns.IP.AsSlice()) {
			return true
		}
	}
	return false
}

func addPeerLabelsToAccount(ctx context.Context, account *Account, peerLabels lookupMap) {
	for _, peer := range account.Peers {
		label, err := getPeerHostLabel(peer.Name, peerLabels)
		if err != nil {
			log.WithContext(ctx).Errorf("got an error while generating a peer host label. Peer name %s, error: %v. Trying with the peer's meta hostname", peer.Name, err)
			label, err = getPeerHostLabel(peer.Meta.Hostname, peerLabels)
			if err != nil {
				log.WithContext(ctx).Errorf("got another error while generating a peer host label with hostname. Peer hostname %s, error: %v. Skipping", peer.Meta.Hostname, err)
				continue
			}
		}
		peer.DNSLabel = label
		peerLabels[label] = struct{}{}
	}
}

func getPeerHostLabel(name string, peerLabels lookupMap) (string, error) {
	label, err := nbdns.GetParsedDomainLabel(name)
	if err != nil {
		return "", err
	}

	uniqueLabel := getUniqueHostLabel(label, peerLabels)
	if uniqueLabel == "" {
		return "", fmt.Errorf("couldn't find a unique valid label for %s, parsed label %s", name, label)
	}
	return uniqueLabel, nil
}

// getUniqueHostLabel look for a unique host label, and if doesn't find add a suffix up to 999
func getUniqueHostLabel(name string, peerLabels lookupMap) string {
	_, found := peerLabels[name]
	if !found {
		return name
	}
	for i := 1; i < 1000; i++ {
		nameWithSuffix := name + "-" + strconv.Itoa(i)
		_, found = peerLabels[nameWithSuffix]
		if !found {
			return nameWithSuffix
		}
	}
	return ""
}

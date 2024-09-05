package server

import (
	"context"
	"fmt"
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
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !(user.HasAdminPower() || user.IsServiceUser) {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power are allowed to view DNS settings")
	}
	dnsSettings := account.DNSSettings.Copy()
	return &dnsSettings, nil
}

// SaveDNSSettings validates a user role and updates the account's DNS settings
func (am *DefaultAccountManager) SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *DNSSettings) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "only users with admin power are allowed to update DNS settings")
	}

	if dnsSettingsToSave == nil {
		return status.Errorf(status.InvalidArgument, "the dns settings provided are nil")
	}

	if len(dnsSettingsToSave.DisabledManagementGroups) != 0 {
		err = validateGroups(dnsSettingsToSave.DisabledManagementGroups, account.Groups)
		if err != nil {
			return err
		}
	}

	oldSettings := account.DNSSettings.Copy()
	account.DNSSettings = dnsSettingsToSave.Copy()

	addedGroups := difference(dnsSettingsToSave.DisabledManagementGroups, oldSettings.DisabledManagementGroups)
	removedGroups := difference(oldSettings.DisabledManagementGroups, dnsSettingsToSave.DisabledManagementGroups)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	for _, id := range addedGroups {
		group := account.GetGroup(id)
		meta := map[string]any{"group": group.Name, "group_id": group.ID}
		am.StoreEvent(ctx, userID, accountID, accountID, activity.GroupAddedToDisabledManagementGroups, meta)
	}

	for _, id := range removedGroups {
		group := account.GetGroup(id)
		meta := map[string]any{"group": group.Name, "group_id": group.ID}
		am.StoreEvent(ctx, userID, accountID, accountID, activity.GroupRemovedFromDisabledManagementGroups, meta)
	}

	if anyGroupHasPeers(account, addedGroups) || anyGroupHasPeers(account, removedGroups) {
		am.updateAccountPeers(ctx, account)
	}

	return nil
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

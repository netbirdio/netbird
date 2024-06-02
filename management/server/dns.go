package server

import (
	"fmt"
	"strconv"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
)

const defaultTTL = 300

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
func (am *DefaultAccountManager) GetDNSSettings(accountID string, userID string) (*DNSSettings, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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
func (am *DefaultAccountManager) SaveDNSSettings(accountID string, userID string, dnsSettingsToSave *DNSSettings) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	addedGroups := difference(dnsSettingsToSave.DisabledManagementGroups, oldSettings.DisabledManagementGroups)
	for _, id := range addedGroups {
		group := account.GetGroup(id)
		meta := map[string]any{"group": group.Name, "group_id": group.ID}
		am.StoreEvent(userID, accountID, accountID, activity.GroupAddedToDisabledManagementGroups, meta)
	}

	removedGroups := difference(oldSettings.DisabledManagementGroups, dnsSettingsToSave.DisabledManagementGroups)
	for _, id := range removedGroups {
		group := account.GetGroup(id)
		meta := map[string]any{"group": group.Name, "group_id": group.ID}
		am.StoreEvent(userID, accountID, accountID, activity.GroupRemovedFromDisabledManagementGroups, meta)
	}

	am.updateAccountPeers(account)

	return nil
}

func toProtocolDNSConfig(update nbdns.Config) *proto.DNSConfig {
	protoUpdate := &proto.DNSConfig{ServiceEnable: update.ServiceEnable}

	for _, zone := range update.CustomZones {
		protoZone := &proto.CustomZone{Domain: zone.Domain}
		for _, record := range zone.Records {
			protoZone.Records = append(protoZone.Records, &proto.SimpleRecord{
				Name:  record.Name,
				Type:  int64(record.Type),
				Class: record.Class,
				TTL:   int64(record.TTL),
				RData: record.RData,
			})
		}
		protoUpdate.CustomZones = append(protoUpdate.CustomZones, protoZone)
	}

	for _, nsGroup := range update.NameServerGroups {
		protoGroup := &proto.NameServerGroup{
			Primary:              nsGroup.Primary,
			Domains:              nsGroup.Domains,
			SearchDomainsEnabled: nsGroup.SearchDomainsEnabled,
		}
		for _, ns := range nsGroup.NameServers {
			protoNS := &proto.NameServer{
				IP:     ns.IP.String(),
				Port:   int64(ns.Port),
				NSType: int64(ns.NSType),
			}
			protoGroup.NameServers = append(protoGroup.NameServers, protoNS)
		}
		protoUpdate.NameServerGroups = append(protoUpdate.NameServerGroups, protoGroup)
	}

	return protoUpdate
}

func getPeersCustomZone(account *Account, dnsDomain string, enableIPv6 bool) nbdns.CustomZone {
	if dnsDomain == "" {
		log.Errorf("no dns domain is set, returning empty zone")
		return nbdns.CustomZone{}
	}

	customZone := nbdns.CustomZone{
		Domain: dns.Fqdn(dnsDomain),
	}

	for _, peer := range account.Peers {
		if peer.DNSLabel == "" {
			log.Errorf("found a peer with empty dns label. It was probably caused by a invalid character in its name. Peer Name: %s", peer.Name)
			continue
		}

		customZone.Records = append(customZone.Records, nbdns.SimpleRecord{
			Name:  dns.Fqdn(peer.DNSLabel + "." + dnsDomain),
			Type:  int(dns.TypeA),
			Class: nbdns.DefaultClass,
			TTL:   defaultTTL,
			RData: peer.IP.String(),
		})

		if peer.IP6 != nil && enableIPv6 {
			customZone.Records = append(customZone.Records, nbdns.SimpleRecord{
				Name:  dns.Fqdn(peer.DNSLabel + "." + dnsDomain),
				Type:  int(dns.TypeAAAA),
				Class: nbdns.DefaultClass,
				TTL:   defaultTTL,
				RData: peer.IP6.String(),
			})
		}
	}

	return customZone
}

func getPeerNSGroups(account *Account, peerID string) []*nbdns.NameServerGroup {
	groupList := account.getPeerGroups(peerID)
	peer := account.GetPeer(peerID)

	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range account.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := groupList[gID]
			if found {
				if !peerIsNameserver(peer, nsGroup) {
					filteredNsGroup := nsGroup.Copy()
					var newNameserverList []nbdns.NameServer
					for _, nameserver := range filteredNsGroup.NameServers {
						if nameserver.IP.Is4() || peer.IP6 != nil {
							newNameserverList = append(newNameserverList, nameserver)
						}
					}
					if len(newNameserverList) > 0 {
						filteredNsGroup.NameServers = newNameserverList
						peerNSGroups = append(peerNSGroups, filteredNsGroup)
					}
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

func addPeerLabelsToAccount(account *Account, peerLabels lookupMap) {
	for _, peer := range account.Peers {
		label, err := getPeerHostLabel(peer.Name, peerLabels)
		if err != nil {
			log.Errorf("got an error while generating a peer host label. Peer name %s, error: %v. Trying with the peer's meta hostname", peer.Name, err)
			label, err = getPeerHostLabel(peer.Meta.Hostname, peerLabels)
			if err != nil {
				log.Errorf("got another error while generating a peer host label with hostname. Peer hostname %s, error: %v. Skipping", peer.Meta.Hostname, err)
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

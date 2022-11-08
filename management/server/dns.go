package server

import (
	"fmt"
	"github.com/miekg/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/proto"
	log "github.com/sirupsen/logrus"
	"strconv"
)

type lookupMap map[string]struct{}

const defaultTTL = 300

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
			Primary: nsGroup.Primary,
			Domains: nsGroup.Domains,
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

func getPeersCustomZone(account *Account, dnsDomain string) nbdns.CustomZone {
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
	}

	return customZone
}

func getPeerNSGroups(account *Account, peerID string) []*nbdns.NameServerGroup {
	groupList := make(lookupMap)
	for groupID, group := range account.Groups {
		for _, id := range group.Peers {
			if id == peerID {
				groupList[groupID] = struct{}{}
				break
			}
		}
	}

	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range account.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := groupList[gID]
			if found {
				peerNSGroups = append(peerNSGroups, nsGroup.Copy())
				break
			}
		}
	}

	return peerNSGroups
}

func addPeerLabelsToAccount(account *Account, peerLabels lookupMap) {
	for _, peer := range account.Peers {
		label, err := getPeerHostLabel(peer.Name, peerLabels)
		if err != nil {
			log.Errorf("got an error while generating a peer host label. Peer name %s, error: %v. Trying with the peer's meta hostname", peer.Name, err)
			label, err = getPeerHostLabel(peer.Meta.Hostname, peerLabels)
			if err != nil {
				log.Errorf("got another error while generating a peer host label with hostname. Peer hostname %s, error: %v. Skiping", peer.Meta.Hostname, err)
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

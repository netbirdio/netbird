package types

import (
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// This file holds the twin→real converters that survive the twin-NetworkMap
// refactor: only the DNS materialization. NetworkMap.DNSConfig stays a real
// nbdns.Config (the client DNS type), so Calculate converts the twin DNS
// components to nbdns at the output boundary. Peers/Routes/Network flow as
// twins all the way through and need no conversion.

func toRealNSGroup(n *nmdata.NameServerGroup) *nbdns.NameServerGroup {
	if n == nil {
		return nil
	}
	nameServers := make([]nbdns.NameServer, 0, len(n.NameServers))
	for _, ns := range n.NameServers {
		nameServers = append(nameServers, nbdns.NameServer{
			IP:     ns.IP,
			NSType: nbdns.NameServerType(ns.NSType),
			Port:   ns.Port,
		})
	}
	return &nbdns.NameServerGroup{
		ID:                   n.ID,
		Name:                 n.Name,
		Description:          n.Description,
		NameServers:          nameServers,
		Groups:               n.Groups,
		Primary:              n.Primary,
		Domains:              n.Domains,
		Enabled:              n.Enabled,
		SearchDomainsEnabled: n.SearchDomainsEnabled,
	}
}

func toRealRecords(recs []nmdata.SimpleRecord) []nbdns.SimpleRecord {
	if recs == nil {
		return nil
	}
	out := make([]nbdns.SimpleRecord, len(recs))
	for i, r := range recs {
		out[i] = nbdns.SimpleRecord{
			Name:  r.Name,
			Type:  r.Type,
			Class: r.Class,
			TTL:   r.TTL,
			RData: r.RData,
		}
	}
	return out
}

func toRealZones(zones []nmdata.CustomZone) []nbdns.CustomZone {
	if zones == nil {
		return nil
	}
	out := make([]nbdns.CustomZone, len(zones))
	for i, z := range zones {
		out[i] = nbdns.CustomZone{
			Domain:               z.Domain,
			Records:              toRealRecords(z.Records),
			SearchDomainDisabled: z.SearchDomainDisabled,
			NonAuthoritative:     z.NonAuthoritative,
		}
	}
	return out
}

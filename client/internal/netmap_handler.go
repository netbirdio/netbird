package internal

import (
	"fmt"
	"net"
	"net/netip"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
	mgmProto "github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/route"

	log "github.com/sirupsen/logrus"
)

type networkMapHandler struct {
	DNSServer    dns.Server
	RouteManager routemanager.Manager
	Firewall     firewall.Manager

	updateSerial uint64
	dnsRules     []firewall.Rule
}

func (h *networkMapHandler) update(serial uint64, networkMap *mgmProto.NetworkMap) error {
	if serial < h.updateSerial {
		return fmt.Errorf("not applying dns update, error: "+
			"network update is %d behind the last applied update", h.updateSerial-serial)
	}

	hasDNSRoute, routes := toRoutes(networkMap.GetRoutes())
	DNSConfig := toDNSConfig(networkMap.GetDNSConfig())

	if err := h.DNSServer.UpdateDNSServer(DNSConfig, hasDNSRoute); err != nil {
		log.Errorf("failed to update dns server, err: %v", err)
		return err
	}
	h.updateSerial = serial

	// todo: consider to eliminate the serial management from the client.go
	_, err := h.RouteManager.UpdateRoutes(serial, routes)
	if err != nil {
		log.Errorf("failed to update routes, err: %v", err)
		return err
	}

	if hasDNSRoute {
		if err := h.allowDNSFirewall(); err != nil {
			return err
		}
	} else {
		if err := h.dropDNSFirewall(); err != nil {
			return err
		}
	}
	return nil
}

func (h *networkMapHandler) allowDNSFirewall() error {
	dport := &firewall.Port{
		IsRange: false,
		Values:  []int{h.DNSServer.DnsPort()},
	}
	dnsRules, err := h.Firewall.AddPeerFiltering(net.ParseIP("0.0.0.0"), firewall.ProtocolUDP, nil, dport, firewall.RuleDirectionIN, firewall.ActionAccept, "", "")
	if err != nil {
		log.Errorf("failed to add allow DNS router rules, err: %v", err)
		return err
	}
	h.dnsRules = dnsRules
	return nil
}

func (h *networkMapHandler) dropDNSFirewall() error {
	if len(h.dnsRules) == 0 {
		return nil
	}

	for _, rule := range h.dnsRules {
		if err := h.Firewall.DeletePeerRule(rule); err != nil {
			log.Errorf("failed to delete DNS router rules, err: %v", err)
			return err
		}
	}

	h.dnsRules = nil
	return nil
}

func toDNSConfig(protoDNSConfig *mgmProto.DNSConfig) nbdns.Config {
	if protoDNSConfig == nil {
		protoDNSConfig = &mgmProto.DNSConfig{}
	}

	dnsUpdate := nbdns.Config{
		ServiceEnable:    protoDNSConfig.GetServiceEnable(),
		CustomZones:      make([]nbdns.CustomZone, 0),
		NameServerGroups: make([]*nbdns.NameServerGroup, 0),
	}

	for _, zone := range protoDNSConfig.GetCustomZones() {
		dnsZone := nbdns.CustomZone{
			Domain: zone.GetDomain(),
		}
		for _, record := range zone.Records {
			dnsRecord := nbdns.SimpleRecord{
				Name:  record.GetName(),
				Type:  int(record.GetType()),
				Class: record.GetClass(),
				TTL:   int(record.GetTTL()),
				RData: record.GetRData(),
			}
			dnsZone.Records = append(dnsZone.Records, dnsRecord)
		}
		dnsUpdate.CustomZones = append(dnsUpdate.CustomZones, dnsZone)
	}

	for _, nsGroup := range protoDNSConfig.GetNameServerGroups() {
		dnsNSGroup := &nbdns.NameServerGroup{
			Primary:              nsGroup.GetPrimary(),
			Domains:              nsGroup.GetDomains(),
			SearchDomainsEnabled: nsGroup.GetSearchDomainsEnabled(),
		}
		for _, ns := range nsGroup.GetNameServers() {
			dnsNS := nbdns.NameServer{
				IP:     netip.MustParseAddr(ns.GetIP()),
				NSType: nbdns.NameServerType(ns.GetNSType()),
				Port:   int(ns.GetPort()),
			}
			dnsNSGroup.NameServers = append(dnsNSGroup.NameServers, dnsNS)
		}
		dnsUpdate.NameServerGroups = append(dnsUpdate.NameServerGroups, dnsNSGroup)
	}
	return dnsUpdate
}

func toRoutes(protoRoutes []*mgmProto.Route) (bool, []*route.Route) {
	if protoRoutes == nil {
		protoRoutes = []*mgmProto.Route{}
	}
	var hasDNSRoute bool
	routes := make([]*route.Route, 0)
	for _, protoRoute := range protoRoutes {
		var prefix netip.Prefix
		if len(protoRoute.Domains) == 0 {
			var err error
			if prefix, err = netip.ParsePrefix(protoRoute.Network); err != nil {
				log.Errorf("Failed to parse prefix %s: %v", protoRoute.Network, err)
				continue
			}
		}

		hasDNSRoute = true

		convertedRoute := &route.Route{
			ID:          route.ID(protoRoute.ID),
			Network:     prefix,
			Domains:     domain.FromPunycodeList(protoRoute.Domains),
			NetID:       route.NetID(protoRoute.NetID),
			NetworkType: route.NetworkType(protoRoute.NetworkType),
			Peer:        protoRoute.Peer,
			Metric:      int(protoRoute.Metric),
			Masquerade:  protoRoute.Masquerade,
			KeepRoute:   protoRoute.KeepRoute,
		}
		routes = append(routes, convertedRoute)
	}
	return hasDNSRoute, routes
}

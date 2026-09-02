package types

import (
	"github.com/miekg/dns"

	nbdns "github.com/netbirdio/netbird/dns"
	proxydomain "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// toNetworkMapData builds the slim twin store from the account once per
// account. The per-peer components calculation then runs on the twin.
func (a *Account) toNetworkMapData(
	accountZones []*zones.Zone,
	validatedPeersMap map[string]struct{},
	resourcePolicies map[string][]*Policy,
	routers map[string]map[string]*routerTypes.NetworkRouter,
	groupIDToUserIDs map[string][]string,
) *networkmap.NetworkMapData {
	nmd := &networkmap.NetworkMapData{
		Peers:                     make(map[string]*nmdata.Peer, len(a.Peers)),
		Groups:                    make(map[string]*nmdata.Group, len(a.Groups)),
		Policies:                  make([]*nmdata.Policy, 0, len(a.Policies)),
		Routes:                    make([]*nmdata.Route, 0, len(a.Routes)),
		NameServerGroups:          make([]*nmdata.NameServerGroup, 0, len(a.NameServerGroups)),
		NetworkResources:          make([]*nmdata.NetworkResource, 0, len(a.NetworkResources)),
		PostureChecks:             make(map[string]*nmdata.PostureChecks, len(a.PostureChecks)),
		ResourcePolicies:          make(map[string][]*nmdata.Policy, len(resourcePolicies)),
		Routers:                   make(map[string]map[string]*nmdata.NetworkRouter, len(routers)),
		ValidatedPeers:            validatedPeersMap,
		GroupIDToUserIDs:          groupIDToUserIDs,
		PostureValidation:         a.PostureValidation,
		AllowedUserIDs:            a.getAllowedUserIDs(),
		NetworkXIDToPublicID:      make(map[string]string, len(a.Networks)),
		PostureCheckXIDToPublicID: make(map[string]string, len(a.PostureChecks)),
	}

	if a.Network != nil {
		nmd.Network = TwinNetwork(a.Network)
	}
	nmd.DNSSettings = &nmdata.DNSSettings{DisabledManagementGroups: a.DNSSettings.DisabledManagementGroups}
	nmd.AccountSettings = TwinAccountSettings(a.Settings)

	for id, p := range a.Peers {
		nmd.Peers[id] = twinPeer(p)
	}
	for id, g := range a.Groups {
		nmd.Groups[id] = twinGroup(g)
	}

	policyCache := make(map[string]*nmdata.Policy, len(a.Policies))
	twinPol := func(p *Policy) *nmdata.Policy {
		if p == nil {
			return nil
		}
		if tp, ok := policyCache[p.ID]; ok {
			return tp
		}
		tp := twinPolicy(p)
		policyCache[p.ID] = tp
		return tp
	}
	for _, p := range a.Policies {
		nmd.Policies = append(nmd.Policies, twinPol(p))
	}
	for resID, pols := range resourcePolicies {
		twinPols := make([]*nmdata.Policy, 0, len(pols))
		for _, p := range pols {
			twinPols = append(twinPols, twinPol(p))
		}
		nmd.ResourcePolicies[resID] = twinPols
	}

	for _, r := range a.Routes {
		if r == nil {
			continue
		}
		nmd.Routes = append(nmd.Routes, twinRoute(r))
	}
	for _, nsg := range a.NameServerGroups {
		nmd.NameServerGroups = append(nmd.NameServerGroups, twinNSG(nsg))
	}
	for _, res := range a.NetworkResources {
		nmd.NetworkResources = append(nmd.NetworkResources, TwinNetworkResource(res))
	}
	for _, pc := range a.PostureChecks {
		if pc != nil {
			nmd.PostureChecks[pc.ID] = TwinPostureChecks(pc)
			nmd.PostureCheckXIDToPublicID[pc.ID] = pc.PublicID
		}
	}
	for _, n := range a.Networks {
		if n != nil {
			nmd.NetworkXIDToPublicID[n.ID] = n.PublicID
		}
	}
	for networkID, inner := range routers {
		twinInner := make(map[string]*nmdata.NetworkRouter, len(inner))
		for peerID, router := range inner {
			twinInner[peerID] = twinRouter(router)
		}
		nmd.Routers[networkID] = twinInner
	}

	nmd.ProxyTargetedDomainResourceIDs = a.proxyTargetedDomainResourceIDs()
	nmd.AppliedZoneCandidates = buildAppliedZoneCandidates(accountZones)
	nmd.PrivateServiceCandidates = a.buildPrivateServiceCandidates()
	nmd.Services = TwinServices(a.Services)
	nmd.Domains = twinProxyDomains(a.Domains)

	return nmd
}

// TwinServices converts reverse-proxy services to their slim nmdata twins.
// Exported for the network-map controller, which hands the store-backed twin
// the same services the account carries.
func TwinServices(services []*service.Service) []*nmdata.Service {
	if len(services) == 0 {
		return nil
	}
	out := make([]*nmdata.Service, 0, len(services))
	for _, svc := range services {
		if svc == nil {
			continue
		}
		targets := make([]*nmdata.ServiceTarget, 0, len(svc.Targets))
		for _, t := range svc.Targets {
			if t == nil {
				continue
			}
			path := ""
			if t.Path != nil {
				path = *t.Path
			}
			targets = append(targets, &nmdata.ServiceTarget{
				Enabled:    t.Enabled,
				Path:       path,
				Port:       t.Port,
				Protocol:   t.Protocol,
				TargetID:   t.TargetId,
				TargetType: string(t.TargetType),
			})
		}
		out = append(out, &nmdata.Service{
			ID:           svc.ID,
			Enabled:      svc.Enabled,
			Private:      svc.Private,
			Mode:         svc.Mode,
			Domain:       svc.Domain,
			ProxyCluster: svc.ProxyCluster,
			AccessGroups: svc.AccessGroups,
			Targets:      targets,
		})
	}
	return out
}

func twinPeer(p *nbpeer.Peer) *nmdata.Peer {
	if p == nil {
		return nil
	}
	networkAddresses := make([]nmdata.NetworkAddress, 0, len(p.Meta.NetworkAddresses))
	for _, na := range p.Meta.NetworkAddresses {
		networkAddresses = append(networkAddresses, nmdata.NetworkAddress{NetIP: na.NetIP})
	}
	files := make([]nmdata.File, 0, len(p.Meta.Files))
	for _, f := range p.Meta.Files {
		files = append(files, nmdata.File{Path: f.Path, ProcessIsRunning: f.ProcessIsRunning})
	}
	return &nmdata.Peer{
		ID:                     p.ID,
		Key:                    p.Key,
		SSHKey:                 p.SSHKey,
		DNSLabel:               p.DNSLabel,
		UserID:                 p.UserID,
		SSHEnabled:             p.SSHEnabled,
		LoginExpirationEnabled: p.LoginExpirationEnabled,
		LastLogin:              p.LastLogin,
		IP:                     p.IP,
		IPv6:                   p.IPv6,
		RequiresApproval:       p.Status != nil && p.Status.RequiresApproval,
		Connected:              p.Status != nil && p.Status.Connected,
		ExtraDNSLabels:         p.ExtraDNSLabels,
		ProxyMeta:              nmdata.ProxyMeta{Embedded: p.ProxyMeta.Embedded, Cluster: p.ProxyMeta.Cluster},
		Meta: nmdata.PeerSystemMeta{
			WtVersion:          p.Meta.WtVersion,
			GoOS:               p.Meta.GoOS,
			OSVersion:          p.Meta.OSVersion,
			KernelVersion:      p.Meta.KernelVersion,
			NetworkAddresses:   networkAddresses,
			Files:              files,
			Capabilities:       p.Meta.Capabilities,
			SyncMessageVersion: p.Meta.SyncMessageVersion,
			Flags: nmdata.Flags{
				ServerSSHAllowed: p.Meta.Flags.ServerSSHAllowed,
				DisableIPv6:      p.Meta.Flags.DisableIPv6,
			},
		},
		Location: nmdata.PeerLocation{
			CountryCode:  p.Location.CountryCode,
			CityName:     p.Location.CityName,
			ConnectionIP: p.Location.ConnectionIP,
		},
	}
}

// TwinPeer converts a real peer to its slim nmdata twin. Exported for the
// port-forwarding integration, which builds proxy NetworkMaps holding twins.
func TwinPeer(p *nbpeer.Peer) *nmdata.Peer {
	return twinPeer(p)
}

// TwinPeers converts real peers to their slim nmdata twins.
func TwinPeers(peers []*nbpeer.Peer) []*nmdata.Peer {
	out := make([]*nmdata.Peer, len(peers))
	for i, p := range peers {
		out[i] = twinPeer(p)
	}
	return out
}

// TwinGroups converts real groups to their slim nmdata twins.
func TwinGroups(groups []*Group) []*nmdata.Group {
	out := make([]*nmdata.Group, len(groups))
	for i, g := range groups {
		out[i] = twinGroup(g)
	}
	return out
}

func twinGroup(g *Group) *nmdata.Group {
	if g == nil {
		return nil
	}
	return &nmdata.Group{
		ID:       g.ID,
		Name:     g.Name,
		PublicID: g.PublicID,
		Peers:    g.Peers,
	}
}

func twinPolicy(p *Policy) *nmdata.Policy {
	if p == nil {
		return nil
	}
	rules := make([]*nmdata.PolicyRule, 0, len(p.Rules))
	for _, r := range p.Rules {
		rules = append(rules, twinRule(r))
	}
	return &nmdata.Policy{
		ID:                  p.ID,
		PublicID:            p.PublicID,
		Enabled:             p.Enabled,
		SourcePostureChecks: p.SourcePostureChecks,
		Rules:               rules,
	}
}

func twinRule(r *PolicyRule) *nmdata.PolicyRule {
	if r == nil {
		return nil
	}
	var portRanges []nmdata.RulePortRange
	if r.PortRanges != nil {
		portRanges = make([]nmdata.RulePortRange, len(r.PortRanges))
		for i, pr := range r.PortRanges {
			portRanges[i] = nmdata.RulePortRange{Start: pr.Start, End: pr.End}
		}
	}
	return &nmdata.PolicyRule{
		ID:                  r.ID,
		PolicyID:            r.PolicyID,
		Enabled:             r.Enabled,
		Action:              string(r.Action),
		Protocol:            string(r.Protocol),
		Bidirectional:       r.Bidirectional,
		Sources:             r.Sources,
		Destinations:        r.Destinations,
		SourceResource:      nmdata.Resource{ID: r.SourceResource.ID, Type: string(r.SourceResource.Type)},
		DestinationResource: nmdata.Resource{ID: r.DestinationResource.ID, Type: string(r.DestinationResource.Type)},
		Ports:               r.Ports,
		PortRanges:          portRanges,
		AuthorizedGroups:    r.AuthorizedGroups,
		AuthorizedUser:      r.AuthorizedUser,
	}
}

func twinRoute(r *nbroute.Route) *nmdata.Route {
	return &nmdata.Route{
		ID:                  string(r.ID),
		AccountID:           r.AccountID,
		PublicID:            r.PublicID,
		Network:             r.Network,
		Domains:             r.Domains,
		KeepRoute:           r.KeepRoute,
		NetID:               string(r.NetID),
		Description:         r.Description,
		Peer:                r.Peer,
		PeerID:              r.PeerID,
		PeerGroups:          r.PeerGroups,
		NetworkType:         int(r.NetworkType),
		Masquerade:          r.Masquerade,
		Metric:              r.Metric,
		Enabled:             r.Enabled,
		Groups:              r.Groups,
		AccessControlGroups: r.AccessControlGroups,
		SkipAutoApply:       r.SkipAutoApply,
	}
}

// TwinRoute converts a real *route.Route to its slim nmdata twin. Exported for
// tests that assert against twin routes returned in a NetworkMap.
func TwinRoute(r *nbroute.Route) *nmdata.Route {
	return twinRoute(r)
}

func TwinNetworkResource(r *resourceTypes.NetworkResource) *nmdata.NetworkResource {
	if r == nil {
		return nil
	}
	return &nmdata.NetworkResource{
		ID:          r.ID,
		NetworkID:   r.NetworkID,
		AccountID:   r.AccountID,
		PublicID:    r.PublicID,
		Name:        r.Name,
		Description: r.Description,
		Type:        string(r.Type),
		Address:     r.Address,
		Domain:      r.Domain,
		Prefix:      r.Prefix,
		Enabled:     r.Enabled,
	}
}

func twinRouter(r *routerTypes.NetworkRouter) *nmdata.NetworkRouter {
	if r == nil {
		return nil
	}
	return &nmdata.NetworkRouter{
		PublicID:   r.PublicID,
		PeerGroups: r.PeerGroups,
		Masquerade: r.Masquerade,
		Metric:     r.Metric,
		Enabled:    r.Enabled,
	}
}

func twinNSG(n *nbdns.NameServerGroup) *nmdata.NameServerGroup {
	if n == nil {
		return nil
	}
	nameServers := make([]nmdata.NameServer, 0, len(n.NameServers))
	for _, ns := range n.NameServers {
		nameServers = append(nameServers, nmdata.NameServer{
			IP:     ns.IP,
			NSType: int(ns.NSType),
			Port:   ns.Port,
		})
	}
	return &nmdata.NameServerGroup{
		ID:                   n.ID,
		PublicID:             n.PublicID,
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

// TwinNetwork converts a real *Network to its slim twin. Exported for the
// graceful-degrade path that builds a minimal NetworkMapComponents directly.
func TwinNetwork(n *Network) *nmdata.Network {
	nc := n.Copy()
	return &nmdata.Network{
		Identifier: nc.Identifier,
		Net:        nc.Net,
		NetV6:      nc.NetV6,
		Dns:        nc.Dns,
		Serial:     int64(nc.Serial),
	}
}

// TwinPostureChecksList converts posture checks to their slim nmdata twins.
func TwinPostureChecksList(checks []*posture.Checks) []*nmdata.PostureChecks {
	out := make([]*nmdata.PostureChecks, 0, len(checks))
	for _, pc := range checks {
		out = append(out, TwinPostureChecks(pc))
	}
	return out
}

// TwinPostureChecks converts posture checks to their slim nmdata twin.
func TwinPostureChecks(pc *posture.Checks) *nmdata.PostureChecks {
	if pc == nil {
		return nil
	}
	out := &nmdata.PostureChecks{ID: pc.ID}
	def := pc.Checks
	if def.NBVersionCheck != nil {
		out.Checks.NBVersionCheck = &nmdata.NBVersionCheck{MinVersion: def.NBVersionCheck.MinVersion}
	}
	if def.OSVersionCheck != nil {
		oc := &nmdata.OSVersionCheck{}
		if def.OSVersionCheck.Android != nil {
			oc.Android = &nmdata.MinVersionCheck{MinVersion: def.OSVersionCheck.Android.MinVersion}
		}
		if def.OSVersionCheck.Darwin != nil {
			oc.Darwin = &nmdata.MinVersionCheck{MinVersion: def.OSVersionCheck.Darwin.MinVersion}
		}
		if def.OSVersionCheck.Ios != nil {
			oc.Ios = &nmdata.MinVersionCheck{MinVersion: def.OSVersionCheck.Ios.MinVersion}
		}
		if def.OSVersionCheck.Linux != nil {
			oc.Linux = &nmdata.MinKernelVersionCheck{MinKernelVersion: def.OSVersionCheck.Linux.MinKernelVersion}
		}
		if def.OSVersionCheck.Windows != nil {
			oc.Windows = &nmdata.MinKernelVersionCheck{MinKernelVersion: def.OSVersionCheck.Windows.MinKernelVersion}
		}
		out.Checks.OSVersionCheck = oc
	}
	if def.GeoLocationCheck != nil {
		gc := &nmdata.GeoLocationCheck{Action: def.GeoLocationCheck.Action}
		for _, loc := range def.GeoLocationCheck.Locations {
			gc.Locations = append(gc.Locations, nmdata.GeoLocation{CountryCode: loc.CountryCode, CityName: loc.CityName})
		}
		out.Checks.GeoLocationCheck = gc
	}
	if def.PeerNetworkRangeCheck != nil {
		out.Checks.PeerNetworkRangeCheck = &nmdata.PeerNetworkRangeCheck{
			Action: def.PeerNetworkRangeCheck.Action,
			Ranges: def.PeerNetworkRangeCheck.Ranges,
		}
	}
	if def.ProcessCheck != nil {
		procs := make([]nmdata.Process, 0, len(def.ProcessCheck.Processes))
		for _, p := range def.ProcessCheck.Processes {
			procs = append(procs, nmdata.Process{LinuxPath: p.LinuxPath, MacPath: p.MacPath, WindowsPath: p.WindowsPath})
		}
		out.Checks.ProcessCheck = &nmdata.ProcessCheck{Processes: procs}
	}
	return out
}

// buildAppliedZoneCandidates precomputes the account-level custom DNS zones
// (record conversion) once; the per-peer distribution-group gate runs in the
// components calc. Mirrors the account-level half of filterPeerAppliedZones.
func buildAppliedZoneCandidates(accountZones []*zones.Zone) []networkmap.AppliedZoneCandidate {
	var out []networkmap.AppliedZoneCandidate
	for _, zone := range accountZones {
		if !zone.Enabled || len(zone.Records) == 0 {
			continue
		}
		simpleRecords := make([]nmdata.SimpleRecord, 0, len(zone.Records))
		for _, record := range zone.Records {
			var recordType int
			rData := record.Content
			switch record.Type {
			case records.RecordTypeA:
				recordType = int(dns.TypeA)
			case records.RecordTypeAAAA:
				recordType = int(dns.TypeAAAA)
			case records.RecordTypeCNAME:
				recordType = int(dns.TypeCNAME)
				rData = dns.Fqdn(record.Content)
			default:
				continue
			}
			simpleRecords = append(simpleRecords, nmdata.SimpleRecord{
				Name:  dns.Fqdn(record.Name),
				Type:  recordType,
				Class: nbdns.DefaultClass,
				TTL:   record.TTL,
				RData: rData,
			})
		}
		out = append(out, networkmap.AppliedZoneCandidate{
			DistributionGroups: zone.DistributionGroups,
			Zone: nmdata.CustomZone{
				Domain:               dns.Fqdn(zone.Domain),
				Records:              simpleRecords,
				SearchDomainDisabled: !zone.EnableSearchDomain,
				NonAuthoritative:     true,
			},
		})
	}
	return out
}

// buildPrivateServiceCandidates precomputes the connected-proxy A records per
// private service (account-level); the per-peer access-group gate + apex merge
// run in the components calc. Mirrors the account-level half of
// SynthesizePrivateServiceZones.
func (a *Account) buildPrivateServiceCandidates() []networkmap.PrivateServiceCandidate {
	if len(a.Services) == 0 {
		return nil
	}
	proxyPeersByCluster := a.GetProxyPeers()
	if len(proxyPeersByCluster) == 0 {
		return nil
	}

	var out []networkmap.PrivateServiceCandidate
	for _, svc := range a.Services {
		if svc == nil || !svc.Enabled || !svc.Private {
			continue
		}
		if len(svc.AccessGroups) == 0 {
			continue
		}
		proxyPeers := proxyPeersByCluster[svc.ProxyCluster]
		if len(proxyPeers) == 0 {
			continue
		}
		apex := a.privateServiceDomainZone(svc)
		if apex == "" {
			continue
		}

		var recs []nmdata.SimpleRecord
		for _, p := range proxyPeers {
			if p == nil || !p.IP.IsValid() {
				continue
			}
			if p.Status == nil || !p.Status.Connected {
				continue
			}
			recs = append(recs, nmdata.SimpleRecord{
				Name:  dns.Fqdn(svc.Domain),
				Type:  int(dns.TypeA),
				Class: nbdns.DefaultClass,
				TTL:   privateServiceDNSRecordTTL,
				RData: p.IP.String(),
			})
		}
		if len(recs) == 0 {
			continue
		}

		out = append(out, networkmap.PrivateServiceCandidate{
			AccessGroups: svc.AccessGroups,
			Zone: nmdata.CustomZone{
				Domain:               dns.Fqdn(apex),
				Records:              recs,
				NonAuthoritative:     true,
				SearchDomainDisabled: true,
			},
		})
	}
	return out
}

// TwinAccountSettings converts real account settings to the slim nmdata twin.
// Exported for callers of the twin-based sync response builders.
func TwinAccountSettings(s *Settings) *nmdata.AccountSettingsInfo {
	if s == nil {
		return nil
	}
	return &nmdata.AccountSettingsInfo{
		PeerLoginExpirationEnabled:      s.PeerLoginExpirationEnabled,
		PeerLoginExpiration:             s.PeerLoginExpiration,
		PeerInactivityExpirationEnabled: s.PeerInactivityExpirationEnabled,
		PeerInactivityExpiration:        s.PeerInactivityExpiration,
		DNSDomain:                       s.DNSDomain,
		IPv6EnabledGroups:               s.IPv6EnabledGroups,
		RoutingPeerDNSResolutionEnabled: s.RoutingPeerDNSResolutionEnabled,
		LazyConnectionEnabled:           s.LazyConnectionEnabled,
		AutoUpdateVersion:               s.AutoUpdateVersion,
		AutoUpdateAlways:                s.AutoUpdateAlways,
		MetricsPushEnabled:              s.MetricsPushEnabled,
	}
}

func fromTwinCustomZone(z nmdata.CustomZone) nbdns.CustomZone {
	records := make([]nbdns.SimpleRecord, 0, len(z.Records))
	for _, r := range z.Records {
		records = append(records, nbdns.SimpleRecord{
			Name:  r.Name,
			Type:  r.Type,
			Class: r.Class,
			TTL:   r.TTL,
			RData: r.RData,
		})
	}
	return nbdns.CustomZone{
		Domain:               z.Domain,
		Records:              records,
		SearchDomainDisabled: z.SearchDomainDisabled,
		NonAuthoritative:     z.NonAuthoritative,
	}
}

// TwinCustomZone converts a real DNS custom zone to its slim nmdata twin.
// Exported for the network-map controller's DB-store path, which feeds real
// zones into the twin-based components calculation.
func TwinCustomZone(z nbdns.CustomZone) nmdata.CustomZone {
	records := make([]nmdata.SimpleRecord, 0, len(z.Records))
	for _, r := range z.Records {
		records = append(records, nmdata.SimpleRecord{
			Name:  r.Name,
			Type:  r.Type,
			Class: r.Class,
			TTL:   r.TTL,
			RData: r.RData,
		})
	}
	return nmdata.CustomZone{
		Domain:               z.Domain,
		Records:              records,
		SearchDomainDisabled: z.SearchDomainDisabled,
		NonAuthoritative:     z.NonAuthoritative,
	}
}

// twinProxyDomains converts the account's registered reverse-proxy domains to
// their slim twins, so private-service zone apex resolution runs on the twin.
func twinProxyDomains(domains []*proxydomain.Domain) []nmdata.ProxyDomain {
	if len(domains) == 0 {
		return nil
	}
	out := make([]nmdata.ProxyDomain, 0, len(domains))
	for _, d := range domains {
		if d == nil {
			continue
		}
		out = append(out, nmdata.ProxyDomain{Domain: d.Domain, TargetCluster: d.TargetCluster})
	}
	return out
}

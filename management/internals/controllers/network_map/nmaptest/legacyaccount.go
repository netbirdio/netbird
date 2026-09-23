package nmaptest

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/types/legacynmap"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// legacyInput is the account and the four derived arguments main's computation
// took alongside it. The controller resolved them from the account before
// calling; the twin carries them as fields, so the fixture is the source for
// both halves.
type legacyInput struct {
	account          *types.Account
	accountZones     []*zones.Zone
	validatedPeers   map[string]struct{}
	resourcePolicies map[string][]*types.Policy
	routers          map[string]map[string]*routerTypes.NetworkRouter
	groupIDToUserIDs map[string][]string
}

// legacyInputFromData rebuilds the Account the fixture stands for. A fixture is
// the value the store returns, and the store's twins carry exactly the state
// the computation reads, so inverting them reproduces the account main would
// have loaded — which is what lets one expectation measure all three paths.
//
// The inverse is only defined for what a twin carries: fields the builders drop
// (peer names, policy descriptions, user records behind AllowedUserIDs) come
// back as the zero value or a minimal stand-in, because no path reads them.
func legacyInputFromData(accountID string, nmData *networkmap.NetworkMapData) legacyInput {
	account := &types.Account{
		Id:               accountID,
		Network:          accountNetwork(nmData.Network),
		Settings:         accountSettings(nmData.AccountSettings),
		DNSSettings:      types.DNSSettings{DisabledManagementGroups: nmData.DNSSettings.DisabledManagementGroups},
		Peers:            make(map[string]*nbpeer.Peer, len(nmData.Peers)),
		Groups:           make(map[string]*types.Group, len(nmData.Groups)),
		Policies:         make([]*types.Policy, 0, len(nmData.Policies)),
		Routes:           make(map[nbroute.ID]*nbroute.Route, len(nmData.Routes)),
		NameServerGroups: make(map[string]*nbdns.NameServerGroup, len(nmData.NameServerGroups)),
		NetworkResources: make([]*resourceTypes.NetworkResource, 0, len(nmData.NetworkResources)),
		PostureChecks:    make([]*posture.Checks, 0, len(nmData.PostureChecks)),
		Users:            make(map[string]*types.User, len(nmData.AllowedUserIDs)),
		Services:         accountServices(nmData.Services),
	}

	for id, p := range nmData.Peers {
		account.Peers[id] = accountPeer(id, p)
	}
	for id, g := range nmData.Groups {
		account.Groups[id] = accountGroup(id, g)
	}

	policiesByID := make(map[string]*types.Policy, len(nmData.Policies))
	for _, p := range nmData.Policies {
		policy := accountPolicy(p)
		if policy == nil {
			continue
		}
		account.Policies = append(account.Policies, policy)
		policiesByID[policy.ID] = policy
	}

	for _, r := range nmData.Routes {
		route := accountRoute(r)
		if route != nil {
			account.Routes[route.ID] = route
		}
	}
	for _, nsg := range nmData.NameServerGroups {
		group := accountNSG(nsg)
		if group != nil {
			account.NameServerGroups[group.ID] = group
		}
	}
	for _, res := range nmData.NetworkResources {
		if resource := accountNetworkResource(res); resource != nil {
			account.NetworkResources = append(account.NetworkResources, resource)
		}
	}
	for id, pc := range nmData.PostureChecks {
		if check := accountPostureChecks(id, pc, nmData.PostureCheckXIDToPublicID[id]); check != nil {
			account.PostureChecks = append(account.PostureChecks, check)
		}
	}
	for xid, publicID := range nmData.NetworkXIDToPublicID {
		account.Networks = append(account.Networks, &networkTypes.Network{ID: xid, PublicID: publicID})
	}
	// The twin keeps only the ids of the users a peer may be shared with; the
	// legacy side derives the same set from the account's user records, so a
	// bare non-blocked regular user per id is enough.
	for userID := range nmData.AllowedUserIDs {
		account.Users[userID] = &types.User{Id: userID}
	}

	// Main's network-map controller synthesised the reverse-proxy ACLs onto the
	// account and only then derived the resource-policy map, so the frozen copy
	// has to be fed in that order to stand for what main produced.
	account.Policies = append(account.Policies, legacynmap.SynthesizeProxyPolicies(account)...)

	return legacyInput{
		account:          account,
		accountZones:     accountZones(nmData.AppliedZoneCandidates),
		validatedPeers:   nmData.ValidatedPeers,
		resourcePolicies: account.GetResourcePoliciesMap(),
		routers:          accountRouters(nmData.Routers),
		groupIDToUserIDs: nmData.GroupIDToUserIDs,
	}
}

// computeLegacy runs the fixture through main's frozen path and its own proto
// encoder, the one comparison surface the three modes share.
func computeLegacy(t *testing.T, ctx context.Context, legacy legacyInput, peerID string, zone nmdata.CustomZone, dnsDomain string, dnsFwdPort int64) *proto.NetworkMap {
	t.Helper()

	require.NotNil(t, legacy.account, "legacy mode needs an account rebuilt from the fixture")
	peer := legacy.account.Peers[peerID]
	require.NotNil(t, peer, "target peer %q not in rebuilt account", peerID)

	nm := legacynmap.GetPeerNetworkMapFromComponents(
		legacy.account, ctx, peerID, legacyCustomZone(zone), legacy.accountZones, legacy.validatedPeers,
		legacy.resourcePolicies, legacy.routers, nil, legacy.groupIDToUserIDs,
	)
	require.NotNil(t, nm, "legacy path returned no network map for peer %q", peerID)

	return legacynmap.ToProtoNetworkMap(
		ctx, peer, nm, dnsDomain, legacy.account.Settings, nil, &cache.DNSConfigCache{}, dnsFwdPort,
	)
}

// legacyCustomZone converts the peers custom zone the runner computes once for
// every mode into the shape main's path took.
func legacyCustomZone(z nmdata.CustomZone) nbdns.CustomZone {
	zoneRecords := make([]nbdns.SimpleRecord, 0, len(z.Records))
	for _, r := range z.Records {
		zoneRecords = append(zoneRecords, nbdns.SimpleRecord{
			Name:  r.Name,
			Type:  r.Type,
			Class: r.Class,
			TTL:   r.TTL,
			RData: r.RData,
		})
	}
	return nbdns.CustomZone{
		Domain:               z.Domain,
		Records:              zoneRecords,
		SearchDomainDisabled: z.SearchDomainDisabled,
		NonAuthoritative:     z.NonAuthoritative,
	}
}

func accountNetwork(n *nmdata.Network) *types.Network {
	if n == nil {
		return nil
	}
	return &types.Network{
		Identifier: n.Identifier,
		Net:        n.Net,
		NetV6:      n.NetV6,
		Dns:        n.Dns,
		Serial:     uint64(n.Serial),
	}
}

func accountSettings(s *nmdata.AccountSettingsInfo) *types.Settings {
	if s == nil {
		return nil
	}
	return &types.Settings{
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

func accountPeer(id string, p *nmdata.Peer) *nbpeer.Peer {
	if p == nil {
		return nil
	}
	networkAddresses := make([]nbpeer.NetworkAddress, 0, len(p.Meta.NetworkAddresses))
	for _, na := range p.Meta.NetworkAddresses {
		networkAddresses = append(networkAddresses, nbpeer.NetworkAddress{NetIP: na.NetIP})
	}
	files := make([]nbpeer.File, 0, len(p.Meta.Files))
	for _, f := range p.Meta.Files {
		files = append(files, nbpeer.File{Path: f.Path, ProcessIsRunning: f.ProcessIsRunning})
	}
	return &nbpeer.Peer{
		ID:                     id,
		Key:                    p.Key,
		SSHKey:                 p.SSHKey,
		DNSLabel:               p.DNSLabel,
		UserID:                 p.UserID,
		SSHEnabled:             p.SSHEnabled,
		LoginExpirationEnabled: p.LoginExpirationEnabled,
		LastLogin:              p.LastLogin,
		IP:                     p.IP,
		IPv6:                   p.IPv6,
		ExtraDNSLabels:         p.ExtraDNSLabels,
		ProxyMeta:              nbpeer.ProxyMeta{Embedded: p.ProxyMeta.Embedded, Cluster: p.ProxyMeta.Cluster},
		// Connected is what SynthesizePrivateServiceZones gates its records on,
		// and a fixture peer stands for a peer the store returned, so it is one
		// the account would have reported connected.
		Status: &nbpeer.PeerStatus{RequiresApproval: p.RequiresApproval, Connected: true},
		Meta: nbpeer.PeerSystemMeta{
			WtVersion:          p.Meta.WtVersion,
			GoOS:               p.Meta.GoOS,
			OSVersion:          p.Meta.OSVersion,
			KernelVersion:      p.Meta.KernelVersion,
			NetworkAddresses:   networkAddresses,
			Files:              files,
			Capabilities:       p.Meta.Capabilities,
			SyncMessageVersion: p.Meta.SyncMessageVersion,
			Flags: nbpeer.Flags{
				ServerSSHAllowed: p.Meta.Flags.ServerSSHAllowed,
				DisableIPv6:      p.Meta.Flags.DisableIPv6,
			},
		},
		Location: nbpeer.Location{
			CountryCode:  p.Location.CountryCode,
			CityName:     p.Location.CityName,
			ConnectionIP: p.Location.ConnectionIP,
		},
	}
}

func accountGroup(id string, g *nmdata.Group) *types.Group {
	if g == nil {
		return nil
	}
	return &types.Group{
		ID:       id,
		Name:     g.Name,
		PublicID: g.PublicID,
		Peers:    g.Peers,
	}
}

func accountPolicy(p *nmdata.Policy) *types.Policy {
	if p == nil {
		return nil
	}
	rules := make([]*types.PolicyRule, 0, len(p.Rules))
	for _, r := range p.Rules {
		if r == nil {
			continue
		}
		var portRanges []sharedtypes.RulePortRange
		if r.PortRanges != nil {
			portRanges = make([]sharedtypes.RulePortRange, len(r.PortRanges))
			for i, pr := range r.PortRanges {
				portRanges[i] = sharedtypes.RulePortRange{Start: pr.Start, End: pr.End}
			}
		}
		rules = append(rules, &types.PolicyRule{
			ID:                  r.ID,
			PolicyID:            r.PolicyID,
			Enabled:             r.Enabled,
			Action:              sharedtypes.PolicyTrafficActionType(r.Action),
			Protocol:            sharedtypes.PolicyRuleProtocolType(r.Protocol),
			Bidirectional:       r.Bidirectional,
			Sources:             r.Sources,
			Destinations:        r.Destinations,
			SourceResource:      types.Resource{ID: r.SourceResource.ID, Type: sharedtypes.ResourceType(r.SourceResource.Type)},
			DestinationResource: types.Resource{ID: r.DestinationResource.ID, Type: sharedtypes.ResourceType(r.DestinationResource.Type)},
			Ports:               r.Ports,
			PortRanges:          portRanges,
			AuthorizedGroups:    r.AuthorizedGroups,
			AuthorizedUser:      r.AuthorizedUser,
		})
	}
	return &types.Policy{
		ID:                  p.ID,
		PublicID:            p.PublicID,
		Enabled:             p.Enabled,
		SourcePostureChecks: p.SourcePostureChecks,
		Rules:               rules,
	}
}

func accountRoute(r *nmdata.Route) *nbroute.Route {
	if r == nil {
		return nil
	}
	return &nbroute.Route{
		ID:                  nbroute.ID(r.ID),
		AccountID:           r.AccountID,
		PublicID:            r.PublicID,
		Network:             r.Network,
		Domains:             r.Domains,
		KeepRoute:           r.KeepRoute,
		NetID:               nbroute.NetID(r.NetID),
		Description:         r.Description,
		Peer:                r.Peer,
		PeerID:              r.PeerID,
		PeerGroups:          r.PeerGroups,
		NetworkType:         nbroute.NetworkType(r.NetworkType),
		Masquerade:          r.Masquerade,
		Metric:              r.Metric,
		Enabled:             r.Enabled,
		Groups:              r.Groups,
		AccessControlGroups: r.AccessControlGroups,
		SkipAutoApply:       r.SkipAutoApply,
	}
}

func accountNSG(n *nmdata.NameServerGroup) *nbdns.NameServerGroup {
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

func accountNetworkResource(r *nmdata.NetworkResource) *resourceTypes.NetworkResource {
	if r == nil {
		return nil
	}
	return &resourceTypes.NetworkResource{
		ID:          r.ID,
		NetworkID:   r.NetworkID,
		AccountID:   r.AccountID,
		PublicID:    r.PublicID,
		Name:        r.Name,
		Description: r.Description,
		Type:        resourceTypes.NetworkResourceType(r.Type),
		Address:     r.Address,
		Domain:      r.Domain,
		Prefix:      r.Prefix,
		Enabled:     r.Enabled,
	}
}

func accountPostureChecks(id string, pc *nmdata.PostureChecks, publicID string) *posture.Checks {
	if pc == nil {
		return nil
	}
	out := &posture.Checks{ID: id, PublicID: publicID}
	def := pc.Checks
	if def.NBVersionCheck != nil {
		out.Checks.NBVersionCheck = &posture.NBVersionCheck{MinVersion: def.NBVersionCheck.MinVersion}
	}
	if def.OSVersionCheck != nil {
		oc := &posture.OSVersionCheck{}
		if def.OSVersionCheck.Android != nil {
			oc.Android = &posture.MinVersionCheck{MinVersion: def.OSVersionCheck.Android.MinVersion}
		}
		if def.OSVersionCheck.Darwin != nil {
			oc.Darwin = &posture.MinVersionCheck{MinVersion: def.OSVersionCheck.Darwin.MinVersion}
		}
		if def.OSVersionCheck.Ios != nil {
			oc.Ios = &posture.MinVersionCheck{MinVersion: def.OSVersionCheck.Ios.MinVersion}
		}
		if def.OSVersionCheck.Linux != nil {
			oc.Linux = &posture.MinKernelVersionCheck{MinKernelVersion: def.OSVersionCheck.Linux.MinKernelVersion}
		}
		if def.OSVersionCheck.Windows != nil {
			oc.Windows = &posture.MinKernelVersionCheck{MinKernelVersion: def.OSVersionCheck.Windows.MinKernelVersion}
		}
		out.Checks.OSVersionCheck = oc
	}
	if def.GeoLocationCheck != nil {
		gc := &posture.GeoLocationCheck{Action: def.GeoLocationCheck.Action}
		for _, loc := range def.GeoLocationCheck.Locations {
			gc.Locations = append(gc.Locations, posture.Location{CountryCode: loc.CountryCode, CityName: loc.CityName})
		}
		out.Checks.GeoLocationCheck = gc
	}
	if def.PeerNetworkRangeCheck != nil {
		out.Checks.PeerNetworkRangeCheck = &posture.PeerNetworkRangeCheck{
			Action: def.PeerNetworkRangeCheck.Action,
			Ranges: def.PeerNetworkRangeCheck.Ranges,
		}
	}
	if def.ProcessCheck != nil {
		procs := make([]posture.Process, 0, len(def.ProcessCheck.Processes))
		for _, p := range def.ProcessCheck.Processes {
			procs = append(procs, posture.Process{LinuxPath: p.LinuxPath, MacPath: p.MacPath, WindowsPath: p.WindowsPath})
		}
		out.Checks.ProcessCheck = &posture.ProcessCheck{Processes: procs}
	}
	return out
}

func accountServices(services []*nmdata.Service) []*service.Service {
	if len(services) == 0 {
		return nil
	}
	out := make([]*service.Service, 0, len(services))
	for _, svc := range services {
		if svc == nil {
			continue
		}
		targets := make([]*service.Target, 0, len(svc.Targets))
		for _, t := range svc.Targets {
			if t == nil {
				continue
			}
			target := &service.Target{
				Enabled:    t.Enabled,
				Port:       t.Port,
				Protocol:   t.Protocol,
				TargetId:   t.TargetID,
				TargetType: service.TargetType(t.TargetType),
			}
			if t.Path != "" {
				path := t.Path
				target.Path = &path
			}
			targets = append(targets, target)
		}
		out = append(out, &service.Service{
			ID:           svc.ID,
			Enabled:      svc.Enabled,
			Private:      svc.Private,
			Mode:         svc.Mode,
			ProxyCluster: svc.ProxyCluster,
			AccessGroups: svc.AccessGroups,
			Targets:      targets,
		})
	}
	return out
}

// accountZones inverts buildAppliedZoneCandidates. Records come back with the
// record type the builder mapped them from; a candidate only ever carries the
// three types it converts.
func accountZones(candidates []networkmap.AppliedZoneCandidate) []*zones.Zone {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]*zones.Zone, 0, len(candidates))
	for _, candidate := range candidates {
		zoneRecords := make([]*records.Record, 0, len(candidate.Zone.Records))
		for _, r := range candidate.Zone.Records {
			recordType, ok := zoneRecordType(r.Type)
			if !ok {
				continue
			}
			zoneRecords = append(zoneRecords, &records.Record{
				Name:    strings.TrimSuffix(r.Name, "."),
				Type:    recordType,
				Content: r.RData,
				TTL:     r.TTL,
			})
		}
		out = append(out, &zones.Zone{
			ID:                 candidate.Zone.Domain,
			Domain:             strings.TrimSuffix(candidate.Zone.Domain, "."),
			Enabled:            true,
			EnableSearchDomain: !candidate.Zone.SearchDomainDisabled,
			DistributionGroups: candidate.DistributionGroups,
			Records:            zoneRecords,
		})
	}
	return out
}

func zoneRecordType(recordType int) (records.RecordType, bool) {
	switch uint16(recordType) {
	case dns.TypeA:
		return records.RecordTypeA, true
	case dns.TypeAAAA:
		return records.RecordTypeAAAA, true
	case dns.TypeCNAME:
		return records.RecordTypeCNAME, true
	default:
		return "", false
	}
}

func accountRouters(routers map[string]map[string]*nmdata.NetworkRouter) map[string]map[string]*routerTypes.NetworkRouter {
	if len(routers) == 0 {
		return nil
	}
	out := make(map[string]map[string]*routerTypes.NetworkRouter, len(routers))
	for networkID, inner := range routers {
		converted := make(map[string]*routerTypes.NetworkRouter, len(inner))
		for peerID, router := range inner {
			if router == nil {
				continue
			}
			converted[peerID] = &routerTypes.NetworkRouter{
				NetworkID:  networkID,
				PublicID:   router.PublicID,
				Peer:       peerID,
				PeerGroups: router.PeerGroups,
				Masquerade: router.Masquerade,
				Metric:     router.Metric,
				Enabled:    router.Enabled,
			}
		}
		out[networkID] = converted
	}
	return out
}

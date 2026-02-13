package types

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ssh/auth"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	defaultTTL                      = 300
	DefaultPeerLoginExpiration      = 24 * time.Hour
	DefaultPeerInactivityExpiration = 10 * time.Minute

	PublicCategory  = "public"
	PrivateCategory = "private"
	UnknownCategory = "unknown"

	// firewallRuleMinPortRangesVer defines the minimum peer version that supports port range rules.
	firewallRuleMinPortRangesVer = "0.48.0"
	// firewallRuleMinNativeSSHVer defines the minimum peer version that supports native SSH features in the firewall rules.
	firewallRuleMinNativeSSHVer = "0.60.0"

	// nativeSSHPortString defines the default port number as a string used for native SSH connections; this port is used by clients when hijacking ssh connections.
	nativeSSHPortString = "22022"
	nativeSSHPortNumber = 22022
	// defaultSSHPortString defines the standard SSH port number as a string, commonly used for default SSH connections.
	defaultSSHPortString = "22"
	defaultSSHPortNumber = 22
)

type supportedFeatures struct {
	nativeSSH  bool
	portRanges bool
}

type LookupMap map[string]struct{}

// AccountMeta is a struct that contains a stripped down version of the Account object.
// It doesn't carry any peers, groups, policies, or routes, etc. Just some metadata (e.g. ID, created by, created at, etc).
type AccountMeta struct {
	// AccountId is the unique identifier of the account
	AccountID      string `gorm:"column:id"`
	CreatedAt      time.Time
	CreatedBy      string
	Domain         string
	DomainCategory string
}

// Account represents a unique account of the system
type Account struct {
	// we have to name column to aid as it collides with Network.Id when work with associations
	Id string `gorm:"primaryKey"`

	// User.Id it was created by
	CreatedBy              string
	CreatedAt              time.Time
	Domain                 string `gorm:"index"`
	DomainCategory         string
	IsDomainPrimaryAccount bool
	SetupKeys              map[string]*SetupKey              `gorm:"-"`
	SetupKeysG             []SetupKey                        `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Network                *Network                          `gorm:"embedded;embeddedPrefix:network_"`
	Peers                  map[string]*nbpeer.Peer           `gorm:"-"`
	PeersG                 []nbpeer.Peer                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Users                  map[string]*User                  `gorm:"-"`
	UsersG                 []User                            `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Groups                 map[string]*Group                 `gorm:"-"`
	GroupsG                []*Group                          `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Policies               []*Policy                         `gorm:"foreignKey:AccountID;references:id"`
	Routes                 map[route.ID]*route.Route         `gorm:"-"`
	RoutesG                []route.Route                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	NameServerGroups       map[string]*nbdns.NameServerGroup `gorm:"-"`
	NameServerGroupsG      []nbdns.NameServerGroup           `json:"-" gorm:"foreignKey:AccountID;references:id"`
	DNSSettings            DNSSettings                       `gorm:"embedded;embeddedPrefix:dns_settings_"`
	PostureChecks          []*posture.Checks                 `gorm:"foreignKey:AccountID;references:id"`
	Services               []*reverseproxy.Service           `gorm:"foreignKey:AccountID;references:id"`
	// Settings is a dictionary of Account settings
	Settings         *Settings                        `gorm:"embedded;embeddedPrefix:settings_"`
	Networks         []*networkTypes.Network          `gorm:"foreignKey:AccountID;references:id"`
	NetworkRouters   []*routerTypes.NetworkRouter     `gorm:"foreignKey:AccountID;references:id"`
	NetworkResources []*resourceTypes.NetworkResource `gorm:"foreignKey:AccountID;references:id"`
	Onboarding       AccountOnboarding                `gorm:"foreignKey:AccountID;references:id;constraint:OnDelete:CASCADE"`

	NetworkMapCache *NetworkMapBuilder `gorm:"-"`
	nmapInitOnce    *sync.Once         `gorm:"-"`

	ReverseProxyFreeDomainNonce string
}

func (a *Account) InitOnce() {
	a.nmapInitOnce = &sync.Once{}
}

// this class is used by gorm only
type PrimaryAccountInfo struct {
	IsDomainPrimaryAccount bool
	Domain                 string
}

// Subclass used in gorm to only load network and not whole account
type AccountNetwork struct {
	Network *Network `gorm:"embedded;embeddedPrefix:network_"`
}

// AccountDNSSettings used in gorm to only load dns settings and not whole account
type AccountDNSSettings struct {
	DNSSettings DNSSettings `gorm:"embedded;embeddedPrefix:dns_settings_"`
}

// Subclass used in gorm to only load settings and not whole account
type AccountSettings struct {
	Settings *Settings `gorm:"embedded;embeddedPrefix:settings_"`
}

type AccountOnboarding struct {
	AccountID             string `gorm:"primaryKey"`
	OnboardingFlowPending bool
	SignupFormPending     bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// IsEqual compares two AccountOnboarding objects and returns true if they are equal
func (o AccountOnboarding) IsEqual(onboarding AccountOnboarding) bool {
	return o.OnboardingFlowPending == onboarding.OnboardingFlowPending &&
		o.SignupFormPending == onboarding.SignupFormPending
}

// GetRoutesToSync returns the enabled routes for the peer ID and the routes
// from the ACL peers that have distribution groups associated with the peer ID.
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
func (a *Account) GetRoutesToSync(ctx context.Context, peerID string, aclPeers []*nbpeer.Peer, peerGroups LookupMap) []*route.Route {
	routes, peerDisabledRoutes := a.getRoutingPeerRoutes(ctx, peerID)
	peerRoutesMembership := make(LookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[string(r.GetHAUniqueID())] = struct{}{}
	}

	for _, peer := range aclPeers {
		activeRoutes, _ := a.getRoutingPeerRoutes(ctx, peer.ID)
		groupFilteredRoutes := a.filterRoutesByGroups(activeRoutes, peerGroups)
		filteredRoutes := a.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

// filterRoutesFromPeersOfSameHAGroup filters and returns a list of routes that don't share the same HA route membership
func (a *Account) filterRoutesFromPeersOfSameHAGroup(routes []*route.Route, peerMemberships LookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		_, found := peerMemberships[string(r.GetHAUniqueID())]
		if !found {
			filteredRoutes = append(filteredRoutes, r)
		}
	}
	return filteredRoutes
}

// filterRoutesByGroups returns a list with routes that have distribution groups in the group's map
func (a *Account) filterRoutesByGroups(routes []*route.Route, groupListMap LookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		for _, groupID := range r.Groups {
			_, found := groupListMap[groupID]
			if found {
				filteredRoutes = append(filteredRoutes, r)
				break
			}
		}
	}
	return filteredRoutes
}

// getRoutingPeerRoutes returns the enabled and disabled lists of routes that the given routing peer serves
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
// If the given is not a routing peer, then the lists are empty.
func (a *Account) getRoutingPeerRoutes(ctx context.Context, peerID string) (enabledRoutes []*route.Route, disabledRoutes []*route.Route) {

	peer := a.GetPeer(peerID)
	if peer == nil {
		log.WithContext(ctx).Errorf("peer %s that doesn't exist under account %s", peerID, a.Id)
		return enabledRoutes, disabledRoutes
	}

	seenRoute := make(map[route.ID]struct{})

	takeRoute := func(r *route.Route, id string) {
		if _, ok := seenRoute[r.ID]; ok {
			return
		}
		seenRoute[r.ID] = struct{}{}

		if r.Enabled {
			r.Peer = peer.Key
			enabledRoutes = append(enabledRoutes, r)
			return
		}
		disabledRoutes = append(disabledRoutes, r)
	}

	for _, r := range a.Routes {
		for _, groupID := range r.PeerGroups {
			group := a.GetGroup(groupID)
			if group == nil {
				log.WithContext(ctx).Errorf("route %s has peers group %s that doesn't exist under account %s", r.ID, groupID, a.Id)
				continue
			}
			for _, id := range group.Peers {
				if id != peerID {
					continue
				}

				newPeerRoute := r.Copy()
				newPeerRoute.Peer = id
				newPeerRoute.PeerGroups = nil
				newPeerRoute.ID = route.ID(string(r.ID) + ":" + id) // we have to provide unique route id when distribute network map
				takeRoute(newPeerRoute, id)
				break
			}
		}
		if r.Peer == peerID {
			takeRoute(r.Copy(), peerID)
		}
	}

	return enabledRoutes, disabledRoutes
}

// GetRoutesByPrefixOrDomains return list of routes by account and route prefix
func (a *Account) GetRoutesByPrefixOrDomains(prefix netip.Prefix, domains domain.List) []*route.Route {
	var routes []*route.Route
	for _, r := range a.Routes {
		dynamic := r.IsDynamic()
		if dynamic && r.Domains.PunycodeString() == domains.PunycodeString() ||
			!dynamic && r.Network.String() == prefix.String() {
			routes = append(routes, r)
		}
	}

	return routes
}

// GetGroup returns a group by ID if exists, nil otherwise
func (a *Account) GetGroup(groupID string) *Group {
	return a.Groups[groupID]
}

// GetPeerNetworkMap returns the networkmap for the given peer ID.
func (a *Account) GetPeerNetworkMap(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	accountZones []*zones.Zone,
	validatedPeersMap map[string]struct{},
	resourcePolicies map[string][]*Policy,
	routers map[string]map[string]*routerTypes.NetworkRouter,
	metrics *telemetry.AccountManagerMetrics,
	groupIDToUserIDs map[string][]string,
) *NetworkMap {
	start := time.Now()
	peer := a.Peers[peerID]
	if peer == nil {
		return &NetworkMap{
			Network: a.Network.Copy(),
		}
	}

	if _, ok := validatedPeersMap[peerID]; !ok {
		return &NetworkMap{
			Network: a.Network.Copy(),
		}
	}

	peerGroups := a.GetPeerGroups(peerID)

	aclPeers, firewallRules, authorizedUsers, enableSSH := a.GetPeerConnectionResources(ctx, peer, validatedPeersMap, groupIDToUserIDs)
	// exclude expired peers
	var peersToConnect []*nbpeer.Peer
	var expiredPeers []*nbpeer.Peer
	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(a.Settings.PeerLoginExpiration)
		if a.Settings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, p)
			continue
		}
		peersToConnect = append(peersToConnect, p)
	}

	routesUpdate := a.GetRoutesToSync(ctx, peerID, peersToConnect, peerGroups)
	routesFirewallRules := a.GetPeerRoutesFirewallRules(ctx, peerID, validatedPeersMap)
	isRouter, networkResourcesRoutes, sourcePeers := a.GetNetworkResourcesRoutesToSync(ctx, peerID, resourcePolicies, routers)
	var networkResourcesFirewallRules []*RouteFirewallRule
	if isRouter {
		networkResourcesFirewallRules = a.GetPeerNetworkResourceFirewallRules(ctx, peer, validatedPeersMap, networkResourcesRoutes, resourcePolicies)
	}
	peersToConnectIncludingRouters := a.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, isRouter, sourcePeers)

	dnsManagementStatus := a.getPeerDNSManagementStatus(peerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var zones []nbdns.CustomZone

		if peersCustomZone.Domain != "" {
			records := filterZoneRecordsForPeers(peer, peersCustomZone, peersToConnectIncludingRouters, expiredPeers)
			zones = append(zones, nbdns.CustomZone{
				Domain:  peersCustomZone.Domain,
				Records: records,
			})
		}

		filteredAccountZones := filterPeerAppliedZones(ctx, accountZones, peerGroups)
		zones = append(zones, filteredAccountZones...)

		dnsUpdate.CustomZones = zones
		dnsUpdate.NameServerGroups = getPeerNSGroups(a, peerID)
	}

	nm := &NetworkMap{
		Peers:               peersToConnectIncludingRouters,
		Network:             a.Network.Copy(),
		Routes:              slices.Concat(networkResourcesRoutes, routesUpdate),
		DNSConfig:           dnsUpdate,
		OfflinePeers:        expiredPeers,
		FirewallRules:       firewallRules,
		RoutesFirewallRules: slices.Concat(networkResourcesFirewallRules, routesFirewallRules),
		AuthorizedUsers:     authorizedUsers,
		EnableSSH:           enableSSH,
	}

	if metrics != nil {
		objectCount := int64(len(peersToConnectIncludingRouters) + len(expiredPeers) + len(routesUpdate) + len(networkResourcesRoutes) + len(firewallRules) + +len(networkResourcesFirewallRules) + len(routesFirewallRules))
		metrics.CountNetworkMapObjects(objectCount)
		metrics.CountGetPeerNetworkMapDuration(time.Since(start))

		if objectCount > 5000 {
			log.WithContext(ctx).Tracef("account: %s has a total resource count of %d objects, "+
				"peers to connect: %d, expired peers: %d, routes: %d, firewall rules: %d, network resources routes: %d, network resources firewall rules: %d, routes firewall rules: %d",
				a.Id, objectCount, len(peersToConnectIncludingRouters), len(expiredPeers), len(routesUpdate), len(firewallRules), len(networkResourcesRoutes), len(networkResourcesFirewallRules), len(routesFirewallRules))
		}
	}

	return nm
}

func (a *Account) addNetworksRoutingPeers(
	networkResourcesRoutes []*route.Route,
	peer *nbpeer.Peer,
	peersToConnect []*nbpeer.Peer,
	expiredPeers []*nbpeer.Peer,
	isRouter bool,
	sourcePeers map[string]struct{},
) []*nbpeer.Peer {

	networkRoutesPeers := make(map[string]struct{}, len(networkResourcesRoutes))
	for _, r := range networkResourcesRoutes {
		networkRoutesPeers[r.PeerID] = struct{}{}
	}

	delete(sourcePeers, peer.ID)
	delete(networkRoutesPeers, peer.ID)

	for _, existingPeer := range peersToConnect {
		delete(sourcePeers, existingPeer.ID)
		delete(networkRoutesPeers, existingPeer.ID)
	}
	for _, expPeer := range expiredPeers {
		delete(sourcePeers, expPeer.ID)
		delete(networkRoutesPeers, expPeer.ID)
	}

	missingPeers := make(map[string]struct{}, len(sourcePeers)+len(networkRoutesPeers))
	if isRouter {
		for p := range sourcePeers {
			missingPeers[p] = struct{}{}
		}
	}
	for p := range networkRoutesPeers {
		missingPeers[p] = struct{}{}
	}

	for p := range missingPeers {
		if missingPeer := a.Peers[p]; missingPeer != nil {
			peersToConnect = append(peersToConnect, missingPeer)
		}
	}

	return peersToConnect
}

func getPeerNSGroups(account *Account, peerID string) []*nbdns.NameServerGroup {
	groupList := account.GetPeerGroups(peerID)

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

func AddPeerLabelsToAccount(ctx context.Context, account *Account, peerLabels LookupMap) {
	for _, peer := range account.Peers {
		label, err := GetPeerHostLabel(peer.Name, peerLabels)
		if err != nil {
			log.WithContext(ctx).Errorf("got an error while generating a peer host label. Peer name %s, error: %v. Trying with the peer's meta hostname", peer.Name, err)
			label, err = GetPeerHostLabel(peer.Meta.Hostname, peerLabels)
			if err != nil {
				log.WithContext(ctx).Errorf("got another error while generating a peer host label with hostname. Peer hostname %s, error: %v. Skipping", peer.Meta.Hostname, err)
				continue
			}
		}
		peer.DNSLabel = label
		peerLabels[label] = struct{}{}
	}
}

func GetPeerHostLabel(name string, peerLabels LookupMap) (string, error) {
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
func getUniqueHostLabel(name string, peerLabels LookupMap) string {
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

func (a *Account) GetPeersCustomZone(ctx context.Context, dnsDomain string) nbdns.CustomZone {
	var merr *multierror.Error

	if dnsDomain == "" {
		log.WithContext(ctx).Error("no dns domain is set, returning empty zone")
		return nbdns.CustomZone{}
	}

	customZone := nbdns.CustomZone{
		Domain:  dns.Fqdn(dnsDomain),
		Records: make([]nbdns.SimpleRecord, 0, len(a.Peers)),
	}

	domainSuffix := "." + dnsDomain

	var sb strings.Builder
	for _, peer := range a.Peers {
		if peer.DNSLabel == "" {
			merr = multierror.Append(merr, fmt.Errorf("peer %s has an empty DNS label", peer.Name))
			continue
		}

		sb.Grow(len(peer.DNSLabel) + len(domainSuffix))
		sb.WriteString(peer.DNSLabel)
		sb.WriteString(domainSuffix)

		customZone.Records = append(customZone.Records, nbdns.SimpleRecord{
			Name:  sb.String(),
			Type:  int(dns.TypeA),
			Class: nbdns.DefaultClass,
			TTL:   defaultTTL,
			RData: peer.IP.String(),
		})
		sb.Reset()

		for _, extraLabel := range peer.ExtraDNSLabels {
			sb.Grow(len(extraLabel) + len(domainSuffix))
			sb.WriteString(extraLabel)
			sb.WriteString(domainSuffix)

			customZone.Records = append(customZone.Records, nbdns.SimpleRecord{
				Name:  sb.String(),
				Type:  int(dns.TypeA),
				Class: nbdns.DefaultClass,
				TTL:   defaultTTL,
				RData: peer.IP.String(),
			})
			sb.Reset()
		}

	}

	go func() {
		if merr != nil {
			log.WithContext(ctx).Errorf("error generating custom zone for account %s: %v", a.Id, merr)
		}
	}()

	return customZone
}

// GetExpiredPeers returns peers that have been expired
func (a *Account) GetExpiredPeers() []*nbpeer.Peer {
	var peers []*nbpeer.Peer
	for _, peer := range a.GetPeersWithExpiration() {
		expired, _ := peer.LoginExpired(a.Settings.PeerLoginExpiration)
		if expired {
			peers = append(peers, peer)
		}
	}

	return peers
}

// GetNextPeerExpiration returns the minimum duration in which the next peer of the account will expire if it was found.
// If there is no peer that expires this function returns false and a duration of 0.
// This function only considers peers that haven't been expired yet and that are connected.
func (a *Account) GetNextPeerExpiration() (time.Duration, bool) {
	peersWithExpiry := a.GetPeersWithExpiration()
	if len(peersWithExpiry) == 0 {
		return 0, false
	}
	var nextExpiry *time.Duration
	for _, peer := range peersWithExpiry {
		// consider only connected peers because others will require login on connecting to the management server
		if peer.Status.LoginExpired || !peer.Status.Connected {
			continue
		}
		_, duration := peer.LoginExpired(a.Settings.PeerLoginExpiration)
		if nextExpiry == nil || duration < *nextExpiry {
			// if expiration is below 1s return 1s duration
			// this avoids issues with ticker that can't be set to < 0
			if duration < time.Second {
				return time.Second, true
			}
			nextExpiry = &duration
		}
	}

	if nextExpiry == nil {
		return 0, false
	}

	return *nextExpiry, true
}

// GetPeersWithExpiration returns a list of peers that have Peer.LoginExpirationEnabled set to true and that were added by a user
func (a *Account) GetPeersWithExpiration() []*nbpeer.Peer {
	peers := make([]*nbpeer.Peer, 0)
	for _, peer := range a.Peers {
		if peer.LoginExpirationEnabled && peer.AddedWithSSOLogin() {
			peers = append(peers, peer)
		}
	}
	return peers
}

// GetInactivePeers returns peers that have been expired by inactivity
func (a *Account) GetInactivePeers() []*nbpeer.Peer {
	var peers []*nbpeer.Peer
	for _, inactivePeer := range a.GetPeersWithInactivity() {
		inactive, _ := inactivePeer.SessionExpired(a.Settings.PeerInactivityExpiration)
		if inactive {
			peers = append(peers, inactivePeer)
		}
	}
	return peers
}

// GetNextInactivePeerExpiration returns the minimum duration in which the next peer of the account will expire if it was found.
// If there is no peer that expires this function returns false and a duration of 0.
// This function only considers peers that haven't been expired yet and that are not connected.
func (a *Account) GetNextInactivePeerExpiration() (time.Duration, bool) {
	peersWithExpiry := a.GetPeersWithInactivity()
	if len(peersWithExpiry) == 0 {
		return 0, false
	}
	var nextExpiry *time.Duration
	for _, peer := range peersWithExpiry {
		if peer.Status.LoginExpired || peer.Status.Connected {
			continue
		}
		_, duration := peer.SessionExpired(a.Settings.PeerInactivityExpiration)
		if nextExpiry == nil || duration < *nextExpiry {
			// if expiration is below 1s return 1s duration
			// this avoids issues with ticker that can't be set to < 0
			if duration < time.Second {
				return time.Second, true
			}
			nextExpiry = &duration
		}
	}

	if nextExpiry == nil {
		return 0, false
	}

	return *nextExpiry, true
}

// GetPeersWithInactivity eturns a list of peers that have Peer.InactivityExpirationEnabled set to true and that were added by a user
func (a *Account) GetPeersWithInactivity() []*nbpeer.Peer {
	peers := make([]*nbpeer.Peer, 0)
	for _, peer := range a.Peers {
		if peer.InactivityExpirationEnabled && peer.AddedWithSSOLogin() {
			peers = append(peers, peer)
		}
	}
	return peers
}

// GetPeers returns a list of all Account peers
func (a *Account) GetPeers() []*nbpeer.Peer {
	var peers []*nbpeer.Peer
	for _, peer := range a.Peers {
		peers = append(peers, peer)
	}
	return peers
}

// UpdateSettings saves new account settings
func (a *Account) UpdateSettings(update *Settings) *Account {
	a.Settings = update.Copy()
	return a
}

// UpdatePeer saves new or replaces existing peer
func (a *Account) UpdatePeer(update *nbpeer.Peer) {
	a.Peers[update.ID] = update
}

// DeletePeer deletes peer from the account cleaning up all the references
func (a *Account) DeletePeer(peerID string) {
	// delete peer from groups
	for _, g := range a.Groups {
		for i, pk := range g.Peers {
			if pk == peerID {
				g.Peers = append(g.Peers[:i], g.Peers[i+1:]...)
				break
			}
		}
	}

	for _, r := range a.Routes {
		if r.Peer == peerID {
			r.Enabled = false
			r.Peer = ""
		}
	}

	for i, r := range a.NetworkRouters {
		if r.Peer == peerID {
			a.NetworkRouters = append(a.NetworkRouters[:i], a.NetworkRouters[i+1:]...)
			break
		}
	}

	delete(a.Peers, peerID)
	a.Network.IncSerial()
}

func (a *Account) DeleteResource(resourceID string) {
	// delete resource from groups
	for _, g := range a.Groups {
		for i, pk := range g.Resources {
			if pk.ID == resourceID {
				g.Resources = append(g.Resources[:i], g.Resources[i+1:]...)
				break
			}
		}
	}
}

// FindPeerByPubKey looks for a Peer by provided WireGuard public key in the Account or returns error if it wasn't found.
// It will return an object copy of the peer.
func (a *Account) FindPeerByPubKey(peerPubKey string) (*nbpeer.Peer, error) {
	for _, peer := range a.Peers {
		if peer.Key == peerPubKey {
			return peer.Copy(), nil
		}
	}

	return nil, status.Errorf(status.NotFound, "peer with the public key %s not found", peerPubKey)
}

// FindUserPeers returns a list of peers that user owns (created)
func (a *Account) FindUserPeers(userID string) ([]*nbpeer.Peer, error) {
	peers := make([]*nbpeer.Peer, 0)
	for _, peer := range a.Peers {
		if peer.UserID == userID {
			peers = append(peers, peer)
		}
	}

	return peers, nil
}

// FindUser looks for a given user in the Account or returns error if user wasn't found.
func (a *Account) FindUser(userID string) (*User, error) {
	user := a.Users[userID]
	if user == nil {
		return nil, status.Errorf(status.NotFound, "user %s not found", userID)
	}

	return user, nil
}

// FindGroupByName looks for a given group in the Account by name or returns error if the group wasn't found.
func (a *Account) FindGroupByName(groupName string) (*Group, error) {
	for _, group := range a.Groups {
		if group.Name == groupName {
			return group, nil
		}
	}
	return nil, status.Errorf(status.NotFound, "group %s not found", groupName)
}

// FindSetupKey looks for a given SetupKey in the Account or returns error if it wasn't found.
func (a *Account) FindSetupKey(setupKey string) (*SetupKey, error) {
	key := a.SetupKeys[setupKey]
	if key == nil {
		return nil, status.Errorf(status.NotFound, "setup key not found")
	}

	return key, nil
}

// GetPeerGroupsList return with the list of groups ID.
func (a *Account) GetPeerGroupsList(peerID string) []string {
	var grps []string
	for groupID, group := range a.Groups {
		for _, id := range group.Peers {
			if id == peerID {
				grps = append(grps, groupID)
				break
			}
		}
	}
	return grps
}

func (a *Account) getPeerDNSManagementStatus(peerID string) bool {
	peerGroups := a.GetPeerGroups(peerID)
	enabled := true
	for _, groupID := range a.DNSSettings.DisabledManagementGroups {
		_, found := peerGroups[groupID]
		if found {
			enabled = false
			break
		}
	}
	return enabled
}

func (a *Account) GetPeerGroups(peerID string) LookupMap {
	groupList := make(LookupMap)
	for groupID, group := range a.Groups {
		for _, id := range group.Peers {
			if id == peerID {
				groupList[groupID] = struct{}{}
				break
			}
		}
	}
	return groupList
}

func (a *Account) GetTakenIPs() []net.IP {
	var takenIps []net.IP
	for _, existingPeer := range a.Peers {
		takenIps = append(takenIps, existingPeer.IP)
	}

	return takenIps
}

func (a *Account) GetPeerDNSLabels() LookupMap {
	existingLabels := make(LookupMap)
	for _, peer := range a.Peers {
		if peer.DNSLabel != "" {
			existingLabels[peer.DNSLabel] = struct{}{}
		}
	}
	return existingLabels
}

func (a *Account) Copy() *Account {
	peers := map[string]*nbpeer.Peer{}
	for id, peer := range a.Peers {
		peers[id] = peer.Copy()
	}

	users := map[string]*User{}
	for id, user := range a.Users {
		users[id] = user.Copy()
	}

	setupKeys := map[string]*SetupKey{}
	for id, key := range a.SetupKeys {
		setupKeys[id] = key.Copy()
	}

	groups := map[string]*Group{}
	for id, group := range a.Groups {
		groups[id] = group.Copy()
	}

	policies := []*Policy{}
	for _, policy := range a.Policies {
		policies = append(policies, policy.Copy())
	}

	routes := map[route.ID]*route.Route{}
	for id, r := range a.Routes {
		routes[id] = r.Copy()
	}

	nsGroups := map[string]*nbdns.NameServerGroup{}
	for id, nsGroup := range a.NameServerGroups {
		nsGroups[id] = nsGroup.Copy()
	}

	dnsSettings := a.DNSSettings.Copy()

	var settings *Settings
	if a.Settings != nil {
		settings = a.Settings.Copy()
	}

	postureChecks := []*posture.Checks{}
	for _, postureCheck := range a.PostureChecks {
		postureChecks = append(postureChecks, postureCheck.Copy())
	}

	nets := []*networkTypes.Network{}
	for _, network := range a.Networks {
		nets = append(nets, network.Copy())
	}

	networkRouters := []*routerTypes.NetworkRouter{}
	for _, router := range a.NetworkRouters {
		networkRouters = append(networkRouters, router.Copy())
	}

	networkResources := []*resourceTypes.NetworkResource{}
	for _, resource := range a.NetworkResources {
		networkResources = append(networkResources, resource.Copy())
	}

	services := []*reverseproxy.Service{}
	for _, service := range a.Services {
		services = append(services, service.Copy())
	}

	return &Account{
		Id:                     a.Id,
		CreatedBy:              a.CreatedBy,
		CreatedAt:              a.CreatedAt,
		Domain:                 a.Domain,
		DomainCategory:         a.DomainCategory,
		IsDomainPrimaryAccount: a.IsDomainPrimaryAccount,
		SetupKeys:              setupKeys,
		Network:                a.Network.Copy(),
		Peers:                  peers,
		Users:                  users,
		Groups:                 groups,
		Policies:               policies,
		Routes:                 routes,
		NameServerGroups:       nsGroups,
		DNSSettings:            dnsSettings,
		PostureChecks:          postureChecks,
		Settings:               settings,
		Networks:               nets,
		NetworkRouters:         networkRouters,
		NetworkResources:       networkResources,
		Services:               services,
		Onboarding:             a.Onboarding,
		NetworkMapCache:        a.NetworkMapCache,
		nmapInitOnce:           a.nmapInitOnce,
	}
}

func (a *Account) GetMeta() *AccountMeta {
	return &AccountMeta{
		AccountID:      a.Id,
		CreatedBy:      a.CreatedBy,
		CreatedAt:      a.CreatedAt,
		Domain:         a.Domain,
		DomainCategory: a.DomainCategory,
	}
}

func (a *Account) GetGroupAll() (*Group, error) {
	for _, g := range a.Groups {
		if g.Name == "All" {
			return g, nil
		}
	}
	return nil, fmt.Errorf("no group ALL found")
}

// GetPeer looks up a Peer by ID
func (a *Account) GetPeer(peerID string) *nbpeer.Peer {
	return a.Peers[peerID]
}

// UserGroupsAddToPeers adds groups to all peers of user
func (a *Account) UserGroupsAddToPeers(userID string, groups ...string) map[string][]string {
	groupUpdates := make(map[string][]string)

	userPeers := make(map[string]struct{})
	for pid, peer := range a.Peers {
		if peer.UserID == userID {
			userPeers[pid] = struct{}{}
		}
	}

	for _, gid := range groups {
		group, ok := a.Groups[gid]
		if !ok {
			continue
		}

		oldPeers := group.Peers

		groupPeers := make(map[string]struct{})
		for _, pid := range group.Peers {
			groupPeers[pid] = struct{}{}
		}

		for pid := range userPeers {
			groupPeers[pid] = struct{}{}
		}

		group.Peers = group.Peers[:0]
		for pid := range groupPeers {
			group.Peers = append(group.Peers, pid)
		}

		groupUpdates[gid] = util.Difference(group.Peers, oldPeers)
	}

	return groupUpdates
}

// UserGroupsRemoveFromPeers removes groups from all peers of user
func (a *Account) UserGroupsRemoveFromPeers(userID string, groups ...string) map[string][]string {
	groupUpdates := make(map[string][]string)

	for _, gid := range groups {
		group, ok := a.Groups[gid]
		if !ok || group.Name == "All" {
			continue
		}

		oldPeers := group.Peers

		update := make([]string, 0, len(group.Peers))
		for _, pid := range group.Peers {
			peer, ok := a.Peers[pid]
			if !ok {
				continue
			}
			if peer.UserID != userID {
				update = append(update, pid)
			}
		}
		group.Peers = update
		groupUpdates[gid] = util.Difference(oldPeers, group.Peers)
	}

	return groupUpdates
}

// GetPeerConnectionResources for a given peer
//
// This function returns the list of peers and firewall rules that are applicable to a given peer.
func (a *Account) GetPeerConnectionResources(ctx context.Context, peer *nbpeer.Peer, validatedPeersMap map[string]struct{}, groupIDToUserIDs map[string][]string) ([]*nbpeer.Peer, []*FirewallRule, map[string]map[string]struct{}, bool) {
	generateResources, getAccumulatedResources := a.connResourcesGenerator(ctx, peer)
	authorizedUsers := make(map[string]map[string]struct{}) // machine user to list of userIDs
	sshEnabled := false

	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			var sourcePeers, destinationPeers []*nbpeer.Peer
			var peerInSources, peerInDestinations bool

			if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
				sourcePeers, peerInSources = a.getPeerFromResource(rule.SourceResource, peer.ID)
			} else {
				sourcePeers, peerInSources = a.getAllPeersFromGroups(ctx, rule.Sources, peer.ID, policy.SourcePostureChecks, validatedPeersMap)
			}

			if rule.DestinationResource.Type == ResourceTypePeer && rule.DestinationResource.ID != "" {
				destinationPeers, peerInDestinations = a.getPeerFromResource(rule.DestinationResource, peer.ID)
			} else {
				destinationPeers, peerInDestinations = a.getAllPeersFromGroups(ctx, rule.Destinations, peer.ID, nil, validatedPeersMap)
			}

			if rule.Bidirectional {
				if peerInSources {
					generateResources(rule, destinationPeers, FirewallRuleDirectionIN)
				}
				if peerInDestinations {
					generateResources(rule, sourcePeers, FirewallRuleDirectionOUT)
				}
			}

			if peerInSources {
				generateResources(rule, destinationPeers, FirewallRuleDirectionOUT)
			}

			if peerInDestinations {
				generateResources(rule, sourcePeers, FirewallRuleDirectionIN)
			}

			if peerInDestinations && rule.Protocol == PolicyRuleProtocolNetbirdSSH {
				sshEnabled = true
				switch {
				case len(rule.AuthorizedGroups) > 0:
					for groupID, localUsers := range rule.AuthorizedGroups {
						userIDs, ok := groupIDToUserIDs[groupID]
						if !ok {
							log.WithContext(ctx).Tracef("no user IDs found for group ID %s", groupID)
							continue
						}

						if len(localUsers) == 0 {
							localUsers = []string{auth.Wildcard}
						}

						for _, localUser := range localUsers {
							if authorizedUsers[localUser] == nil {
								authorizedUsers[localUser] = make(map[string]struct{})
							}
							for _, userID := range userIDs {
								authorizedUsers[localUser][userID] = struct{}{}
							}
						}
					}
				case rule.AuthorizedUser != "":
					if authorizedUsers[auth.Wildcard] == nil {
						authorizedUsers[auth.Wildcard] = make(map[string]struct{})
					}
					authorizedUsers[auth.Wildcard][rule.AuthorizedUser] = struct{}{}
				default:
					authorizedUsers[auth.Wildcard] = a.getAllowedUserIDs()
				}
			} else if peerInDestinations && policyRuleImpliesLegacySSH(rule) && peer.SSHEnabled {
				sshEnabled = true
				authorizedUsers[auth.Wildcard] = a.getAllowedUserIDs()
			}
		}
	}

	peers, fwRules := getAccumulatedResources()
	return peers, fwRules, authorizedUsers, sshEnabled
}

func (a *Account) getAllowedUserIDs() map[string]struct{} {
	users := make(map[string]struct{})
	for _, nbUser := range a.Users {
		if !nbUser.IsBlocked() && !nbUser.IsServiceUser {
			users[nbUser.Id] = struct{}{}
		}
	}
	return users
}

// connResourcesGenerator returns generator and accumulator function which returns the result of generator calls
//
// The generator function is used to generate the list of peers and firewall rules that are applicable to a given peer.
// It safe to call the generator function multiple times for same peer and different rules no duplicates will be
// generated. The accumulator function returns the result of all the generator calls.
func (a *Account) connResourcesGenerator(ctx context.Context, targetPeer *nbpeer.Peer) (func(*PolicyRule, []*nbpeer.Peer, int), func() ([]*nbpeer.Peer, []*FirewallRule)) {
	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	rules := make([]*FirewallRule, 0)
	peers := make([]*nbpeer.Peer, 0)

	return func(rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int) {
			for _, peer := range groupPeers {
				if peer == nil {
					continue
				}

				if _, ok := peersExists[peer.ID]; !ok {
					peers = append(peers, peer)
					peersExists[peer.ID] = struct{}{}
				}

				protocol := rule.Protocol
				if protocol == PolicyRuleProtocolNetbirdSSH {
					protocol = PolicyRuleProtocolTCP
				}

				fr := FirewallRule{
					PolicyID:  rule.ID,
					PeerIP:    peer.IP.String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(protocol),
				}

				ruleID := rule.ID + fr.PeerIP + strconv.Itoa(direction) +
					fr.Protocol + fr.Action + strings.Join(rule.Ports, ",")
				if _, ok := rulesExists[ruleID]; ok {
					continue
				}
				rulesExists[ruleID] = struct{}{}

				if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
					rules = append(rules, &fr)
					continue
				}

				rules = append(rules, expandPortsAndRanges(fr, rule, targetPeer)...)
			}
		}, func() ([]*nbpeer.Peer, []*FirewallRule) {
			return peers, rules
		}
}

func policyRuleImpliesLegacySSH(rule *PolicyRule) bool {
	return rule.Protocol == PolicyRuleProtocolALL || (rule.Protocol == PolicyRuleProtocolTCP && (portsIncludesSSH(rule.Ports) || portRangeIncludesSSH(rule.PortRanges)))
}

func portRangeIncludesSSH(portRanges []RulePortRange) bool {
	for _, pr := range portRanges {
		if (pr.Start <= defaultSSHPortNumber && pr.End >= defaultSSHPortNumber) || (pr.Start <= nativeSSHPortNumber && pr.End >= nativeSSHPortNumber) {
			return true
		}
	}
	return false
}

func portsIncludesSSH(ports []string) bool {
	for _, port := range ports {
		if port == defaultSSHPortString || port == nativeSSHPortString {
			return true
		}
	}
	return false
}

// getAllPeersFromGroups for given peer ID and list of groups
//
// Returns a list of peers from specified groups that pass specified posture checks
// and a boolean indicating if the supplied peer ID exists within these groups.
//
// Important: Posture checks are applicable only to source group peers,
// for destination group peers, call this method with an empty list of sourcePostureChecksIDs
func (a *Account) getAllPeersFromGroups(ctx context.Context, groups []string, peerID string, sourcePostureChecksIDs []string, validatedPeersMap map[string]struct{}) ([]*nbpeer.Peer, bool) {
	peerInGroups := false
	uniquePeerIDs := a.getUniquePeerIDsFromGroupsIDs(ctx, groups)
	filteredPeers := make([]*nbpeer.Peer, 0, len(uniquePeerIDs))
	for _, p := range uniquePeerIDs {
		peer, ok := a.Peers[p]
		if !ok || peer == nil || peer.ProxyMeta.Embedded {
			continue
		}

		// validate the peer based on policy posture checks applied
		isValid := a.validatePostureChecksOnPeer(ctx, sourcePostureChecksIDs, peer.ID)
		if !isValid {
			continue
		}

		if _, ok := validatedPeersMap[peer.ID]; !ok {
			continue
		}

		if peer.ID == peerID {
			peerInGroups = true
			continue
		}

		filteredPeers = append(filteredPeers, peer)
	}

	return filteredPeers, peerInGroups
}

func (a *Account) getPeerFromResource(resource Resource, peerID string) ([]*nbpeer.Peer, bool) {
	peer := a.GetPeer(resource.ID)
	if peer == nil {
		return []*nbpeer.Peer{}, false
	}

	if peer.ID == peerID {
		return []*nbpeer.Peer{}, true
	}

	return []*nbpeer.Peer{peer}, false
}

// validatePostureChecksOnPeer validates the posture checks on a peer
func (a *Account) validatePostureChecksOnPeer(ctx context.Context, sourcePostureChecksID []string, peerID string) bool {
	peer, ok := a.Peers[peerID]
	if !ok && peer == nil {
		return false
	}

	for _, postureChecksID := range sourcePostureChecksID {
		postureChecks := a.GetPostureChecks(postureChecksID)
		if postureChecks == nil {
			continue
		}

		for _, check := range postureChecks.GetChecks() {
			isValid, err := check.Check(ctx, *peer)
			if err != nil {
				log.WithContext(ctx).Debugf("an error occurred check %s: on peer: %s :%s", check.Name(), peer.ID, err.Error())
			}
			if !isValid {
				return false
			}
		}
	}
	return true
}

func (a *Account) GetPostureChecks(postureChecksID string) *posture.Checks {
	for _, postureChecks := range a.PostureChecks {
		if postureChecks.ID == postureChecksID {
			return postureChecks
		}
	}
	return nil
}

// GetPeerRoutesFirewallRules gets the routes firewall rules associated with a routing peer ID for the account.
func (a *Account) GetPeerRoutesFirewallRules(ctx context.Context, peerID string, validatedPeersMap map[string]struct{}) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0, len(a.Routes))

	enabledRoutes, _ := a.getRoutingPeerRoutes(ctx, peerID)
	for _, route := range enabledRoutes {
		// If no access control groups are specified, accept all traffic.
		if len(route.AccessControlGroups) == 0 {
			defaultPermit := getDefaultPermit(route)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		distributionPeers := a.getDistributionGroupsPeers(route)

		for _, accessGroup := range route.AccessControlGroups {
			policies := GetAllRoutePoliciesFromGroups(a, []string{accessGroup})
			rules := a.getRouteFirewallRules(ctx, peerID, policies, route, validatedPeersMap, distributionPeers)
			routesFirewallRules = append(routesFirewallRules, rules...)
		}
	}

	return routesFirewallRules
}

func (a *Account) getRouteFirewallRules(ctx context.Context, peerID string, policies []*Policy, route *route.Route, validatedPeersMap map[string]struct{}, distributionPeers map[string]struct{}) []*RouteFirewallRule {
	var fwRules []*RouteFirewallRule
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			rulePeers := a.getRulePeers(rule, policy.SourcePostureChecks, peerID, distributionPeers, validatedPeersMap)
			rules := generateRouteFirewallRules(ctx, route, rule, rulePeers, FirewallRuleDirectionIN)
			fwRules = append(fwRules, rules...)
		}
	}
	return fwRules
}

func (a *Account) getRulePeers(rule *PolicyRule, postureChecks []string, peerID string, distributionPeers map[string]struct{}, validatedPeersMap map[string]struct{}) []*nbpeer.Peer {
	distPeersWithPolicy := make(map[string]struct{})
	for _, id := range rule.Sources {
		group := a.Groups[id]
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			if pID == peerID {
				continue
			}
			_, distPeer := distributionPeers[pID]
			_, valid := validatedPeersMap[pID]
			if distPeer && valid && a.validatePostureChecksOnPeer(context.Background(), postureChecks, pID) {
				distPeersWithPolicy[pID] = struct{}{}
			}
		}
	}
	if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
		_, distPeer := distributionPeers[rule.SourceResource.ID]
		_, valid := validatedPeersMap[rule.SourceResource.ID]
		if distPeer && valid && a.validatePostureChecksOnPeer(context.Background(), postureChecks, rule.SourceResource.ID) {
			distPeersWithPolicy[rule.SourceResource.ID] = struct{}{}
		}
	}

	distributionGroupPeers := make([]*nbpeer.Peer, 0, len(distPeersWithPolicy))
	for pID := range distPeersWithPolicy {
		peer := a.Peers[pID]
		if peer == nil {
			continue
		}
		distributionGroupPeers = append(distributionGroupPeers, peer)
	}
	return distributionGroupPeers
}

func (a *Account) getDistributionGroupsPeers(route *route.Route) map[string]struct{} {
	distPeers := make(map[string]struct{})
	for _, id := range route.Groups {
		group := a.Groups[id]
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			distPeers[pID] = struct{}{}
		}
	}
	return distPeers
}

func getDefaultPermit(route *route.Route) []*RouteFirewallRule {
	var rules []*RouteFirewallRule

	sources := []string{"0.0.0.0/0"}
	if route.Network.Addr().Is6() {
		sources = []string{"::/0"}
	}
	rule := RouteFirewallRule{
		SourceRanges: sources,
		Action:       string(PolicyTrafficActionAccept),
		Destination:  route.Network.String(),
		Protocol:     string(PolicyRuleProtocolALL),
		Domains:      route.Domains,
		IsDynamic:    route.IsDynamic(),
		RouteID:      route.ID,
	}

	rules = append(rules, &rule)

	// dynamic routes always contain an IPv4 placeholder as destination, hence we must add IPv6 rules additionally
	if route.IsDynamic() {
		ruleV6 := rule
		ruleV6.SourceRanges = []string{"::/0"}
		rules = append(rules, &ruleV6)
	}

	return rules
}

// GetAllRoutePoliciesFromGroups retrieves route policies associated with the specified access control groups
// and returns a list of policies that have rules with destinations matching the specified groups.
func GetAllRoutePoliciesFromGroups(account *Account, accessControlGroups []string) []*Policy {
	routePolicies := make([]*Policy, 0)
	for _, groupID := range accessControlGroups {
		group, ok := account.Groups[groupID]
		if !ok {
			continue
		}

		for _, policy := range account.Policies {
			for _, rule := range policy.Rules {
				exist := slices.ContainsFunc(rule.Destinations, func(groupID string) bool {
					return groupID == group.ID
				})
				if exist {
					routePolicies = append(routePolicies, policy)
					continue
				}
			}
		}
	}

	return routePolicies
}

// GetPeerNetworkResourceFirewallRules gets the network resources firewall rules associated with a routing peer ID for the account.
func (a *Account) GetPeerNetworkResourceFirewallRules(ctx context.Context, peer *nbpeer.Peer, validatedPeersMap map[string]struct{}, routes []*route.Route, resourcePolicies map[string][]*Policy) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	for _, route := range routes {
		if route.Peer != peer.Key {
			continue
		}
		resourceAppliedPolicies := resourcePolicies[string(route.GetResourceID())]
		distributionPeers := getPoliciesSourcePeers(resourceAppliedPolicies, a.Groups)

		rules := a.getRouteFirewallRules(ctx, peer.ID, resourceAppliedPolicies, route, validatedPeersMap, distributionPeers)
		for _, rule := range rules {
			if len(rule.SourceRanges) > 0 {
				routesFirewallRules = append(routesFirewallRules, rule)
			}
		}
	}

	return routesFirewallRules
}

// getNetworkResourceGroups retrieves all groups associated with the given network resource.
func (a *Account) getNetworkResourceGroups(resourceID string) []*Group {
	var networkResourceGroups []*Group

	for _, group := range a.Groups {
		for _, resource := range group.Resources {
			if resource.ID == resourceID {
				networkResourceGroups = append(networkResourceGroups, group)
			}
		}
	}

	return networkResourceGroups
}

// GetResourcePoliciesMap returns a map of networks resource IDs and their associated policies.
func (a *Account) GetResourcePoliciesMap() map[string][]*Policy {
	resourcePolicies := make(map[string][]*Policy)
	for _, resource := range a.NetworkResources {
		if !resource.Enabled {
			continue
		}

		resourceAppliedPolicies := a.GetPoliciesForNetworkResource(resource.ID)
		resourcePolicies[resource.ID] = resourceAppliedPolicies
	}
	return resourcePolicies
}

// GetNetworkResourcesRoutesToSync returns network routes for syncing with a specific peer and its ACL peers.
func (a *Account) GetNetworkResourcesRoutesToSync(ctx context.Context, peerID string, resourcePolicies map[string][]*Policy, routers map[string]map[string]*routerTypes.NetworkRouter) (bool, []*route.Route, map[string]struct{}) {
	var isRoutingPeer bool
	var routes []*route.Route
	allSourcePeers := make(map[string]struct{}, len(a.Peers))

	for _, resource := range a.NetworkResources {
		if !resource.Enabled {
			continue
		}

		var addSourcePeers bool

		networkRoutingPeers, exists := routers[resource.NetworkID]
		if exists {
			if router, ok := networkRoutingPeers[peerID]; ok {
				isRoutingPeer, addSourcePeers = true, true
				routes = append(routes, a.getNetworkResourcesRoutes(resource, peerID, router, resourcePolicies)...)
			}
		}

		addedResourceRoute := false
		for _, policy := range resourcePolicies[resource.ID] {
			var peers []string
			if policy.Rules[0].SourceResource.Type == ResourceTypePeer && policy.Rules[0].SourceResource.ID != "" {
				peers = []string{policy.Rules[0].SourceResource.ID}
			} else {
				peers = a.getUniquePeerIDsFromGroupsIDs(ctx, policy.SourceGroups())
			}
			if addSourcePeers {
				for _, pID := range a.getPostureValidPeers(peers, policy.SourcePostureChecks) {
					allSourcePeers[pID] = struct{}{}
				}
			} else if slices.Contains(peers, peerID) && a.validatePostureChecksOnPeer(ctx, policy.SourcePostureChecks, peerID) {
				// add routes for the resource if the peer is in the distribution group
				for peerId, router := range networkRoutingPeers {
					routes = append(routes, a.getNetworkResourcesRoutes(resource, peerId, router, resourcePolicies)...)
				}
				addedResourceRoute = true
			}
			if addedResourceRoute {
				break
			}
		}
	}

	return isRoutingPeer, routes, allSourcePeers
}

func (a *Account) getPostureValidPeers(inputPeers []string, postureChecksIDs []string) []string {
	var dest []string
	for _, peerID := range inputPeers {
		if a.validatePostureChecksOnPeer(context.Background(), postureChecksIDs, peerID) {
			dest = append(dest, peerID)
		}
	}
	return dest
}

func (a *Account) getUniquePeerIDsFromGroupsIDs(ctx context.Context, groups []string) []string {
	peerIDs := make(map[string]struct{}, len(groups)) // we expect at least one peer per group as initial capacity
	for _, groupID := range groups {
		group := a.GetGroup(groupID)
		if group == nil {
			log.WithContext(ctx).Warnf("group %s doesn't exist under account %s, will continue map generation without it", groupID, a.Id)
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			return group.Peers
		}

		for _, peerID := range group.Peers {
			peerIDs[peerID] = struct{}{}
		}
	}

	ids := make([]string, 0, len(peerIDs))
	for peerID := range peerIDs {
		ids = append(ids, peerID)
	}

	return ids
}

// getNetworkResources filters and returns a list of network resources associated with the given network ID.
func (a *Account) getNetworkResources(networkID string) []*resourceTypes.NetworkResource {
	var resources []*resourceTypes.NetworkResource
	for _, resource := range a.NetworkResources {
		if resource.NetworkID == networkID {
			resources = append(resources, resource)
		}
	}
	return resources
}

// GetPoliciesForNetworkResource retrieves the list of policies that apply to a specific network resource.
// A policy is deemed applicable if its destination groups include any of the given network resource groups
// or if its destination resource explicitly matches the provided resource.
func (a *Account) GetPoliciesForNetworkResource(resourceId string) []*Policy {
	var resourceAppliedPolicies []*Policy

	networkResourceGroups := a.getNetworkResourceGroups(resourceId)

	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			if rule.DestinationResource.ID == resourceId {
				resourceAppliedPolicies = append(resourceAppliedPolicies, policy)
				break
			}

			for _, group := range networkResourceGroups {
				if slices.Contains(rule.Destinations, group.ID) {
					resourceAppliedPolicies = append(resourceAppliedPolicies, policy)
					break
				}
			}
		}
	}

	return resourceAppliedPolicies
}

func (a *Account) GetPoliciesAppliedInNetwork(networkID string) []string {
	networkResources := a.getNetworkResources(networkID)

	policiesIDs := map[string]struct{}{}
	for _, resource := range networkResources {
		resourceAppliedPolicies := a.GetPoliciesForNetworkResource(resource.ID)
		for _, policy := range resourceAppliedPolicies {
			policiesIDs[policy.ID] = struct{}{}
		}
	}

	result := make([]string, 0, len(policiesIDs))
	for id := range policiesIDs {
		result = append(result, id)
	}

	return result
}

// getNetworkResourcesRoutes convert the network resources list to routes list.
func (a *Account) getNetworkResourcesRoutes(resource *resourceTypes.NetworkResource, peerId string, router *routerTypes.NetworkRouter, resourcePolicies map[string][]*Policy) []*route.Route {
	resourceAppliedPolicies := resourcePolicies[resource.ID]

	var routes []*route.Route
	// distribute the resource routes only if there is policy applied to it
	if len(resourceAppliedPolicies) > 0 {
		peer := a.GetPeer(peerId)
		if peer != nil {
			routes = append(routes, resource.ToRoute(peer, router))
		}
	}

	return routes
}

func (a *Account) GetResourceRoutersMap() map[string]map[string]*routerTypes.NetworkRouter {
	routers := make(map[string]map[string]*routerTypes.NetworkRouter)

	for _, router := range a.NetworkRouters {
		if !router.Enabled {
			continue
		}

		if routers[router.NetworkID] == nil {
			routers[router.NetworkID] = make(map[string]*routerTypes.NetworkRouter)
		}

		if router.Peer != "" {
			routers[router.NetworkID][router.Peer] = router
			continue
		}

		for _, peerGroup := range router.PeerGroups {
			g := a.Groups[peerGroup]
			if g != nil {
				for _, peerID := range g.Peers {
					routers[router.NetworkID][peerID] = router
				}
			}
		}
	}

	return routers
}

// getPoliciesSourcePeers collects all unique peers from the source groups defined in the given policies.
func getPoliciesSourcePeers(policies []*Policy, groups map[string]*Group) map[string]struct{} {
	sourcePeers := make(map[string]struct{})

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			for _, sourceGroup := range rule.Sources {
				group := groups[sourceGroup]
				if group == nil {
					continue
				}

				for _, peer := range group.Peers {
					sourcePeers[peer] = struct{}{}
				}
			}

			if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
				sourcePeers[rule.SourceResource.ID] = struct{}{}
			}
		}
	}

	return sourcePeers
}

// AddAllGroup to account object if it doesn't exist
func (a *Account) AddAllGroup(disableDefaultPolicy bool) error {
	if len(a.Groups) == 0 {
		allGroup := &Group{
			ID:     xid.New().String(),
			Name:   "All",
			Issued: GroupIssuedAPI,
		}
		for _, peer := range a.Peers {
			allGroup.Peers = append(allGroup.Peers, peer.ID)
		}
		a.Groups = map[string]*Group{allGroup.ID: allGroup}

		if disableDefaultPolicy {
			return nil
		}

		id := xid.New().String()

		defaultPolicy := &Policy{
			ID:          id,
			Name:        DefaultRuleName,
			Description: DefaultRuleDescription,
			Enabled:     true,
			Rules: []*PolicyRule{
				{
					ID:            id,
					Name:          DefaultRuleName,
					Description:   DefaultRuleDescription,
					Enabled:       true,
					Sources:       []string{allGroup.ID},
					Destinations:  []string{allGroup.ID},
					Bidirectional: true,
					Protocol:      PolicyRuleProtocolALL,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		a.Policies = []*Policy{defaultPolicy}
	}
	return nil
}

func (a *Account) GetActiveGroupUsers() map[string][]string {
	allGroupID := ""
	group, err := a.GetGroupAll()
	if err != nil {
		log.Errorf("failed to get group all: %v", err)
	} else {
		allGroupID = group.ID
	}
	groups := make(map[string][]string, len(a.GroupsG))
	for _, user := range a.Users {
		if !user.IsBlocked() && !user.IsServiceUser {
			for _, groupID := range user.AutoGroups {
				groups[groupID] = append(groups[groupID], user.Id)
			}
			groups[allGroupID] = append(groups[allGroupID], user.Id)
		}
	}
	return groups
}

func (a *Account) GetProxyPeers() map[string][]*nbpeer.Peer {
	proxyPeers := make(map[string][]*nbpeer.Peer)
	for _, peer := range a.Peers {
		if peer.ProxyMeta.Embedded {
			proxyPeers[peer.ProxyMeta.Cluster] = append(proxyPeers[peer.ProxyMeta.Cluster], peer)
		}
	}
	return proxyPeers
}

func (a *Account) InjectProxyPolicies(ctx context.Context) {
	if len(a.Services) == 0 {
		return
	}

	proxyPeersByCluster := a.GetProxyPeers()
	if len(proxyPeersByCluster) == 0 {
		return
	}

	for _, service := range a.Services {
		if !service.Enabled {
			continue
		}
		a.injectServiceProxyPolicies(ctx, service, proxyPeersByCluster)
	}
}

func (a *Account) injectServiceProxyPolicies(ctx context.Context, service *reverseproxy.Service, proxyPeersByCluster map[string][]*nbpeer.Peer) {
	for _, target := range service.Targets {
		if !target.Enabled {
			continue
		}
		a.injectTargetProxyPolicies(ctx, service, target, proxyPeersByCluster[service.ProxyCluster])
	}
}

func (a *Account) injectTargetProxyPolicies(ctx context.Context, service *reverseproxy.Service, target *reverseproxy.Target, proxyPeers []*nbpeer.Peer) {
	port, ok := a.resolveTargetPort(ctx, target)
	if !ok {
		return
	}

	path := ""
	if target.Path != nil {
		path = *target.Path
	}

	for _, proxyPeer := range proxyPeers {
		policy := a.createProxyPolicy(service, target, proxyPeer, port, path)
		a.Policies = append(a.Policies, policy)
	}
}

func (a *Account) resolveTargetPort(ctx context.Context, target *reverseproxy.Target) (int, bool) {
	if target.Port != 0 {
		return target.Port, true
	}

	switch target.Protocol {
	case "https":
		return 443, true
	case "http":
		return 80, true
	default:
		log.WithContext(ctx).Warnf("unsupported protocol %s for proxy target %s, skipping policy injection", target.Protocol, target.TargetId)
		return 0, false
	}
}

func (a *Account) createProxyPolicy(service *reverseproxy.Service, target *reverseproxy.Target, proxyPeer *nbpeer.Peer, port int, path string) *Policy {
	policyID := fmt.Sprintf("proxy-access-%s-%s-%s", service.ID, proxyPeer.ID, path)
	return &Policy{
		ID:      policyID,
		Name:    fmt.Sprintf("Proxy Access to %s", service.Name),
		Enabled: true,
		Rules: []*PolicyRule{
			{
				ID:       policyID,
				PolicyID: policyID,
				Name:     fmt.Sprintf("Allow access to %s", service.Name),
				Enabled:  true,
				SourceResource: Resource{
					ID:   proxyPeer.ID,
					Type: ResourceTypePeer,
				},
				DestinationResource: Resource{
					ID:   target.TargetId,
					Type: ResourceType(target.TargetType),
				},
				Bidirectional: false,
				Protocol:      PolicyRuleProtocolTCP,
				Action:        PolicyTrafficActionAccept,
				PortRanges: []RulePortRange{
					{
						Start: uint16(port),
						End:   uint16(port),
					},
				},
			},
		},
	}
}

// expandPortsAndRanges expands Ports and PortRanges of a rule into individual firewall rules
func expandPortsAndRanges(base FirewallRule, rule *PolicyRule, peer *nbpeer.Peer) []*FirewallRule {
	features := peerSupportedFirewallFeatures(peer.Meta.WtVersion)

	var expanded []*FirewallRule

	for _, port := range rule.Ports {
		fr := base
		fr.Port = port
		expanded = append(expanded, &fr)
	}

	for _, portRange := range rule.PortRanges {
		// prefer PolicyRule.Ports
		if len(rule.Ports) > 0 {
			break
		}
		fr := base

		if features.portRanges {
			fr.PortRange = portRange
		} else {
			// Peer doesn't support port ranges, only allow single-port ranges
			if portRange.Start != portRange.End {
				continue
			}
			fr.Port = strconv.FormatUint(uint64(portRange.Start), 10)
		}
		expanded = append(expanded, &fr)
	}

	if shouldCheckRulesForNativeSSH(features.nativeSSH, rule, peer) || rule.Protocol == PolicyRuleProtocolNetbirdSSH {
		expanded = addNativeSSHRule(base, expanded)
	}

	return expanded
}

// addNativeSSHRule adds a native SSH rule (port 22022) to the expanded rules if the base rule has port 22 configured.
func addNativeSSHRule(base FirewallRule, expanded []*FirewallRule) []*FirewallRule {
	shouldAdd := false
	for _, fr := range expanded {
		if isPortInRule(nativeSSHPortString, 22022, fr) {
			return expanded
		}
		if isPortInRule(defaultSSHPortString, 22, fr) {
			shouldAdd = true
		}
	}
	if !shouldAdd {
		return expanded
	}

	fr := base
	fr.Port = nativeSSHPortString
	return append(expanded, &fr)
}

func isPortInRule(portString string, portInt uint16, rule *FirewallRule) bool {
	return rule.Port == portString || (rule.PortRange.Start <= portInt && portInt <= rule.PortRange.End)
}

// shouldCheckRulesForNativeSSH determines whether specific policy rules should be checked for native SSH support.
// While users can add the nativeSSHPortString, we look for cases when they used port 22 and based on SSH enabled
// in both management and client, we indicate to add the native port.
func shouldCheckRulesForNativeSSH(supportsNative bool, rule *PolicyRule, peer *nbpeer.Peer) bool {
	return supportsNative && peer.SSHEnabled && peer.Meta.Flags.ServerSSHAllowed && rule.Protocol == PolicyRuleProtocolTCP
}

// peerSupportedFirewallFeatures checks if the peer version supports port ranges.
func peerSupportedFirewallFeatures(peerVer string) supportedFeatures {
	if strings.Contains(peerVer, "dev") {
		return supportedFeatures{true, true}
	}

	var features supportedFeatures

	meetMinVer, err := posture.MeetsMinVersion(firewallRuleMinNativeSSHVer, peerVer)
	features.nativeSSH = err == nil && meetMinVer

	if features.nativeSSH {
		features.portRanges = true
	} else {
		meetMinVer, err = posture.MeetsMinVersion(firewallRuleMinPortRangesVer, peerVer)
		features.portRanges = err == nil && meetMinVer
	}

	return features
}

// filterZoneRecordsForPeers filters DNS records to only include peers to connect.
func filterZoneRecordsForPeers(peer *nbpeer.Peer, customZone nbdns.CustomZone, peersToConnect, expiredPeers []*nbpeer.Peer) []nbdns.SimpleRecord {
	filteredRecords := make([]nbdns.SimpleRecord, 0, len(customZone.Records))
	peerIPs := make(map[string]struct{})

	// Add peer's own IP to include its own DNS records
	peerIPs[peer.IP.String()] = struct{}{}

	for _, peerToConnect := range peersToConnect {
		peerIPs[peerToConnect.IP.String()] = struct{}{}
	}

	for _, expiredPeer := range expiredPeers {
		peerIPs[expiredPeer.IP.String()] = struct{}{}
	}

	for _, record := range customZone.Records {
		if _, exists := peerIPs[record.RData]; exists {
			filteredRecords = append(filteredRecords, record)
		}
	}

	return filteredRecords
}

// filterPeerAppliedZones filters account zones based on the peer's group membership
func filterPeerAppliedZones(ctx context.Context, accountZones []*zones.Zone, peerGroups LookupMap) []nbdns.CustomZone {
	var customZones []nbdns.CustomZone

	if len(peerGroups) == 0 {
		return customZones
	}

	for _, zone := range accountZones {
		if !zone.Enabled || len(zone.Records) == 0 {
			continue
		}

		hasAccess := false
		for _, distGroupID := range zone.DistributionGroups {
			if _, found := peerGroups[distGroupID]; found {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			continue
		}

		simpleRecords := make([]nbdns.SimpleRecord, 0, len(zone.Records))
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
				log.WithContext(ctx).Warnf("unknown DNS record type %s for record %s", record.Type, record.ID)
				continue
			}

			simpleRecords = append(simpleRecords, nbdns.SimpleRecord{
				Name:  dns.Fqdn(record.Name),
				Type:  recordType,
				Class: nbdns.DefaultClass,
				TTL:   record.TTL,
				RData: rData,
			})
		}

		customZones = append(customZones, nbdns.CustomZone{
			Domain:               dns.Fqdn(zone.Domain),
			Records:              simpleRecords,
			SearchDomainDisabled: !zone.EnableSearchDomain,
			NonAuthoritative:     true,
		})
	}

	return customZones
}

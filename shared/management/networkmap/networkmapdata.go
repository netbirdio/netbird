package networkmap

import (
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// NetworkMapData is a dependency-light, slim twin of the server Account. It
// carries only the state GetPeerNetworkMapComponents needs, expressed in the
// fresh nmdata twin types. A builder converts an Account into a NetworkMapData
// once per account; the per-peer components calculation then runs on this twin
// with no reference back to the Account.
type NetworkMapData struct { //nolint:revive // established name across the codebase
	Peers            map[string]*nmdata.Peer
	Groups           map[string]*nmdata.Group
	Policies         []*nmdata.Policy
	Routes           []*nmdata.Route
	NameServerGroups []*nmdata.NameServerGroup
	NetworkResources []*nmdata.NetworkResource

	Network         *nmdata.Network
	DNSSettings     *nmdata.DNSSettings
	AccountSettings *nmdata.AccountSettingsInfo

	PostureChecks map[string]*nmdata.PostureChecks

	AllowedUserIDs            map[string]struct{}
	NetworkXIDToPublicID      map[string]string
	PostureCheckXIDToPublicID map[string]string
	ValidatedPeers            map[string]struct{}
	ResourcePolicies          map[string][]*nmdata.Policy
	Routers                   map[string]map[string]*nmdata.NetworkRouter
	GroupIDToUserIDs          map[string][]string
	DNSDomain                 string

	// ProxyTargetedDomainResourceIDs is the account-level half of
	// forcesRoutingPeerDNSResolution: domain network resources targeted by an
	// enabled reverse-proxy service.
	ProxyTargetedDomainResourceIDs map[string]struct{}

	AppliedZoneCandidates    []AppliedZoneCandidate
	PrivateServiceCandidates []PrivateServiceCandidate
}

// AppliedZoneCandidate is an account-level custom DNS zone reduced to the
// per-peer decision the components calc still makes: include the zone only when
// the peer belongs to one of its distribution groups. Record conversion is done
// once at build time.
type AppliedZoneCandidate struct {
	DistributionGroups []string
	Zone               nmdata.CustomZone
}

// PrivateServiceCandidate is a single private service's synthesized records,
// carried per apex zone. The builder resolves proxy-cluster connectivity and
// domain-suffix matching once; the calc merges the candidates whose AccessGroups
// the peer belongs to, grouped by Zone.Domain.
type PrivateServiceCandidate struct {
	AccessGroups []string
	Zone         nmdata.CustomZone
}

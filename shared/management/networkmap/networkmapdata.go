package networkmap

import (
	"sync"

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

	// PostureValidation holds the precomputed posture-check results, keyed by
	// posture check ID then peer ID. Filled by PrecomputePostureValidation; a
	// present but nil inner map marks a check ID that resolves to no posture
	// check, which the calc treats as passing.
	PostureValidation map[string]map[string]bool

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

	// Services are the account's reverse-proxy services, persisted ones and
	// the in-memory ones synthesised from agent-network state. They are the
	// source of the proxy ACLs injectProxyPolicies synthesises, which no
	// builder can load because they are never written to the database.
	Services []*nmdata.Service

	// Domains are the account's registered reverse-proxy domains, used to
	// resolve the zone apex a private service's records hang under.
	Domains []nmdata.ProxyDomain

	peerGroupsOnce sync.Once
	peerGroupsIdx  map[string]map[string]struct{}

	proxyPoliciesOnce sync.Once
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

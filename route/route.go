package route

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

// Windows has some limitation regarding metric size that differ from Unix-like systems.
// Because of that we are limiting the min and max metric size based on Windows limits:
// see based on info from https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/route_ws2008
const (
	// MinMetric max metric input
	MinMetric = 1
	// MaxMetric max metric input
	MaxMetric = 9999
	// MaxNetIDChar Max Network Identifier
	MaxNetIDChar = 40

	// V6ExitSuffix is appended to a v4 exit node NetID to form its v6 counterpart.
	V6ExitSuffix = "-v6"
)

const (
	// InvalidNetworkString invalid network type string
	InvalidNetworkString = "Invalid"
	// IPv4NetworkString IPv4 network type string
	IPv4NetworkString = "IPv4"
	// IPv6NetworkString IPv6 network type string
	IPv6NetworkString = "IPv6"
	// DomainNetworkString domain network type string
	DomainNetworkString = "Domain"
)

const (
	// InvalidNetwork invalid network type
	InvalidNetwork NetworkType = iota
	// IPv4Network IPv4 network type
	IPv4Network
	// IPv6Network IPv6 network type
	IPv6Network
	// DomainNetwork domain network type
	DomainNetwork
)

// ID is the unique route ID.
type ID string

// ResID is the resourceID part of a route.ID (first part before the colon).
type ResID string

// NetID is the route network identifier, a human-readable string.
type NetID string

// HAMap is a map of HAUniqueID to a list of routes.
type HAMap map[HAUniqueID][]*Route

// NetworkType route network type
type NetworkType int

// String returns prefix type string
func (p NetworkType) String() string {
	switch p {
	case IPv4Network:
		return IPv4NetworkString
	case IPv6Network:
		return IPv6NetworkString
	case DomainNetwork:
		return DomainNetworkString
	default:
		return InvalidNetworkString
	}
}

// ToPrefixType returns a prefix type
func ToPrefixType(prefix string) NetworkType {
	switch prefix {
	case IPv4NetworkString:
		return IPv4Network
	case IPv6NetworkString:
		return IPv6Network
	case DomainNetworkString:
		return DomainNetwork
	default:
		return InvalidNetwork
	}
}

// Route represents a route
type Route struct {
	ID ID `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID string `gorm:"index"`
	// Network and Domains are mutually exclusive
	Network             netip.Prefix `gorm:"serializer:json"`
	Domains             domain.List  `gorm:"serializer:json"`
	KeepRoute           bool
	NetID               NetID
	Description         string
	Peer                string
	PeerID              string   `gorm:"-"`
	PeerGroups          []string `gorm:"serializer:json"`
	NetworkType         NetworkType
	Masquerade          bool
	Metric              int
	Enabled             bool
	Groups              []string `gorm:"serializer:json"`
	AccessControlGroups []string `gorm:"serializer:json"`
	// SkipAutoApply indicates if this exit node route (0.0.0.0/0) should skip auto-application for client routing
	SkipAutoApply bool
}

// EventMeta returns activity event meta related to the route
func (r *Route) EventMeta() map[string]any {
	domains := ""
	if r.Domains != nil {
		domains = r.Domains.SafeString()
	}
	return map[string]any{"name": r.NetID, "network_range": r.Network.String(), "domains": domains, "peer_id": r.Peer, "peer_groups": r.PeerGroups}
}

// Copy copies a route object
func (r *Route) Copy() *Route {
	route := &Route{
		ID:                  r.ID,
		AccountID:           r.AccountID,
		Description:         r.Description,
		NetID:               r.NetID,
		Network:             r.Network,
		Domains:             slices.Clone(r.Domains),
		KeepRoute:           r.KeepRoute,
		NetworkType:         r.NetworkType,
		Peer:                r.Peer,
		PeerID:              r.PeerID,
		PeerGroups:          slices.Clone(r.PeerGroups),
		Metric:              r.Metric,
		Masquerade:          r.Masquerade,
		Enabled:             r.Enabled,
		Groups:              slices.Clone(r.Groups),
		AccessControlGroups: slices.Clone(r.AccessControlGroups),
		SkipAutoApply:       r.SkipAutoApply,
	}
	return route
}

// Equal compares one route with the other
func (r *Route) Equal(other *Route) bool {
	if r == nil && other == nil {
		return true
	} else if r == nil || other == nil {
		return false
	}

	return other.ID == r.ID &&
		other.Description == r.Description &&
		other.NetID == r.NetID &&
		other.Network == r.Network &&
		slices.Equal(r.Domains, other.Domains) &&
		other.KeepRoute == r.KeepRoute &&
		other.NetworkType == r.NetworkType &&
		other.Peer == r.Peer &&
		other.PeerID == r.PeerID &&
		other.Metric == r.Metric &&
		other.Masquerade == r.Masquerade &&
		other.Enabled == r.Enabled &&
		slices.Equal(r.Groups, other.Groups) &&
		slices.Equal(r.PeerGroups, other.PeerGroups) &&
		slices.Equal(r.AccessControlGroups, other.AccessControlGroups) &&
		other.SkipAutoApply == r.SkipAutoApply
}

// IsDynamic returns if the route is dynamic, i.e. has domains
func (r *Route) IsDynamic() bool {
	return r.NetworkType == DomainNetwork
}

// GetHAUniqueID returns the HAUniqueID for the route, it can be used for grouping.
func (r *Route) GetHAUniqueID() HAUniqueID {
	return HAUniqueID(fmt.Sprintf("%s%s%s", r.NetID, haSeparator, r.NetString()))
}

// GetResourceID returns the Networks ResID from the route ID.
// It's the part before the first colon in the ID string.
func (r *Route) GetResourceID() ResID {
	return ResID(strings.Split(string(r.ID), ":")[0])
}

// NetString returns the network string.
// If the route is dynamic, it returns the domains as comma-separated punycode-encoded string.
// If the route is not dynamic, it returns the network (prefix) string.
func (r *Route) NetString() string {
	if r.IsDynamic() && r.Domains != nil {
		return r.Domains.SafeString()
	}
	return r.Network.String()
}

// ParseNetwork Parses a network prefix string and returns a netip.Prefix object and if is invalid, IPv4 or IPv6
func ParseNetwork(networkString string) (NetworkType, netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(networkString)
	if err != nil {
		return InvalidNetwork, netip.Prefix{}, status.Errorf(status.InvalidArgument, "invalid network %s", networkString)
	}

	masked := prefix.Masked()

	if !masked.IsValid() {
		return InvalidNetwork, netip.Prefix{}, status.Errorf(status.InvalidArgument, "invalid range %s", networkString)
	}

	if masked.Addr().Is6() {
		return IPv6Network, masked, nil
	}

	return IPv4Network, masked, nil
}

var (
	v4Default = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	v6Default = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

// IsV4DefaultRoute reports whether p is the IPv4 default route (0.0.0.0/0).
func IsV4DefaultRoute(p netip.Prefix) bool { return p == v4Default }

// IsV6DefaultRoute reports whether p is the IPv6 default route (::/0).
func IsV6DefaultRoute(p netip.Prefix) bool { return p == v6Default }

// ExpandV6ExitPairs appends the paired "-v6" exit node NetID for any v4 exit
// node (0.0.0.0/0) in ids that has a matching v6 counterpart (::/0) in routesMap.
// It modifies and returns the input slice.
func ExpandV6ExitPairs(ids []NetID, routesMap map[NetID][]*Route) []NetID {
	for _, id := range ids {
		rt, ok := routesMap[id]
		if !ok || len(rt) == 0 || !IsV4DefaultRoute(rt[0].Network) {
			continue
		}
		v6ID := NetID(string(id) + V6ExitSuffix)
		if v6Rt, ok := routesMap[v6ID]; ok && len(v6Rt) > 0 && IsV6DefaultRoute(v6Rt[0].Network) {
			if !slices.Contains(ids, v6ID) {
				ids = append(ids, v6ID)
			}
		}
	}
	return ids
}

// V6ExitMergeSet scans routesMap and returns the set of v6 exit node NetIDs
// that should be hidden from the UI because they are paired with a v4 exit node.
// A v6 ID is paired when it has suffix "-v6", its route is ::/0, and the base
// name (without "-v6") exists with route 0.0.0.0/0.
func V6ExitMergeSet(routesMap map[NetID][]*Route) map[NetID]struct{} {
	merged := make(map[NetID]struct{})
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		name := string(id)
		if !IsV6DefaultRoute(rt[0].Network) || !strings.HasSuffix(name, V6ExitSuffix) {
			continue
		}
		baseName := NetID(strings.TrimSuffix(name, V6ExitSuffix))
		if baseRt, ok := routesMap[baseName]; ok && len(baseRt) > 0 && IsV4DefaultRoute(baseRt[0].Network) {
			merged[id] = struct{}{}
		}
	}
	return merged
}

// HasV6ExitPair reports whether id has a paired v6 exit node in the merge set.
func HasV6ExitPair(id NetID, v6Merged map[NetID]struct{}) bool {
	_, ok := v6Merged[NetID(string(id)+"-v6")]
	return ok
}

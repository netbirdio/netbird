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

package route

import (
	"net/netip"

	"github.com/netbirdio/netbird/management/server/status"
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
)

const (
	// InvalidNetwork invalid network type
	InvalidNetwork NetworkType = iota
	// IPv4Network IPv4 network type
	IPv4Network
	// IPv6Network IPv6 network type
	IPv6Network
)

type ID string

type NetID string

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
	default:
		return InvalidNetwork
	}
}

// Route represents a route
type Route struct {
	ID ID `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID   string       `gorm:"index"`
	Network     netip.Prefix `gorm:"serializer:json"`
	NetID       NetID
	Description string
	Peer        string
	PeerGroups  []string `gorm:"serializer:json"`
	NetworkType NetworkType
	Masquerade  bool
	Metric      int
	Enabled     bool
	Groups      []string `gorm:"serializer:json"`
}

// EventMeta returns activity event meta related to the route
func (r *Route) EventMeta() map[string]any {
	return map[string]any{"name": r.NetID, "network_range": r.Network.String(), "peer_id": r.Peer, "peer_groups": r.PeerGroups}
}

// Copy copies a route object
func (r *Route) Copy() *Route {
	route := &Route{
		ID:          r.ID,
		Description: r.Description,
		NetID:       r.NetID,
		Network:     r.Network,
		NetworkType: r.NetworkType,
		Peer:        r.Peer,
		PeerGroups:  make([]string, len(r.PeerGroups)),
		Metric:      r.Metric,
		Masquerade:  r.Masquerade,
		Enabled:     r.Enabled,
		Groups:      make([]string, len(r.Groups)),
	}
	copy(route.Groups, r.Groups)
	copy(route.PeerGroups, r.PeerGroups)
	return route
}

// IsEqual compares one route with the other
func (r *Route) IsEqual(other *Route) bool {
	if r == nil && other == nil {
		return true
	} else if r == nil || other == nil {
		return false
	}

	return other.ID == r.ID &&
		other.Description == r.Description &&
		other.NetID == r.NetID &&
		other.Network == r.Network &&
		other.NetworkType == r.NetworkType &&
		other.Peer == r.Peer &&
		other.Metric == r.Metric &&
		other.Masquerade == r.Masquerade &&
		other.Enabled == r.Enabled &&
		compareList(r.Groups, other.Groups) &&
		compareList(r.PeerGroups, other.PeerGroups)
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

func compareList(list, other []string) bool {
	if len(list) != len(other) {
		return false
	}
	for _, id := range list {
		match := false
		for _, otherID := range other {
			if id == otherID {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	return true
}

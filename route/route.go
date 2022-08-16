package route

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/netip"
)

// Windows has some limitation regarding metric size that differ from Unix-like systems.
// Because of that we are limiting the min and max metric size based on Windows limits:
// see based on info from https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/route_ws2008
const (
	// MinMetric max metric input
	MinMetric = 1
	// MaxMetric max metric input
	MaxMetric = 9999
)
const (
	// InvalidPrefixString invalid prefix type string
	InvalidPrefixString = "Invalid"
	// IPv4PrefixString IPv4 prefix type string
	IPv4PrefixString = "IPv4"
	// IPv6PrefixString IPv6 prefix type string
	IPv6PrefixString = "IPv6"
)

const (
	// InvalidPrefix invalid prefix type
	InvalidPrefix PrefixType = iota
	// IPv4Prefix IPv4 prefix type
	IPv4Prefix
	// IPv6Prefix IPv6 prefix type
	IPv6Prefix
)

// PrefixType route prefix type
type PrefixType int

// String returns prefix type string
func (p PrefixType) String() string {
	switch p {
	case IPv4Prefix:
		return IPv4PrefixString
	case IPv6Prefix:
		return IPv6PrefixString
	default:
		return InvalidPrefixString
	}
}

// ToPrefixType returns a prefix type
func ToPrefixType(prefix string) PrefixType {
	switch prefix {
	case IPv4PrefixString:
		return IPv4Prefix
	case IPv6PrefixString:
		return IPv6Prefix
	default:
		return InvalidPrefix
	}
}

// Route represents a route
type Route struct {
	Prefix      netip.Prefix
	ID          string
	Description string
	Peer        string
	PrefixType  PrefixType
	Masquerade  bool
	Metric      int
	Enabled     bool
}

// Copy copies a route object
func (r *Route) Copy() *Route {
	return &Route{
		ID:          r.ID,
		Description: r.Description,
		Prefix:      r.Prefix,
		PrefixType:  r.PrefixType,
		Peer:        r.Peer,
		Metric:      r.Metric,
		Masquerade:  r.Masquerade,
		Enabled:     r.Enabled,
	}
}

// IsEqual compares one route with the other
func (r *Route) IsEqual(other *Route) bool {
	return other.ID == r.ID &&
		other.Description == r.Description &&
		other.Prefix == r.Prefix &&
		other.PrefixType == r.PrefixType &&
		other.Peer == r.Peer &&
		other.Metric == r.Metric &&
		other.Masquerade == r.Masquerade &&
		other.Enabled == r.Enabled
}

// ParsePrefix Parses a prefix string and returns a netip.Prefix object and if is invalid, IPv4 or IPv6
func ParsePrefix(prefixString string) (PrefixType, netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(prefixString)
	if err != nil {
		return InvalidPrefix, netip.Prefix{}, err
	}

	masked := prefix.Masked()

	if !masked.IsValid() {
		return InvalidPrefix, netip.Prefix{}, status.Errorf(codes.InvalidArgument, "invalid range %s", prefixString)
	}

	if masked.Addr().Is6() {
		return IPv6Prefix, masked, nil
	}

	return IPv4Prefix, masked, nil
}

package route

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/netip"
)

const (
	// InvalidPrefix invalid prefix type
	InvalidPrefix PrefixType = iota
	// IPv4Prefix IPv4 prefix type
	IPv4Prefix
	// IPv6Prefix IPv6 prefix type
	IPv6Prefix
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

// PrefixType route prefix type
type PrefixType int

// Route represents a route
type Route struct {
	Prefix      netip.Prefix
	ID          string
	Description string
	Peer        string
	PrefixType  PrefixType
	Masquerade  bool
	Metric      int
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
	}
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

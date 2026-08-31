package nmdata

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/netbirdio/netbird/shared/management/domain"
)

// NetworkType mirrors route.NetworkType iota values.
const (
	NetworkTypeInvalid = 0
	NetworkTypeIPv4    = 1
	NetworkTypeIPv6    = 2
	NetworkTypeDomain  = 3

	haSeparator = "|"
)

// Route is the slim twin of route.Route.
type Route struct {
	ID                  string
	AccountID           string
	PublicID            string
	Network             netip.Prefix
	Domains             domain.List
	KeepRoute           bool
	NetID               string
	Description         string
	Peer                string
	PeerID              string
	PeerGroups          []string
	NetworkType         int
	Masquerade          bool
	Metric              int
	Enabled             bool
	Groups              []string
	AccessControlGroups []string
	SkipAutoApply       bool
}

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

func (r *Route) IsDynamic() bool {
	return r.NetworkType == NetworkTypeDomain
}

func (r *Route) NetString() string {
	if r.IsDynamic() && r.Domains != nil {
		return r.Domains.SafeString()
	}
	return r.Network.String()
}

func (r *Route) GetHAUniqueID() string {
	return r.NetID + haSeparator + r.NetString()
}

func (r *Route) GetResourceID() string {
	return strings.Split(r.ID, ":")[0]
}

func (r *Route) Copy() *Route {
	return &Route{
		ID:                  r.ID,
		AccountID:           r.AccountID,
		PublicID:            r.PublicID,
		Network:             r.Network,
		Domains:             slices.Clone(r.Domains),
		KeepRoute:           r.KeepRoute,
		NetID:               r.NetID,
		Description:         r.Description,
		Peer:                r.Peer,
		PeerID:              r.PeerID,
		PeerGroups:          slices.Clone(r.PeerGroups),
		NetworkType:         r.NetworkType,
		Masquerade:          r.Masquerade,
		Metric:              r.Metric,
		Enabled:             r.Enabled,
		Groups:              slices.Clone(r.Groups),
		AccessControlGroups: slices.Clone(r.AccessControlGroups),
		SkipAutoApply:       r.SkipAutoApply,
	}
}

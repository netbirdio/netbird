package types

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/rs/xid"

	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
	nbDomain "github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

type NetworkResourceType string

const (
	Host   NetworkResourceType = "host"
	Subnet NetworkResourceType = "subnet"
	Domain NetworkResourceType = "domain"
)

func (p NetworkResourceType) String() string {
	return string(p)
}

type NetworkResource struct {
	ID          string `gorm:"primaryKey"`
	NetworkID   string `gorm:"index"`
	AccountID   string `gorm:"index"`
	Name        string
	Description string
	Type        NetworkResourceType
	Address     string   `gorm:"-"`
	GroupIDs    []string `gorm:"-"`
	Domain      string
	Prefix      netip.Prefix `gorm:"serializer:json"`
	Enabled     bool
}

func NewNetworkResource(accountID, networkID, name, description, address string, groupIDs []string, enabled bool) (*NetworkResource, error) {
	resourceType, domain, prefix, err := GetResourceType(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	return &NetworkResource{
		ID:          xid.New().String(),
		AccountID:   accountID,
		NetworkID:   networkID,
		Name:        name,
		Description: description,
		Type:        resourceType,
		Address:     address,
		Domain:      domain,
		Prefix:      prefix,
		GroupIDs:    groupIDs,
		Enabled:     enabled,
	}, nil
}

func (n *NetworkResource) ToAPIResponse(groups []api.GroupMinimum) *api.NetworkResource {
	addr := n.Prefix.String()
	if n.Type == Domain {
		addr = n.Domain
	}

	return &api.NetworkResource{
		Id:          n.ID,
		Name:        n.Name,
		Description: &n.Description,
		Type:        api.NetworkResourceType(n.Type.String()),
		Address:     addr,
		Groups:      groups,
		Enabled:     n.Enabled,
	}
}

func (n *NetworkResource) FromAPIRequest(req *api.NetworkResourceRequest) {
	n.Name = req.Name

	if req.Description != nil {
		n.Description = *req.Description
	}
	n.Address = req.Address
	n.GroupIDs = req.Groups
	n.Enabled = req.Enabled
}

func (n *NetworkResource) Copy() *NetworkResource {
	return &NetworkResource{
		ID:          n.ID,
		AccountID:   n.AccountID,
		NetworkID:   n.NetworkID,
		Name:        n.Name,
		Description: n.Description,
		Type:        n.Type,
		Address:     n.Address,
		Domain:      n.Domain,
		Prefix:      n.Prefix,
		GroupIDs:    n.GroupIDs,
		Enabled:     n.Enabled,
	}
}

func (n *NetworkResource) ToRoute(peer *nbpeer.Peer, router *routerTypes.NetworkRouter) *route.Route {
	r := &route.Route{
		ID:                  route.ID(fmt.Sprintf("%s:%s", n.ID, peer.ID)),
		AccountID:           n.AccountID,
		KeepRoute:           true,
		NetID:               route.NetID(n.Name),
		Description:         n.Description,
		Peer:                peer.Key,
		PeerID:              peer.ID,
		PeerGroups:          nil,
		Masquerade:          router.Masquerade,
		Metric:              router.Metric,
		Enabled:             n.Enabled,
		Groups:              nil,
		AccessControlGroups: nil,
	}

	if n.Type == Host || n.Type == Subnet {
		r.Network = n.Prefix

		r.NetworkType = route.IPv4Network
		if n.Prefix.Addr().Is6() {
			r.NetworkType = route.IPv6Network
		}
	}

	if n.Type == Domain {
		domainList, err := nbDomain.FromStringList([]string{n.Domain})
		if err != nil {
			return nil
		}
		r.Domains = domainList
		r.NetworkType = route.DomainNetwork

		// add default placeholder for domain network
		r.Network = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 32)
	}

	return r
}

func (n *NetworkResource) EventMeta(network *networkTypes.Network) map[string]any {
	return map[string]any{"name": n.Name, "type": n.Type, "network_name": network.Name, "network_id": network.ID}
}

// GetResourceType returns the type of the resource based on the address
func GetResourceType(address string) (NetworkResourceType, string, netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(address); err == nil {
		if prefix.Bits() == 32 || prefix.Bits() == 128 {
			return Host, "", prefix, nil
		}
		return Subnet, "", prefix, nil
	}

	if ip, err := netip.ParseAddr(address); err == nil {
		return Host, "", netip.PrefixFrom(ip, ip.BitLen()), nil
	}

	if _, err := nbDomain.ValidateDomains([]string{address}); err == nil {
		return Domain, address, netip.Prefix{}, nil
	}

	return "", "", netip.Prefix{}, errors.New("not a valid host, subnet, or domain")
}

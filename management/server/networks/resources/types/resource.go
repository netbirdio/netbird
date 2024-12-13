package types

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	nbDomain "github.com/netbirdio/netbird/management/domain"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/http/api"
)

type NetworkResourceType string

const (
	host   NetworkResourceType = "host"
	subnet NetworkResourceType = "subnet"
	domain NetworkResourceType = "domain"
)

func (p NetworkResourceType) String() string {
	return string(p)
}

type NetworkResource struct {
	ID          string `gorm:"index"`
	NetworkID   string `gorm:"index"`
	AccountID   string `gorm:"index"`
	Name        string
	Description string
	Type        NetworkResourceType
	Address     string
}

func NewNetworkResource(accountID, networkID, name, description, address string) (*NetworkResource, error) {
	resourceType, err := GetResourceType(address)
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
	}, nil
}

func (n *NetworkResource) ToAPIResponse() *api.NetworkResource {
	return &api.NetworkResource{
		Id:          n.ID,
		Name:        n.Name,
		Description: &n.Description,
		Type:        api.NetworkResourceType(n.Type.String()),
		Address:     n.Address,
	}
}

func (n *NetworkResource) FromAPIRequest(req *api.NetworkResourceRequest) {
	n.Name = req.Name

	if req.Description != nil {
		n.Description = *req.Description
	}
	n.Address = req.Address
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
	}
}

func (n *NetworkResource) ToRoute(peer *peer.Peer, router *routerTypes.NetworkRouter) *route.Route {
	r := &route.Route{
		ID:                  route.ID(n.ID),
		AccountID:           n.AccountID,
		KeepRoute:           true,
		NetID:               route.NetID(n.Name),
		Description:         n.Description,
		Peer:                peer.Key,
		PeerGroups:          nil,
		Masquerade:          router.Masquerade,
		Metric:              router.Metric,
		Enabled:             true,
		Groups:              nil,
		AccessControlGroups: nil,
	}

	if n.Type == host || n.Type == subnet {
		prefix, err := netip.ParsePrefix(n.Address)
		if err != nil {
			return nil
		}
		r.Network = prefix

		r.NetworkType = route.IPv4Network
		if prefix.Addr().Is6() {
			r.NetworkType = route.IPv6Network
		}
	}

	if n.Type == domain {
		domainList, err := nbDomain.FromStringList([]string{n.Address})
		if err != nil {
			return nil
		}
		r.Domains = domainList
		r.NetworkType = route.DomainNetwork
	}

	return r
}

// GetResourceType returns the type of the resource based on the address
func GetResourceType(address string) (NetworkResourceType, error) {
	if ip, cidr, err := net.ParseCIDR(address); err == nil {
		ones, _ := cidr.Mask.Size()
		if strings.HasSuffix(address, "/32") || (ip != nil && ones == 32) {
			return host, nil
		}
		return subnet, nil
	}

	if net.ParseIP(address) != nil {
		return host, nil
	}

	domainRegex := regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	if domainRegex.MatchString(address) {
		return domain, nil
	}

	return "", errors.New("not a host, subnet, or domain")
}

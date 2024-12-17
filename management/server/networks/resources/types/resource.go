package types

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"

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
	Address     string `gorm:"-"`
	Domain      string
	Prefix      netip.Prefix
}

func NewNetworkResource(accountID, networkID, name, description, address string) (*NetworkResource, error) {
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
	}, nil
}

func (n *NetworkResource) ToAPIResponse(groups []api.GroupMinimum) *api.NetworkResource {
	return &api.NetworkResource{
		Id:          n.ID,
		Name:        n.Name,
		Description: &n.Description,
		Type:        api.NetworkResourceType(n.Type.String()),
		Domain:      n.Domain,
		Prefix:      n.Prefix.String(),
		Groups:      groups,
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

// GetResourceType returns the type of the resource based on the address
func GetResourceType(address string) (NetworkResourceType, string, netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(address); err == nil {
		if prefix.Bits() == 32 || prefix.Bits() == 128 {
			return host, "", prefix, nil
		}
		return subnet, "", prefix, nil
	}

	if ip, err := netip.ParseAddr(address); err == nil {
		return host, "", netip.PrefixFrom(ip, ip.BitLen()), nil
	}

	domainRegex := regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	if domainRegex.MatchString(address) {
		return domain, address, netip.Prefix{}, nil
	}

	return "", "", netip.Prefix{}, errors.New("not a valid host, subnet, or domain")
}

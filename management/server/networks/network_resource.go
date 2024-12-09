package networks

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/rs/xid"
)

type NetworkResourceType string

const (
	host   NetworkResourceType = "Host"
	subnet NetworkResourceType = "Subnet"
	domain NetworkResourceType = "Domain"
)

func (p NetworkResourceType) String() string {
	return string(p)
}

type NetworkResource struct {
	ID        string `gorm:"index"`
	NetworkID string `gorm:"index"`
	Type      NetworkResourceType
	Address   string
}

func NewNetworkResource(networkID string, address string) (*NetworkResource, error) {
	resourceType, err := getResourceType(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	return &NetworkResource{
		ID:        xid.New().String(),
		NetworkID: networkID,
		Type:      resourceType,
		Address:   address,
	}, nil
}

// getResourceType returns the type of the resource based on the address
func getResourceType(address string) (NetworkResourceType, error) {
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

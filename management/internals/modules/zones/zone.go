package zones

import (
	"errors"
	"regexp"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

var domainRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)

type Zone struct {
	ID                 string `gorm:"primaryKey"`
	AccountID          string `gorm:"index"`
	Name               string
	Domain             string
	Enabled            bool
	EnableSearchDomain bool
	DistributionGroups []string `gorm:"serializer:json"`
}

func NewZone(accountID, name, domain string, enabled, enableSearchDomain bool, distributionGroups []string) *Zone {
	return &Zone{
		ID:                 xid.New().String(),
		AccountID:          accountID,
		Name:               name,
		Domain:             domain,
		Enabled:            enabled,
		EnableSearchDomain: enableSearchDomain,
		DistributionGroups: distributionGroups,
	}
}

func (z *Zone) ToAPIResponse() *api.Zone {
	return &api.Zone{
		DistributionGroups: z.DistributionGroups,
		Domain:             z.Domain,
		EnableSearchDomain: z.EnableSearchDomain,
		Enabled:            z.Enabled,
		Id:                 z.ID,
		Name:               z.Name,
	}
}

func (z *Zone) FromAPIRequest(req *api.ZoneRequest) {
	z.Name = req.Name
	z.Domain = req.Domain
	z.EnableSearchDomain = req.EnableSearchDomain
	z.DistributionGroups = req.DistributionGroups

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	z.Enabled = enabled
}

func (z *Zone) Validate() error {
	if z.Name == "" {
		return errors.New("zone name is required")
	}
	if len(z.Name) > 255 {
		return errors.New("zone name exceeds maximum length of 255 characters")
	}

	if !domainRegex.MatchString(z.Domain) {
		return errors.New("zone domain has invalid format")
	}

	if len(z.DistributionGroups) == 0 {
		return errors.New("at least one distribution group is required")
	}

	return nil
}

func (z *Zone) EventMeta() map[string]any {
	return map[string]any{"name": z.Name, "domain": z.Domain}
}

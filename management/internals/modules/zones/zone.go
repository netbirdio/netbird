package zones

import (
	"errors"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type Zone struct {
	ID                 string `gorm:"primaryKey"`
	AccountID          string `gorm:"index"`
	Name               string
	Domain             string
	Enabled            bool
	EnableSearchDomain bool
	DistributionGroups []string          `gorm:"serializer:json"`
	Records            []*records.Record `gorm:"foreignKey:ZoneID;references:ID"`
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
	apiRecords := make([]api.DNSRecord, 0, len(z.Records))
	for _, record := range z.Records {
		if apiRecord := record.ToAPIResponse(); apiRecord != nil {
			apiRecords = append(apiRecords, *apiRecord)
		}
	}

	return &api.Zone{
		DistributionGroups: z.DistributionGroups,
		Domain:             z.Domain,
		EnableSearchDomain: z.EnableSearchDomain,
		Enabled:            z.Enabled,
		Id:                 z.ID,
		Name:               z.Name,
		Records:            apiRecords,
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

	if !domain.IsValidDomainNoWildcard(z.Domain) {
		return errors.New("invalid zone domain format")
	}

	if len(z.DistributionGroups) == 0 {
		return errors.New("at least one distribution group is required")
	}

	return nil
}

func (z *Zone) EventMeta() map[string]any {
	return map[string]any{"name": z.Name, "domain": z.Domain}
}

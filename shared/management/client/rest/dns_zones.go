package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// DNSZonesAPI APIs for DNS Zones Management, do not use directly
type DNSZonesAPI struct {
	c *Client
}

// ListZones list all DNS zones
// See more: https://docs.netbird.io/api/resources/dns-zones#list-all-dns-zones
func (a *DNSZonesAPI) ListZones(ctx context.Context) ([]api.Zone, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/dns/zones", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Zone](resp)
	return ret, err
}

// GetZone get DNS zone info
// See more: https://docs.netbird.io/api/resources/dns-zones#retrieve-a-dns-zone
func (a *DNSZonesAPI) GetZone(ctx context.Context, zoneID string) (*api.Zone, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/dns/zones/"+zoneID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Zone](resp)
	return &ret, err
}

// CreateZone create new DNS zone
// See more: https://docs.netbird.io/api/resources/dns-zones#create-a-dns-zone
func (a *DNSZonesAPI) CreateZone(ctx context.Context, request api.PostApiDnsZonesJSONRequestBody) (*api.Zone, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/dns/zones", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Zone](resp)
	return &ret, err
}

// UpdateZone update DNS zone info
// See more: https://docs.netbird.io/api/resources/dns-zones#update-a-dns-zone
func (a *DNSZonesAPI) UpdateZone(ctx context.Context, zoneID string, request api.PutApiDnsZonesZoneIdJSONRequestBody) (*api.Zone, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/dns/zones/"+zoneID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Zone](resp)
	return &ret, err
}

// DeleteZone delete DNS zone
// See more: https://docs.netbird.io/api/resources/dns-zones#delete-a-dns-zone
func (a *DNSZonesAPI) DeleteZone(ctx context.Context, zoneID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/dns/zones/"+zoneID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// ListRecords list all DNS records in a zone
// See more: https://docs.netbird.io/api/resources/dns-zones#list-all-dns-records
func (a *DNSZonesAPI) ListRecords(ctx context.Context, zoneID string) ([]api.DNSRecord, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/dns/zones/"+zoneID+"/records", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.DNSRecord](resp)
	return ret, err
}

// GetRecord get DNS record info
// See more: https://docs.netbird.io/api/resources/dns-zones#retrieve-a-dns-record
func (a *DNSZonesAPI) GetRecord(ctx context.Context, zoneID, recordID string) (*api.DNSRecord, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/dns/zones/"+zoneID+"/records/"+recordID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.DNSRecord](resp)
	return &ret, err
}

// CreateRecord create new DNS record in a zone
// See more: https://docs.netbird.io/api/resources/dns-zones#create-a-dns-record
func (a *DNSZonesAPI) CreateRecord(ctx context.Context, zoneID string, request api.PostApiDnsZonesZoneIdRecordsJSONRequestBody) (*api.DNSRecord, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/dns/zones/"+zoneID+"/records", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.DNSRecord](resp)
	return &ret, err
}

// UpdateRecord update DNS record info
// See more: https://docs.netbird.io/api/resources/dns-zones#update-a-dns-record
func (a *DNSZonesAPI) UpdateRecord(ctx context.Context, zoneID, recordID string, request api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody) (*api.DNSRecord, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/dns/zones/"+zoneID+"/records/"+recordID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.DNSRecord](resp)
	return &ret, err
}

// DeleteRecord delete DNS record
// See more: https://docs.netbird.io/api/resources/dns-zones#delete-a-dns-record
func (a *DNSZonesAPI) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/dns/zones/"+zoneID+"/records/"+recordID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

package rest

import (
	"context"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// GeoLocationAPI APIs for Geo-Location, do not use directly
type GeoLocationAPI struct {
	c *Client
}

// ListCountries list all country codes
// See more: https://docs.netbird.io/api/resources/geo-locations#list-all-country-codes
func (a *GeoLocationAPI) ListCountries(ctx context.Context) ([]api.Country, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/locations/countries", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[[]api.Country](resp)
	return ret, err
}

// ListCountryCities Get a list of all English city names for a given country code
// See more: https://docs.netbird.io/api/resources/geo-locations#list-all-city-names-by-country
func (a *GeoLocationAPI) ListCountryCities(ctx context.Context, countryCode string) ([]api.City, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/locations/countries/"+countryCode+"/cities", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[[]api.City](resp)
	return ret, err
}

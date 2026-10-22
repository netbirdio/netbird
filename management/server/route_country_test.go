package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

// countriesGeo knows a fixed list of countries; nothing else of the service is used here.
type countriesGeo struct {
	geolocation.Mock
	codes []string
}

func (g *countriesGeo) GetAllCountries() ([]geolocation.Country, error) {
	countries := make([]geolocation.Country, 0, len(g.codes))
	for _, code := range g.codes {
		countries = append(countries, geolocation.Country{CountryISOCode: code, CountryName: code})
	}
	return countries, nil
}

func TestCreateCountryRoute(t *testing.T) {
	am, _, err := createRouterManager(t)
	require.NoError(t, err)
	account, err := initTestRouteAccount(t, am)
	require.NoError(t, err)

	createRoute := func(prefix netip.Prefix, countries []string, peerGroup string) (*route.Route, error) {
		return am.CreateRoute(context.Background(), account.Id, prefix, route.CountryNetwork, nil, countries, "", []string{peerGroup},
			"", "us-exit", true, 9999, []string{routeGroup1}, nil, true, userID, false, false)
	}
	requireStatus := func(t *testing.T, err error, expected status.Type) {
		t.Helper()
		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok, "expected a status error, got %v", err)
		assert.Equal(t, expected, sErr.Type(), "unexpected error: %v", err)
	}

	t.Run("geolocation disabled", func(t *testing.T) {
		am.geo = nil
		_, err := createRoute(netip.Prefix{}, []string{"US"}, routeGroupHA1)
		requireStatus(t, err, status.PreconditionFailed)
	})

	am.geo = &countriesGeo{codes: []string{"US", "CA", "DE"}}

	t.Run("unknown country", func(t *testing.T) {
		_, err := createRoute(netip.Prefix{}, []string{"US", "ZZ"}, routeGroupHA1)
		requireStatus(t, err, status.InvalidArgument)
	})

	t.Run("network and countries together", func(t *testing.T) {
		_, err := createRoute(netip.MustParsePrefix("10.0.0.0/8"), []string{"US"}, routeGroupHA1)
		requireStatus(t, err, status.InvalidArgument)
	})

	t.Run("countries are normalized", func(t *testing.T) {
		created, err := createRoute(netip.Prefix{}, []string{"us", "CA", "US"}, routeGroupHA1)
		require.NoError(t, err)
		assert.Equal(t, []string{"CA", "US"}, created.Countries, "codes should be upper-case, sorted and unique")
		assert.Equal(t, route.CountryNetwork, created.NetworkType)
		assert.Equal(t, getPlaceholderIP(), created.Network, "country routes carry the placeholder network")

		stored, err := am.Store.GetRouteByID(context.Background(), "", account.Id, string(created.ID))
		require.NoError(t, err)
		assert.Equal(t, created.Countries, stored.Countries, "the stored route should keep the countries")
	})

	t.Run("same countries on the same routing peers are refused", func(t *testing.T) {
		_, err := createRoute(netip.Prefix{}, []string{"US", "CA"}, routeGroupHA1)
		requireStatus(t, err, status.AlreadyExists)
	})

	t.Run("other countries on the same routing peers are allowed", func(t *testing.T) {
		_, err := createRoute(netip.Prefix{}, []string{"DE"}, routeGroupHA1)
		require.NoError(t, err, "a route for other countries is a different destination")
	})
}

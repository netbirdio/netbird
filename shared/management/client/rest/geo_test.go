//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

var (
	testCountry = api.Country{
		CountryCode: "DE",
		CountryName: "Germany",
	}

	testCity = api.City{
		CityName:  "Berlin",
		GeonameId: 2950158,
	}
)

func TestGeo_ListCountries_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/locations/countries", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Country{testCountry})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GeoLocation.ListCountries(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testCountry, ret[0])
	})
}

func TestGeo_ListCountries_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/locations/countries", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GeoLocation.ListCountries(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestGeo_ListCountryCities_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/locations/countries/Test/cities", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.City{testCity})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GeoLocation.ListCountryCities(context.Background(), "Test")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testCity, ret[0])
	})
}

func TestGeo_ListCountryCities_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/locations/countries/Test/cities", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GeoLocation.ListCountryCities(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestGeo_Integration(t *testing.T) {
	// Blackbox is initialized with empty GeoLocations
	withBlackBoxServer(t, func(c *rest.Client) {
		countries, err := c.GeoLocation.ListCountries(context.Background())
		require.NoError(t, err)
		assert.Empty(t, countries)

		cities, err := c.GeoLocation.ListCountryCities(context.Background(), "DE")
		require.NoError(t, err)
		assert.Empty(t, cities)
	})
}

package http

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// GeolocationsHandler is a handler that returns locations.
type GeolocationsHandler struct {
	accountManager     server.AccountManager
	geolocationManager *geolocation.Geolocation
	claimsExtractor    *jwtclaims.ClaimsExtractor
}

// NewGeolocationsHandlerHandler creates a new Geolocations handler
func NewGeolocationsHandlerHandler(accountManager server.AccountManager, geolocationManager *geolocation.Geolocation, authCfg AuthCfg) *GeolocationsHandler {
	return &GeolocationsHandler{
		accountManager:     accountManager,
		geolocationManager: geolocationManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllCountries retrieves a list of all countries
func (l *GeolocationsHandler) GetAllCountries(w http.ResponseWriter, r *http.Request) {
	if err := l.authenticateUser(r); err != nil {
		util.WriteError(err, w)
		return
	}

	if l.geolocationManager == nil {
		// TODO: update error message to include geo db self hosted doc link when ready
		util.WriteError(status.Errorf(status.PreconditionFailed, "Geo location database is not initialized"), w)
		return
	}

	allCountries, err := l.geolocationManager.GetAllCountries()
	if err != nil {
		util.WriteError(err, w)
		return
	}

	countries := make([]api.Country, 0, len(allCountries))
	for _, country := range allCountries {
		countries = append(countries, toCountryResponse(country))
	}
	util.WriteJSONObject(w, countries)
}

// GetCitiesByCountry retrieves a list of cities based on the given country code
func (l *GeolocationsHandler) GetCitiesByCountry(w http.ResponseWriter, r *http.Request) {
	if err := l.authenticateUser(r); err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	countryCode := vars["country"]
	if !countryCodeRegex.MatchString(countryCode) {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid country code"), w)
		return
	}

	if l.geolocationManager == nil {
		// TODO: update error message to include geo db self hosted doc link when ready
		util.WriteError(status.Errorf(status.PreconditionFailed, "Geo location database is not initialized"), w)
		return
	}

	allCities, err := l.geolocationManager.GetCitiesByCountry(countryCode)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	cities := make([]api.City, 0, len(allCities))
	for _, city := range allCities {
		cities = append(cities, toCityResponse(city))
	}
	util.WriteJSONObject(w, cities)
}

func (l *GeolocationsHandler) authenticateUser(r *http.Request) error {
	claims := l.claimsExtractor.FromRequestContext(r)
	_, user, err := l.accountManager.GetAccountFromToken(claims)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "user is not allowed to perform this action")
	}
	return nil
}

func toCountryResponse(country geolocation.Country) api.Country {
	return api.Country{
		CountryName: country.CountryName,
		CountryCode: country.CountryISOCode,
	}
}

func toCityResponse(city geolocation.City) api.City {
	return api.City{
		CityName:  city.CityName,
		GeonameId: city.GeoNameID,
	}
}

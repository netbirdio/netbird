package http

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// LocationsHandler is a handler that returns locations.
type LocationsHandler struct {
	accountManager  server.AccountManager
	locationManager *geolocation.Manager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewLocationsHandlerHandler creates a new Location handler
func NewLocationsHandlerHandler(accountManager server.AccountManager, locationManager *geolocation.Manager, authCfg AuthCfg) *LocationsHandler {
	return &LocationsHandler{
		accountManager:  accountManager,
		locationManager: locationManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllCountries retrieves a list of all countries
func (l *LocationsHandler) GetAllCountries(w http.ResponseWriter, r *http.Request) {
	if err := l.authenticateUser(r); err != nil {
		util.WriteError(err, w)
		return
	}

	countries, err := l.locationManager.GetAllCountries()
	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, countries)
}

// GetCitiesByCountry retrieves a list of cities based on the given country code
func (l *LocationsHandler) GetCitiesByCountry(w http.ResponseWriter, r *http.Request) {
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

	cities, err := l.locationManager.GetCitiesByCountry(countryCode)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, cities)
}

func (l *LocationsHandler) authenticateUser(r *http.Request) error {
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

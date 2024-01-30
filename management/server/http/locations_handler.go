package http

import (
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

// LocationsHandler is a handler that returns locations.
type LocationsHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewLocationsHandlerHandler creates a new Location handler
func NewLocationsHandlerHandler(accountManager server.AccountManager, authCfg AuthCfg) *LocationsHandler {
	return &LocationsHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

func (l *LocationsHandler) GetAllCountries(w http.ResponseWriter, r *http.Request) {
}

func (l *LocationsHandler) GetCitiesByCountry(w http.ResponseWriter, r *http.Request) {
}

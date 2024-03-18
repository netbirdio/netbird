package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/netbird/management/refactor/resources/peers"
	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"

	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const apiPrefix = "/api"

// AuthCfg contains parameters for authentication middleware
type AuthCfg struct {
	Issuer       string
	Audience     string
	UserIDClaim  string
	KeysLocation string
}

type DefaultAPIHandler struct {
	Router             *mux.Router
	AccountManager     s.AccountManager
	geolocationManager *geolocation.Geolocation
	AuthCfg            AuthCfg
}

// EmptyObject is an empty struct used to return empty JSON object
type EmptyObject struct {
}

// NewDefaultAPIHandler creates the Management service HTTP API handler registering all the available endpoints.
func NewDefaultAPIHandler(ctx context.Context, jwtValidator jwtclaims.JWTValidator, appMetrics telemetry.AppMetrics, authCfg AuthCfg) (http.Handler, error) {
	claimsExtractor := jwtclaims.NewClaimsExtractor(
		jwtclaims.WithAudience(authCfg.Audience),
		jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
	)

	authMiddleware := middleware.NewAuthMiddleware(
		accountManager.GetAccountFromPAT,
		jwtValidator.ValidateAndParse,
		accountManager.MarkPATUsed,
		accountManager.CheckUserAccessByJWTGroups,
		claimsExtractor,
		authCfg.Audience,
		authCfg.UserIDClaim,
	)

	corsMiddleware := cors.AllowAll()

	acMiddleware := middleware.NewAccessControl(
		authCfg.Audience,
		authCfg.UserIDClaim,
		accountManager.GetUser)

	rootRouter := mux.NewRouter()
	metricsMiddleware := appMetrics.HTTPMiddleware()

	prefix := apiPrefix
	router := rootRouter.PathPrefix(prefix).Subrouter()
	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler, acMiddleware.Handler)

	api := DefaultAPIHandler{
		Router:             router,
		AccountManager:     accountManager,
		geolocationManager: LocationManager,
		AuthCfg:            authCfg,
	}

	if _, err := integrations.RegisterHandlers(ctx, prefix, api.Router, accountManager, claimsExtractor); err != nil {
		return nil, fmt.Errorf("register integrations endpoints: %w", err)
	}

	peers.RegisterPeersEndpoints(api.Router)
	// api.addAccountsEndpoint()
	// api.addPeersEndpoint()
	// api.addUsersEndpoint()
	// api.addUsersTokensEndpoint()
	// api.addSetupKeysEndpoint()
	// api.addRulesEndpoint()
	// api.addPoliciesEndpoint()
	// api.addGroupsEndpoint()
	// api.addRoutesEndpoint()
	// api.addDNSNameserversEndpoint()
	// api.addDNSSettingEndpoint()
	// api.addEventsEndpoint()
	// api.addPostureCheckEndpoint()
	// api.addLocationsEndpoint()

	err := api.Router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		methods, err := route.GetMethods()
		if err != nil { // we may have wildcard routes from integrations without methods, skip them for now
			methods = []string{}
		}
		for _, method := range methods {
			template, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			err = metricsMiddleware.AddHTTPRequestResponseCounter(template, method)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return rootRouter, nil
}

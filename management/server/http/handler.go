package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"github.com/netbirdio/management-integrations/integrations"

	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	nbgroups "github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/handlers/accounts"
	"github.com/netbirdio/netbird/management/server/http/handlers/dns"
	"github.com/netbirdio/netbird/management/server/http/handlers/events"
	"github.com/netbirdio/netbird/management/server/http/handlers/groups"
	"github.com/netbirdio/netbird/management/server/http/handlers/networks"
	"github.com/netbirdio/netbird/management/server/http/handlers/peers"
	"github.com/netbirdio/netbird/management/server/http/handlers/policies"
	"github.com/netbirdio/netbird/management/server/http/handlers/routes"
	"github.com/netbirdio/netbird/management/server/http/handlers/setup_keys"
	"github.com/netbirdio/netbird/management/server/http/handlers/users"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/integrated_validator"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbnetworks "github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const apiPrefix = "/api"

type apiHandler struct {
	Router             *mux.Router
	AccountManager     s.AccountManager
	geolocationManager *geolocation.Geolocation
	AuthCfg            configs.AuthCfg
}

// APIHandler creates the Management service HTTP API handler registering all the available endpoints.
func APIHandler(ctx context.Context, accountManager s.AccountManager, networksManager nbnetworks.Manager, resourceManager resources.Manager, routerManager routers.Manager, groupsManager nbgroups.Manager, LocationManager *geolocation.Geolocation, jwtValidator jwtclaims.JWTValidator, appMetrics telemetry.AppMetrics, authCfg configs.AuthCfg, integratedValidator integrated_validator.IntegratedValidator) (http.Handler, error) {
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

	claimsExtractor = jwtclaims.NewClaimsExtractor(
		jwtclaims.WithAudience(authCfg.Audience),
		jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
	)

	acMiddleware := middleware.NewAccessControl(
		authCfg.Audience,
		authCfg.UserIDClaim,
		accountManager.GetUser)

	rootRouter := mux.NewRouter()
	metricsMiddleware := appMetrics.HTTPMiddleware()

	prefix := apiPrefix
	router := rootRouter.PathPrefix(prefix).Subrouter()
	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler, acMiddleware.Handler)

	api := apiHandler{
		Router:             router,
		AccountManager:     accountManager,
		geolocationManager: LocationManager,
		AuthCfg:            authCfg,
	}

	if _, err := integrations.RegisterHandlers(ctx, prefix, api.Router, accountManager, claimsExtractor, integratedValidator, appMetrics.GetMeter()); err != nil {
		return nil, fmt.Errorf("register integrations endpoints: %w", err)
	}

	accounts.AddEndpoints(api.AccountManager, authCfg, router)
	peers.AddEndpoints(api.AccountManager, authCfg, router)
	users.AddEndpoints(api.AccountManager, authCfg, router)
	setup_keys.AddEndpoints(api.AccountManager, authCfg, router)
	policies.AddEndpoints(api.AccountManager, api.geolocationManager, authCfg, router)
	groups.AddEndpoints(api.AccountManager, authCfg, router)
	routes.AddEndpoints(api.AccountManager, authCfg, router)
	dns.AddEndpoints(api.AccountManager, authCfg, router)
	events.AddEndpoints(api.AccountManager, authCfg, router)
	networks.AddEndpoints(networksManager, resourceManager, routerManager, groupsManager, api.AccountManager, api.AccountManager.GetAccountIDFromToken, authCfg, router)

	return rootRouter, nil
}

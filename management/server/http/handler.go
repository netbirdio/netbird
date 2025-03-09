package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"github.com/netbirdio/management-integrations/integrations"

	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/permissions"

	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/geolocation"
	nbgroups "github.com/netbirdio/netbird/management/server/groups"
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
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	nbnetworks "github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	nbpeers "github.com/netbirdio/netbird/management/server/peers"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const apiPrefix = "/api"

// NewAPIHandler creates the Management service HTTP API handler registering all the available endpoints.
func NewAPIHandler(
	ctx context.Context,
	accountManager s.AccountManager,
	networksManager nbnetworks.Manager,
	resourceManager resources.Manager,
	routerManager routers.Manager,
	groupsManager nbgroups.Manager,
	LocationManager geolocation.Geolocation,
	authManager auth.Manager,
	appMetrics telemetry.AppMetrics,
	integratedValidator integrated_validator.IntegratedValidator,
	proxyController port_forwarding.Controller,
	permissionsManager permissions.Manager,
	peersManager nbpeers.Manager,
) (http.Handler, error) {

	authMiddleware := middleware.NewAuthMiddleware(
		authManager,
		accountManager.GetAccountIDFromUserAuth,
		accountManager.SyncUserJWTGroups,
	)

	corsMiddleware := cors.AllowAll()

	acMiddleware := middleware.NewAccessControl(accountManager.GetUserFromUserAuth)

	rootRouter := mux.NewRouter()
	metricsMiddleware := appMetrics.HTTPMiddleware()

	prefix := apiPrefix
	router := rootRouter.PathPrefix(prefix).Subrouter()

	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler, acMiddleware.Handler)

	if _, err := integrations.RegisterHandlers(ctx, prefix, router, accountManager, integratedValidator, appMetrics.GetMeter(), permissionsManager, peersManager, proxyController); err != nil {
		return nil, fmt.Errorf("register integrations endpoints: %w", err)
	}

	accounts.AddEndpoints(accountManager, router)
	peers.AddEndpoints(accountManager, router)
	users.AddEndpoints(accountManager, router)
	setup_keys.AddEndpoints(accountManager, router)
	policies.AddEndpoints(accountManager, LocationManager, router)
	groups.AddEndpoints(accountManager, router)
	routes.AddEndpoints(accountManager, router)
	dns.AddEndpoints(accountManager, router)
	events.AddEndpoints(accountManager, router)
	networks.AddEndpoints(networksManager, resourceManager, routerManager, groupsManager, accountManager, router)

	return rootRouter, nil
}

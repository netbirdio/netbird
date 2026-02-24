package http

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"

	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	reverseproxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/manager"

	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	idpmanager "github.com/netbirdio/netbird/management/server/idp"

	"github.com/netbirdio/management-integrations/integrations"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	zonesManager "github.com/netbirdio/netbird/management/internals/modules/zones/manager"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	recordsManager "github.com/netbirdio/netbird/management/internals/modules/zones/records/manager"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/settings"

	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/permissions"

	"github.com/netbirdio/netbird/management/server/http/handlers/proxy"

	nbpeers "github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/geolocation"
	nbgroups "github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/http/handlers/accounts"
	"github.com/netbirdio/netbird/management/server/http/handlers/dns"
	"github.com/netbirdio/netbird/management/server/http/handlers/events"
	"github.com/netbirdio/netbird/management/server/http/handlers/groups"
	"github.com/netbirdio/netbird/management/server/http/handlers/idp"
	"github.com/netbirdio/netbird/management/server/http/handlers/instance"
	"github.com/netbirdio/netbird/management/server/http/handlers/networks"
	"github.com/netbirdio/netbird/management/server/http/handlers/peers"
	"github.com/netbirdio/netbird/management/server/http/handlers/policies"
	"github.com/netbirdio/netbird/management/server/http/handlers/routes"
	"github.com/netbirdio/netbird/management/server/http/handlers/setup_keys"
	"github.com/netbirdio/netbird/management/server/http/handlers/users"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	nbinstance "github.com/netbirdio/netbird/management/server/instance"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	nbnetworks "github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	apiPrefix              = "/api"
	rateLimitingEnabledKey = "NB_API_RATE_LIMITING_ENABLED"
	rateLimitingBurstKey   = "NB_API_RATE_LIMITING_BURST"
	rateLimitingRPMKey     = "NB_API_RATE_LIMITING_RPM"
)

// NewAPIHandler creates the Management service HTTP API handler registering all the available endpoints.
func NewAPIHandler(ctx context.Context, accountManager account.Manager, networksManager nbnetworks.Manager, resourceManager resources.Manager, routerManager routers.Manager, groupsManager nbgroups.Manager, LocationManager geolocation.Geolocation, authManager auth.Manager, appMetrics telemetry.AppMetrics, integratedValidator integrated_validator.IntegratedValidator, proxyController port_forwarding.Controller, permissionsManager permissions.Manager, peersManager nbpeers.Manager, settingsManager settings.Manager, zManager zones.Manager, rManager records.Manager, networkMapController network_map.Controller, idpManager idpmanager.Manager, reverseProxyManager reverseproxy.Manager, reverseProxyDomainManager *manager.Manager, reverseProxyAccessLogsManager accesslogs.Manager, proxyGRPCServer *nbgrpc.ProxyServiceServer, trustedHTTPProxies []netip.Prefix) (http.Handler, error) {

	// Register bypass paths for unauthenticated endpoints
	if err := bypass.AddBypassPath("/api/instance"); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}
	if err := bypass.AddBypassPath("/api/setup"); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}
	// Public invite endpoints (tokens start with nbi_)
	if err := bypass.AddBypassPath("/api/users/invites/nbi_*"); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}
	if err := bypass.AddBypassPath("/api/users/invites/nbi_*/accept"); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}
	// OAuth callback for proxy authentication
	if err := bypass.AddBypassPath(types.ProxyCallbackEndpointFull); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}

	var rateLimitingConfig *middleware.RateLimiterConfig
	if os.Getenv(rateLimitingEnabledKey) == "true" {
		rpm := 6
		if v := os.Getenv(rateLimitingRPMKey); v != "" {
			value, err := strconv.Atoi(v)
			if err != nil {
				log.Warnf("parsing %s env var: %v, using default %d", rateLimitingRPMKey, err, rpm)
			} else {
				rpm = value
			}
		}

		burst := 500
		if v := os.Getenv(rateLimitingBurstKey); v != "" {
			value, err := strconv.Atoi(v)
			if err != nil {
				log.Warnf("parsing %s env var: %v, using default %d", rateLimitingBurstKey, err, burst)
			} else {
				burst = value
			}
		}

		rateLimitingConfig = &middleware.RateLimiterConfig{
			RequestsPerMinute: float64(rpm),
			Burst:             burst,
			CleanupInterval:   6 * time.Hour,
			LimiterTTL:        24 * time.Hour,
		}
	}

	authMiddleware := middleware.NewAuthMiddleware(
		authManager,
		accountManager.GetAccountIDFromUserAuth,
		accountManager.SyncUserJWTGroups,
		accountManager.GetUserFromUserAuth,
		rateLimitingConfig,
		appMetrics.GetMeter(),
	)

	corsMiddleware := cors.AllowAll()

	rootRouter := mux.NewRouter()
	metricsMiddleware := appMetrics.HTTPMiddleware()

	prefix := apiPrefix
	router := rootRouter.PathPrefix(prefix).Subrouter()

	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler)

	if _, err := integrations.RegisterHandlers(ctx, prefix, router, accountManager, integratedValidator, appMetrics.GetMeter(), permissionsManager, peersManager, proxyController, settingsManager); err != nil {
		return nil, fmt.Errorf("register integrations endpoints: %w", err)
	}

	// Check if embedded IdP is enabled for instance manager
	embeddedIdP, embeddedIdpEnabled := idpManager.(*idpmanager.EmbeddedIdPManager)
	instanceManager, err := nbinstance.NewManager(ctx, accountManager.GetStore(), embeddedIdP)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance manager: %w", err)
	}

	accounts.AddEndpoints(accountManager, settingsManager, router)
	peers.AddEndpoints(accountManager, router, networkMapController, permissionsManager)
	users.AddEndpoints(accountManager, router)
	users.AddInvitesEndpoints(accountManager, router)
	users.AddPublicInvitesEndpoints(accountManager, router)
	setup_keys.AddEndpoints(accountManager, router)
	policies.AddEndpoints(accountManager, LocationManager, router)
	policies.AddPostureCheckEndpoints(accountManager, LocationManager, router)
	policies.AddLocationsEndpoints(accountManager, LocationManager, permissionsManager, router)
	groups.AddEndpoints(accountManager, router)
	routes.AddEndpoints(accountManager, router)
	dns.AddEndpoints(accountManager, router)
	events.AddEndpoints(accountManager, router)
	networks.AddEndpoints(networksManager, resourceManager, routerManager, groupsManager, accountManager, router)
	zonesManager.RegisterEndpoints(router, zManager)
	recordsManager.RegisterEndpoints(router, rManager)
	idp.AddEndpoints(accountManager, router)
	instance.AddEndpoints(instanceManager, router)
	instance.AddVersionEndpoint(instanceManager, router)
	if reverseProxyManager != nil && reverseProxyDomainManager != nil {
		reverseproxymanager.RegisterEndpoints(reverseProxyManager, *reverseProxyDomainManager, reverseProxyAccessLogsManager, router)
	}

	// Register OAuth callback handler for proxy authentication
	if proxyGRPCServer != nil {
		oauthHandler := proxy.NewAuthCallbackHandler(proxyGRPCServer, trustedHTTPProxies)
		oauthHandler.RegisterEndpoints(router)
	}

	// Mount embedded IdP handler at /oauth2 path if configured
	if embeddedIdpEnabled {
		rootRouter.PathPrefix("/oauth2").Handler(corsMiddleware.Handler(embeddedIdP.Handler()))
	}

	return rootRouter, nil
}

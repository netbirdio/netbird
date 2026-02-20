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

type APIHandlerDeps struct {
	AccountManager            account.Manager
	NetworksManager           nbnetworks.Manager
	ResourceManager           resources.Manager
	RouterManager             routers.Manager
	GroupsManager             nbgroups.Manager
	LocationManager           geolocation.Geolocation
	AuthManager               auth.Manager
	AppMetrics                telemetry.AppMetrics
	IntegratedValidator       integrated_validator.IntegratedValidator
	ProxyController           port_forwarding.Controller
	PermissionsManager        permissions.Manager
	PeersManager              nbpeers.Manager
	SettingsManager           settings.Manager
	ZonesManager              zones.Manager
	RecordsManager            records.Manager
	NetworkMapController      network_map.Controller
	IdpManager                idpmanager.Manager
	ReverseProxyManager       reverseproxy.Manager
	ReverseProxyDomainManager *manager.Manager
	ReverseProxyAccessLogs    accesslogs.Manager
	ProxyGRPCServer           *nbgrpc.ProxyServiceServer
	TrustedHTTPProxies        []netip.Prefix
	EnableDeploymentMaturity  bool
}

const (
	apiPrefix              = "/api"
	rateLimitingEnabledKey = "NB_API_RATE_LIMITING_ENABLED"
	rateLimitingBurstKey   = "NB_API_RATE_LIMITING_BURST"
	rateLimitingRPMKey     = "NB_API_RATE_LIMITING_RPM"
)

// NewAPIHandler creates the Management service HTTP API handler registering all the available endpoints.
func NewAPIHandler(ctx context.Context, deps APIHandlerDeps) (http.Handler, error) {
	if err := registerBypassPaths(apiPrefix); err != nil {
		return nil, err
	}

	rootRouter := mux.NewRouter()
	prefix := apiPrefix
	router := rootRouter.PathPrefix(prefix).Subrouter()

	setupMiddleware(router, deps)

	if err := registerIntegrations(ctx, router, deps); err != nil {
		return nil, err
	}

	embeddedIdP, embeddedIdpEnabled := deps.IdpManager.(*idpmanager.EmbeddedIdPManager)
	instanceManager, err := nbinstance.NewManager(ctx, deps.AccountManager.GetStore(), embeddedIdP)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance manager: %w", err)
	}

	registerCoreEndpoints(router, deps, instanceManager)
	registerReverseProxyAndOAuth(router, deps)

	if embeddedIdpEnabled {
		corsMiddleware := cors.AllowAll()
		rootRouter.PathPrefix("/oauth2").Handler(corsMiddleware.Handler(embeddedIdP.Handler()))
	}

	return rootRouter, nil
}

func registerBypassPaths(prefix string) error {
	if err := bypass.AddBypassPath(prefix + "/instance"); err != nil {
		return fmt.Errorf("failed to add bypass path: %w", err)
	}

	if err := bypass.AddBypassPath(prefix + "/setup"); err != nil {
		return fmt.Errorf("failed to add bypass path: %w", err)
	}

	if err := bypass.AddBypassPath(prefix + "/users/invites/nbi_*"); err != nil {
		return fmt.Errorf("failed to add bypass path: %w", err)
	}

	if err := bypass.AddBypassPath(prefix + "/users/invites/nbi_*/accept"); err != nil {
		return fmt.Errorf("failed to add bypass path: %w", err)
	}

	if err := bypass.AddBypassPath(types.ProxyCallbackEndpointFull); err != nil {
		return fmt.Errorf("failed to add bypass path: %w", err)
	}

	return nil
}

func setupMiddleware(router *mux.Router, deps APIHandlerDeps) {
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
		deps.AuthManager,
		deps.AccountManager.GetAccountIDFromUserAuth,
		deps.AccountManager.SyncUserJWTGroups,
		deps.AccountManager.GetUserFromUserAuth,
		rateLimitingConfig,
		deps.AppMetrics.GetMeter(),
	)

	corsMiddleware := cors.AllowAll()
	metricsMiddleware := deps.AppMetrics.HTTPMiddleware()

	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler)
}

func registerIntegrations(ctx context.Context, router *mux.Router, deps APIHandlerDeps) error {
	prefix := apiPrefix
	if _, err := integrations.RegisterHandlers(
		ctx,
		prefix,
		router,
		deps.AccountManager,
		deps.IntegratedValidator,
		deps.AppMetrics.GetMeter(),
		deps.PermissionsManager,
		deps.PeersManager,
		deps.ProxyController,
		deps.SettingsManager,
	); err != nil {
		return fmt.Errorf("register integrations endpoints: %w", err)
	}

	return nil
}

func registerCoreEndpoints(router *mux.Router, deps APIHandlerDeps, instanceManager nbinstance.Manager) {
	accounts.AddEndpoints(deps.AccountManager, deps.SettingsManager, router, deps.EnableDeploymentMaturity)
	peers.AddEndpoints(deps.AccountManager, router, deps.NetworkMapController, deps.PermissionsManager)
	users.AddEndpoints(deps.AccountManager, router)
	users.AddInvitesEndpoints(deps.AccountManager, router)
	users.AddPublicInvitesEndpoints(deps.AccountManager, router)
	setup_keys.AddEndpoints(deps.AccountManager, router)
	policies.AddEndpoints(deps.AccountManager, deps.LocationManager, router)
	policies.AddPostureCheckEndpoints(deps.AccountManager, deps.LocationManager, router)
	policies.AddLocationsEndpoints(deps.AccountManager, deps.LocationManager, deps.PermissionsManager, router)
	groups.AddEndpoints(deps.AccountManager, router)
	routes.AddEndpoints(deps.AccountManager, router)
	dns.AddEndpoints(deps.AccountManager, router)
	events.AddEndpoints(deps.AccountManager, router)
	networks.AddEndpoints(
		deps.NetworksManager,
		deps.ResourceManager,
		deps.RouterManager,
		deps.GroupsManager,
		deps.AccountManager,
		router,
	)
	zonesManager.RegisterEndpoints(router, deps.ZonesManager)
	recordsManager.RegisterEndpoints(router, deps.RecordsManager)
	idp.AddEndpoints(deps.AccountManager, router)
	instance.AddEndpoints(instanceManager, router)
	instance.AddVersionEndpoint(instanceManager, router)
}

func registerReverseProxyAndOAuth(router *mux.Router, deps APIHandlerDeps) {
	if deps.ReverseProxyManager != nil && deps.ReverseProxyDomainManager != nil {
		reverseproxymanager.RegisterEndpoints(
			deps.ReverseProxyManager,
			*deps.ReverseProxyDomainManager,
			deps.ReverseProxyAccessLogs,
			router,
		)
	}

	if deps.ProxyGRPCServer != nil {
		oauthHandler := proxy.NewAuthCallbackHandler(deps.ProxyGRPCServer, deps.TrustedHTTPProxies)
		oauthHandler.RegisterEndpoints(router)
	}
}

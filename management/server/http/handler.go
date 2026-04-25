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

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	reverseproxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service/manager"

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
	"github.com/netbirdio/netbird/management/server/http/handlers/entra_device_auth"
	"github.com/netbirdio/netbird/management/server/http/handlers/setup_keys"
	entra_device "github.com/netbirdio/netbird/management/server/integrations/entra_device"
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

// APIHandlerOptions bundles the dependencies NewAPIHandler needs.
//
// Aggregating these into a single struct keeps NewAPIHandler under
// SonarCloud's go:S107 (>7 parameters) limit and reduces the cognitive
// complexity SonarCloud measures via go:S3776. Callers populate the struct
// once during application bootstrap or test setup and pass it in by value.
type APIHandlerOptions struct {
	AccountManager                account.Manager
	NetworksManager               nbnetworks.Manager
	ResourceManager               resources.Manager
	RouterManager                 routers.Manager
	GroupsManager                 nbgroups.Manager
	LocationManager               geolocation.Geolocation
	AuthManager                   auth.Manager
	AppMetrics                    telemetry.AppMetrics
	IntegratedValidator           integrated_validator.IntegratedValidator
	ProxyController               port_forwarding.Controller
	PermissionsManager            permissions.Manager
	PeersManager                  nbpeers.Manager
	SettingsManager               settings.Manager
	ZonesManager                  zones.Manager
	RecordsManager                records.Manager
	NetworkMapController          network_map.Controller
	IdpManager                    idpmanager.Manager
	ServiceManager                service.Manager
	ReverseProxyDomainManager     *manager.Manager
	ReverseProxyAccessLogsManager accesslogs.Manager
	ProxyGRPCServer               *nbgrpc.ProxyServiceServer
	TrustedHTTPProxies            []netip.Prefix
}

// NewAPIHandler creates the Management service HTTP API handler registering all the available endpoints.
func NewAPIHandler(ctx context.Context, opts APIHandlerOptions) (http.Handler, error) {
	if err := addBypassPaths(); err != nil {
		return nil, err
	}

	rateLimitingConfig := buildRateLimiterFromEnv(ctx)

	authMiddleware := middleware.NewAuthMiddleware(
		opts.AuthManager,
		opts.AccountManager.GetAccountIDFromUserAuth,
		opts.AccountManager.SyncUserJWTGroups,
		opts.AccountManager.GetUserFromUserAuth,
		rateLimitingConfig,
		opts.AppMetrics.GetMeter(),
	)
	corsMiddleware := cors.AllowAll()

	rootRouter := mux.NewRouter()
	metricsMiddleware := opts.AppMetrics.HTTPMiddleware()

	prefix := apiPrefix
	router := rootRouter.PathPrefix(prefix).Subrouter()
	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler)

	if _, err := integrations.RegisterHandlers(ctx, prefix, router,
		opts.AccountManager, opts.IntegratedValidator, opts.AppMetrics.GetMeter(),
		opts.PermissionsManager, opts.PeersManager, opts.ProxyController, opts.SettingsManager); err != nil {
		return nil, fmt.Errorf("register integrations endpoints: %w", err)
	}

	embeddedIdP, embeddedIdpEnabled := opts.IdpManager.(*idpmanager.EmbeddedIdPManager)
	instanceManager, err := nbinstance.NewManager(ctx, opts.AccountManager.GetStore(), embeddedIdP)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance manager: %w", err)
	}

	registerCoreEndpoints(ctx, opts, rootRouter, router, instanceManager)

	if embeddedIdpEnabled {
		rootRouter.PathPrefix("/oauth2").Handler(corsMiddleware.Handler(embeddedIdP.Handler()))
	}
	return rootRouter, nil
}

// addBypassPaths registers all the unauthenticated routes that the auth
// middleware on the /api subrouter must skip. Entra device enrolment
// endpoints live on /join/entra directly on the root router and therefore
// never flow through the /api auth middleware, so they don't need a bypass
// registration here.
func addBypassPaths() error {
	paths := []string{
		"/api/instance",
		"/api/setup",
		// Public invite endpoints (tokens start with nbi_).
		"/api/users/invites/nbi_*",
		"/api/users/invites/nbi_*/accept",
		// OAuth callback for proxy authentication.
		types.ProxyCallbackEndpointFull,
	}
	for _, p := range paths {
		if err := bypass.AddBypassPath(p); err != nil {
			return fmt.Errorf("failed to add bypass path %q: %w", p, err)
		}
	}
	return nil
}

// buildRateLimiterFromEnv returns a non-nil RateLimiterConfig only when the
// NB_API_RATE_LIMITING_ENABLED env var is "true". Extracted from
// NewAPIHandler so that function stays under the project-wide cognitive
// complexity threshold.
func buildRateLimiterFromEnv(ctx context.Context) *middleware.RateLimiterConfig {
	if os.Getenv(rateLimitingEnabledKey) != "true" {
		return nil
	}
	return &middleware.RateLimiterConfig{
		RequestsPerMinute: float64(parseIntEnv(ctx, rateLimitingRPMKey, 6)),
		Burst:             parseIntEnv(ctx, rateLimitingBurstKey, 500),
		CleanupInterval:   6 * time.Hour,
		LimiterTTL:        24 * time.Hour,
	}
}

// parseIntEnv returns the integer value of `name` from the environment, or
// `fallback` if unset or unparseable. A non-empty value that fails to parse
// is logged as a warning so operators don't silently end up with the
// default.
func parseIntEnv(ctx context.Context, name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		log.WithContext(ctx).Warnf("parsing %s env var: %v, using default %d", name, err, fallback)
		return fallback
	}
	return v
}

// registerCoreEndpoints wires every per-feature HTTP endpoint group onto the
// authenticated /api subrouter. Extracted from NewAPIHandler to keep that
// function below SonarCloud's cognitive complexity threshold.
func registerCoreEndpoints(
	ctx context.Context,
	opts APIHandlerOptions,
	rootRouter *mux.Router,
	router *mux.Router,
	instanceManager nbinstance.Manager,
) {
	accounts.AddEndpoints(opts.AccountManager, opts.SettingsManager, router)
	peers.AddEndpoints(opts.AccountManager, router, opts.NetworkMapController, opts.PermissionsManager)
	users.AddEndpoints(opts.AccountManager, router)
	users.AddInvitesEndpoints(opts.AccountManager, router)
	users.AddPublicInvitesEndpoints(opts.AccountManager, router)
	setup_keys.AddEndpoints(opts.AccountManager, router)

	installEntraDeviceAuth(ctx, opts.AccountManager, rootRouter, router, opts.PermissionsManager)

	policies.AddEndpoints(opts.AccountManager, opts.LocationManager, router)
	policies.AddPostureCheckEndpoints(opts.AccountManager, opts.LocationManager, router)
	policies.AddLocationsEndpoints(opts.AccountManager, opts.LocationManager, opts.PermissionsManager, router)
	groups.AddEndpoints(opts.AccountManager, router)
	routes.AddEndpoints(opts.AccountManager, router)
	dns.AddEndpoints(opts.AccountManager, router)
	events.AddEndpoints(opts.AccountManager, router)
	networks.AddEndpoints(opts.NetworksManager, opts.ResourceManager, opts.RouterManager, opts.GroupsManager, opts.AccountManager, router)
	zonesManager.RegisterEndpoints(router, opts.ZonesManager)
	recordsManager.RegisterEndpoints(router, opts.RecordsManager)
	idp.AddEndpoints(opts.AccountManager, router)
	instance.AddEndpoints(instanceManager, router)
	instance.AddVersionEndpoint(instanceManager, router)

	if opts.ServiceManager != nil && opts.ReverseProxyDomainManager != nil {
		reverseproxymanager.RegisterEndpoints(opts.ServiceManager, *opts.ReverseProxyDomainManager,
			opts.ReverseProxyAccessLogsManager, opts.PermissionsManager, router)
	}
	if opts.ProxyGRPCServer != nil {
		oauthHandler := proxy.NewAuthCallbackHandler(opts.ProxyGRPCServer, opts.TrustedHTTPProxies)
		oauthHandler.RegisterEndpoints(router)
	}
}

// installEntraDeviceAuth wires up the Entra/Intune device authentication
// integration. It is a best-effort install: the integration is only mounted
// if the account manager's store exposes a gorm.DB and the manager itself
// can produce a PeerEnroller (via the unexported AsEntraDevicePeerEnroller
// method on DefaultAccountManager).
func installEntraDeviceAuth(
	ctx context.Context,
	accountManager account.Manager,
	rootRouter *mux.Router,
	adminRouter *mux.Router,
	permissionsManager permissions.Manager,
) {
	dbProvider, ok := accountManager.GetStore().(entra_device_auth.DBProvider)
	if !ok {
		log.WithContext(ctx).Errorf("Entra device auth: store %T does not implement entra_device_auth.DBProvider; admin endpoints and /join/entra will be unavailable", accountManager.GetStore())
		return
	}
	enrollerProvider, ok := accountManager.(interface {
		AsEntraDevicePeerEnroller() entra_device.PeerEnroller
	})
	if !ok {
		log.WithContext(ctx).Errorf("Entra device auth: account manager %T does not implement AsEntraDevicePeerEnroller; admin endpoints and /join/entra will be unavailable", accountManager)
		return
	}
	if _, err := entra_device_auth.Install(entra_device_auth.Wiring{
		RootRouter:   rootRouter,
		AdminRouter:  adminRouter,
		DB:           dbProvider,
		PeerEnroller: enrollerProvider.AsEntraDevicePeerEnroller(),
		Permissions:  permissionsManager,
	}); err != nil {
		log.WithContext(ctx).Errorf("Entra device auth install failed: %v", err)
	}
}

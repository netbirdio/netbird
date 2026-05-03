package http

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

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
	"github.com/netbirdio/netbird/management/server/peer_connections"

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
	peer_connections_http "github.com/netbirdio/netbird/management/server/http/handlers/peer_connections"
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
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const apiPrefix = "/api"

// APIHandler wraps the HTTP router and holds shared state for all HTTP handlers.
// The peerConnections and snapshotRouter fields are constructed once in boot.go
// and shared with the gRPC server so both sides see the same in-memory state.
// Phase 3.7i of #5989; HTTP routes that consume these are registered in Task 4.2.
type APIHandler struct {
	http.Handler

	peerConnections peer_connections.Store
	snapshotRouter  *peer_connections.SnapshotRouter
}

// NewAPIHandler creates the Management service HTTP API handler registering all the available endpoints.
func NewAPIHandler(ctx context.Context, accountManager account.Manager, networksManager nbnetworks.Manager, resourceManager resources.Manager, routerManager routers.Manager, groupsManager nbgroups.Manager, LocationManager geolocation.Geolocation, authManager auth.Manager, appMetrics telemetry.AppMetrics, integratedValidator integrated_validator.IntegratedValidator, proxyController port_forwarding.Controller, permissionsManager permissions.Manager, peersManager nbpeers.Manager, settingsManager settings.Manager, zManager zones.Manager, rManager records.Manager, networkMapController network_map.Controller, idpManager idpmanager.Manager, serviceManager service.Manager, reverseProxyDomainManager *manager.Manager, reverseProxyAccessLogsManager accesslogs.Manager, proxyGRPCServer *nbgrpc.ProxyServiceServer, trustedHTTPProxies []netip.Prefix, rateLimiter *middleware.APIRateLimiter, peerConnStore peer_connections.Store, peerConnRouter *peer_connections.SnapshotRouter) (*APIHandler, error) {

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

	if rateLimiter == nil {
		log.Warn("NewAPIHandler: nil rate limiter, rate limiting disabled")
		rateLimiter = middleware.NewAPIRateLimiter(nil)
		rateLimiter.SetEnabled(false)
	}

	authMiddleware := middleware.NewAuthMiddleware(
		authManager,
		accountManager.GetAccountIDFromUserAuth,
		accountManager.SyncUserJWTGroups,
		accountManager.GetUserFromUserAuth,
		rateLimiter,
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

	// Phase 3.7i of #5989: peer connection-map REST routes.
	peerConnHandler := peer_connections_http.NewHandler(
		peerConnStore,
		&pcAccountManagerAdapter{am: accountManager, nmc: networkMapController},
		peerConnRouter,
	)
	router.HandleFunc("/peers/{peerId}/connections", peerConnHandler.GetPeerConnections).Methods("GET", "OPTIONS")
	router.HandleFunc("/peers/{peerId}/connections/refresh", peerConnHandler.PostRefresh).Methods("POST", "OPTIONS")

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
	instance.AddEndpoints(instanceManager, accountManager, router)
	instance.AddVersionEndpoint(instanceManager, router)
	if serviceManager != nil && reverseProxyDomainManager != nil {
		reverseproxymanager.RegisterEndpoints(serviceManager, *reverseProxyDomainManager, reverseProxyAccessLogsManager, permissionsManager, router)
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

	return &APIHandler{
		Handler:         rootRouter,
		peerConnections: peerConnStore,
		snapshotRouter:  peerConnRouter,
	}, nil
}

// pcAccountManagerAdapter bridges the real account.Manager into the small
// interface peer_connections.Handler uses. Phase 3.7i of #5989.
type pcAccountManagerAdapter struct {
	am  account.Manager
	nmc network_map.Controller
}

func (a *pcAccountManagerAdapter) GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error) {
	return a.am.GetPeer(ctx, accountID, peerID, userID)
}

func (a *pcAccountManagerAdapter) GetPeerByPubKey(ctx context.Context, accountID, pubKey string) (*nbpeer.Peer, error) {
	return a.am.GetPeerByPubKey(ctx, accountID, pubKey)
}

// GetDNSDomain resolves the configured DNS domain for the account.
// It reads the account settings and delegates to the networkMapController
// which applies the global default when the account has no custom domain.
// Falls back to "" on error — FQDN enrichment in the handler is best-effort.
func (a *pcAccountManagerAdapter) GetDNSDomain(ctx context.Context, accountID string) string {
	settings, err := a.am.GetAccountSettings(ctx, accountID, "internal")
	if err != nil {
		return ""
	}
	if a.nmc == nil {
		if settings != nil {
			return settings.DNSDomain
		}
		return ""
	}
	return a.nmc.GetDNSDomain(settings)
}

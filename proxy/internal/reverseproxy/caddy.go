package reverseproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/logging"
	log "github.com/sirupsen/logrus"
)

// CaddyProxy wraps Caddy's reverse proxy functionality
type CaddyProxy struct {
	config          Config
	mu              sync.RWMutex
	isRunning       bool
	routes          map[string]*RouteConfig // key is route ID
	requestCallback RequestDataCallback
	// customHandlers stores handlers with custom transports that can't be JSON-serialized
	// key is "routeID:path" to uniquely identify each handler
	customHandlers map[string]*reverseproxy.Handler
}

// Config holds the reverse proxy configuration
type Config struct {
	// ListenAddress is the address to listen on
	ListenAddress string

	// EnableHTTPS enables automatic HTTPS with Let's Encrypt
	EnableHTTPS bool

	// TLSEmail is the email for Let's Encrypt registration
	TLSEmail string

	// RequestDataCallback is called for each proxied request with metrics
	RequestDataCallback RequestDataCallback
}

// RouteConfig defines a routing configuration
type RouteConfig struct {
	// ID is a unique identifier for this route
	ID string

	// Domain is the domain to listen on (e.g., "example.com" or "*" for all)
	Domain string

	// PathMappings defines paths that should be forwarded to specific ports
	// Key is the path prefix (e.g., "/", "/api", "/admin")
	// Value is the target IP:port (e.g., "192.168.1.100:3000")
	// Must have at least one entry. Use "/" or "" for the default/catch-all route.
	PathMappings map[string]string

	// Conn is an optional existing network connection to use for this route
	// This allows routing through specific tunnels (e.g., WireGuard) per route
	// If set, this connection will be reused for all requests to this route
	Conn net.Conn

	// CustomDialer is an optional custom dialer for this specific route
	// This is used if Conn is not set. It allows using different network connections per route
	CustomDialer func(ctx context.Context, network, address string) (net.Conn, error)
}

// New creates a new Caddy-based reverse proxy
func New(config Config) (*CaddyProxy, error) {
	// Default to port 443 if not specified
	if config.ListenAddress == "" {
		config.ListenAddress = ":443"
	}

	cp := &CaddyProxy{
		config:          config,
		isRunning:       false,
		routes:          make(map[string]*RouteConfig),
		requestCallback: config.RequestDataCallback,
		customHandlers:  make(map[string]*reverseproxy.Handler),
	}

	return cp, nil
}

// Start starts the Caddy reverse proxy server
func (cp *CaddyProxy) Start() error {
	cp.mu.Lock()
	if cp.isRunning {
		cp.mu.Unlock()
		return fmt.Errorf("reverse proxy already running")
	}
	cp.isRunning = true
	cp.mu.Unlock()

	// Build Caddy configuration
	cfg, err := cp.buildCaddyConfig()
	if err != nil {
		cp.mu.Lock()
		cp.isRunning = false
		cp.mu.Unlock()
		return fmt.Errorf("failed to build Caddy config: %w", err)
	}

	// Run Caddy with the configuration
	err = caddy.Run(cfg)
	if err != nil {
		cp.mu.Lock()
		cp.isRunning = false
		cp.mu.Unlock()
		return fmt.Errorf("failed to run Caddy: %w", err)
	}

	log.Infof("Caddy reverse proxy started on %s", cp.config.ListenAddress)
	log.Infof("Configured %d route(s)", len(cp.routes))

	return nil
}

// Stop gracefully stops the Caddy reverse proxy
func (cp *CaddyProxy) Stop(ctx context.Context) error {
	cp.mu.Lock()
	if !cp.isRunning {
		cp.mu.Unlock()
		return fmt.Errorf("reverse proxy not running")
	}
	cp.mu.Unlock()

	log.Info("Stopping Caddy reverse proxy...")

	// Stop Caddy
	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("failed to stop Caddy: %w", err)
	}

	cp.mu.Lock()
	cp.isRunning = false
	cp.mu.Unlock()

	log.Info("Caddy reverse proxy stopped")
	return nil
}

// buildCaddyConfig builds the Caddy configuration
func (cp *CaddyProxy) buildCaddyConfig() (*caddy.Config, error) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	if len(cp.routes) == 0 {
		// Create a default empty server that returns 404
		httpServer := &caddyhttp.Server{
			Listen: []string{cp.config.ListenAddress},
			Routes: caddyhttp.RouteList{},
		}

		httpApp := &caddyhttp.App{
			Servers: map[string]*caddyhttp.Server{
				"proxy": httpServer,
			},
		}

		cfg := &caddy.Config{
			Admin: &caddy.AdminConfig{
				Disabled: true,
			},
			AppsRaw: caddy.ModuleMap{
				"http": caddyconfig.JSON(httpApp, nil),
			},
		}

		return cfg, nil
	}

	// Build routes grouped by domain
	domainRoutes := make(map[string][]caddyhttp.Route)
	// Track unique service IDs for logger configuration
	serviceIDs := make(map[string]bool)

	for _, routeConfig := range cp.routes {
		domain := routeConfig.Domain
		if domain == "" {
			domain = "*" // wildcard for all domains
		}

		// Register callback for this service ID
		if cp.requestCallback != nil {
			RegisterCallback(routeConfig.ID, cp.requestCallback)
			serviceIDs[routeConfig.ID] = true
		}

		// Sort path mappings by path length (longest first) for proper matching
		// This ensures more specific paths match before catch-all paths
		paths := make([]string, 0, len(routeConfig.PathMappings))
		for path := range routeConfig.PathMappings {
			paths = append(paths, path)
		}
		sort.Slice(paths, func(i, j int) bool {
			// Sort by length descending, but put empty string last (catch-all)
			if paths[i] == "" || paths[i] == "/" {
				return false
			}
			if paths[j] == "" || paths[j] == "/" {
				return true
			}
			return len(paths[i]) > len(paths[j])
		})

		// Create routes for each path mapping
		for _, path := range paths {
			target := routeConfig.PathMappings[path]
			route := cp.createRoute(routeConfig, path, target)
			domainRoutes[domain] = append(domainRoutes[domain], route)
		}
	}

	// Build Caddy routes
	var caddyRoutes caddyhttp.RouteList
	for domain, routes := range domainRoutes {
		if domain != "*" {
			// Add host matcher for specific domains
			for i := range routes {
				routes[i].MatcherSetsRaw = []caddy.ModuleMap{
					{
						"host": caddyconfig.JSON(caddyhttp.MatchHost{domain}, nil),
					},
				}
			}
		}
		caddyRoutes = append(caddyRoutes, routes...)
	}

	// Create HTTP server with access logging if callback is set
	httpServer := &caddyhttp.Server{
		Listen: []string{cp.config.ListenAddress},
		Routes: caddyRoutes,
	}

	// Configure server logging if callback is set
	if cp.requestCallback != nil {
		httpServer.Logs = &caddyhttp.ServerLogConfig{
			// Use our custom logger for access logs
			LoggerNames: map[string]caddyhttp.StringArray{
				"http.log.access": {"http_access"},
			},
			// Disable default access logging (only use custom logger)
			ShouldLogCredentials: false,
		}
	}

	// Disable automatic HTTPS if not enabled
	if !cp.config.EnableHTTPS {
		// Explicitly disable automatic HTTPS for the server
		httpServer.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{
			Disabled: true,
		}
	}

	// Build HTTP app
	httpApp := &caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{
			"proxy": httpServer,
		},
	}

	// Provision the HTTP app to set up handlers from JSON
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := httpApp.Provision(ctx); err != nil {
		return nil, fmt.Errorf("failed to provision HTTP app: %w", err)
	}

	// After provisioning, inject custom transports into handlers
	// This is done post-provisioning so the Transport field is preserved
	if err := cp.injectCustomTransports(httpApp); err != nil {
		return nil, fmt.Errorf("failed to inject custom transports: %w", err)
	}

	// Create Caddy config with the provisioned app
	// IMPORTANT: We pass the already-provisioned app, not JSON
	// This preserves the Transport fields we set
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
		},
		// Apps field takes already-provisioned apps
		Apps: map[string]caddy.App{
			"http": httpApp,
		},
	}

	// Configure logging if callback is set
	if cp.requestCallback != nil {
		// Register the callback for the proxy service ID
		RegisterCallback("proxy", cp.requestCallback)

		// Build logging config with proper module names
		cfg.Logging = &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"http_access": {
					BaseLog: caddy.BaseLog{
						WriterRaw:  caddyconfig.JSONModuleObject(&CallbackWriter{ServiceID: "proxy"}, "output", "callback", nil),
						EncoderRaw: caddyconfig.JSONModuleObject(&logging.JSONEncoder{}, "format", "json", nil),
						Level:      "INFO",
					},
					Include: []string{"http.log.access"},
				},
			},
		}

		log.Infof("Configured custom logging with callback writer for service: proxy")
	}

	return cfg, nil
}

// createRoute creates a Caddy route for a path and target with service ID tracking
func (cp *CaddyProxy) createRoute(routeConfig *RouteConfig, path, target string) caddyhttp.Route {
	// Check if this route needs a custom transport
	hasCustomTransport := routeConfig.Conn != nil || routeConfig.CustomDialer != nil

	if hasCustomTransport {
		// For routes with custom transports, store them separately
		// and configure the upstream to use a special dial address that we'll intercept
		handlerKey := fmt.Sprintf("%s:%s", routeConfig.ID, path)

		// Create upstream with custom dial configuration
		upstream := &reverseproxy.Upstream{
			Dial: target,
		}

		// Create the reverse proxy handler with custom transport
		handler := &reverseproxy.Handler{
			Upstreams: reverseproxy.UpstreamPool{upstream},
		}

		// Configure the custom transport
		if routeConfig.Conn != nil {
			// Use the provided connection directly
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					log.Debugf("Reusing existing connection for route %s to %s", routeConfig.ID, address)
					return routeConfig.Conn, nil
				},
				MaxIdleConns:          1,
				MaxIdleConnsPerHost:   1,
				IdleConnTimeout:       0,
				DisableKeepAlives:     false,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
			handler.Transport = transport
			log.Infof("Configured net.Conn transport for route %s (path: %s)", routeConfig.ID, path)
		} else if routeConfig.CustomDialer != nil {
			// Use the custom dialer function
			transport := &http.Transport{
				DialContext:           routeConfig.CustomDialer,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
			handler.Transport = transport
			log.Infof("Configured custom dialer transport for route %s (path: %s)", routeConfig.ID, path)
		}

		// Store the handler for later injection
		cp.customHandlers[handlerKey] = handler

		// Create route using HandlersRaw with a placeholder that will be replaced
		// We'll use JSON serialization here, but inject the real handler after Caddy loads
		route := caddyhttp.Route{
			HandlersRaw: []json.RawMessage{
				caddyconfig.JSONModuleObject(handler, "handler", "reverse_proxy", nil),
			},
		}

		if path != "" {
			route.MatcherSetsRaw = []caddy.ModuleMap{
				{
					"path": caddyconfig.JSON(caddyhttp.MatchPath{path + "*"}, nil),
				},
			}
		}

		return route
	}

	// Standard route without custom transport
	upstream := &reverseproxy.Upstream{
		Dial: target,
	}

	handler := &reverseproxy.Handler{
		Upstreams: reverseproxy.UpstreamPool{upstream},
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(handler, "handler", "reverse_proxy", nil),
		},
	}

	if path != "" {
		route.MatcherSetsRaw = []caddy.ModuleMap{
			{
				"path": caddyconfig.JSON(caddyhttp.MatchPath{path + "*"}, nil),
			},
		}
	}

	return route
}

// IsRunning returns whether the proxy is running
func (cp *CaddyProxy) IsRunning() bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.isRunning
}

// GetConfig returns the proxy configuration
func (cp *CaddyProxy) GetConfig() Config {
	return cp.config
}

// AddRoute adds a new route configuration to the proxy
// If the proxy is running, it will reload the configuration
func (cp *CaddyProxy) AddRoute(route *RouteConfig) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}
	if route.ID == "" {
		return fmt.Errorf("route ID is required")
	}
	if len(route.PathMappings) == 0 {
		return fmt.Errorf("route must have at least one path mapping")
	}

	cp.mu.Lock()
	// Check if route already exists
	if _, exists := cp.routes[route.ID]; exists {
		cp.mu.Unlock()
		return fmt.Errorf("route with ID %s already exists", route.ID)
	}

	// Add new route
	cp.routes[route.ID] = route
	isRunning := cp.isRunning
	cp.mu.Unlock()

	log.WithFields(log.Fields{
		"route_id": route.ID,
		"domain":   route.Domain,
		"paths":    len(route.PathMappings),
	}).Info("Added route")

	// Reload configuration if proxy is running
	if isRunning {
		if err := cp.reloadConfig(); err != nil {
			// Rollback: remove the route
			cp.mu.Lock()
			delete(cp.routes, route.ID)
			cp.mu.Unlock()
			return fmt.Errorf("failed to reload config after adding route: %w", err)
		}
	}

	return nil
}

// RemoveRoute removes a route from the proxy
// If the proxy is running, it will reload the configuration
func (cp *CaddyProxy) RemoveRoute(routeID string) error {
	cp.mu.Lock()
	// Check if route exists
	route, exists := cp.routes[routeID]
	if !exists {
		cp.mu.Unlock()
		return fmt.Errorf("route %s not found", routeID)
	}

	// Remove route
	delete(cp.routes, routeID)
	isRunning := cp.isRunning
	cp.mu.Unlock()

	log.Infof("Removed route: %s", routeID)

	// Reload configuration if proxy is running
	if isRunning {
		if err := cp.reloadConfig(); err != nil {
			// Rollback: add the route back
			cp.mu.Lock()
			cp.routes[routeID] = route
			cp.mu.Unlock()
			return fmt.Errorf("failed to reload config after removing route: %w", err)
		}
	}

	return nil
}

// UpdateRoute updates an existing route configuration
// If the proxy is running, it will reload the configuration
func (cp *CaddyProxy) UpdateRoute(route *RouteConfig) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}
	if route.ID == "" {
		return fmt.Errorf("route ID is required")
	}

	cp.mu.Lock()
	// Check if route exists
	oldRoute, exists := cp.routes[route.ID]
	if !exists {
		cp.mu.Unlock()
		return fmt.Errorf("route %s not found", route.ID)
	}

	// Update route
	cp.routes[route.ID] = route
	isRunning := cp.isRunning
	cp.mu.Unlock()

	log.WithFields(log.Fields{
		"route_id": route.ID,
		"domain":   route.Domain,
		"paths":    len(route.PathMappings),
	}).Info("Updated route")

	// Reload configuration if proxy is running
	if isRunning {
		if err := cp.reloadConfig(); err != nil {
			// Rollback: restore old route
			cp.mu.Lock()
			cp.routes[route.ID] = oldRoute
			cp.mu.Unlock()
			return fmt.Errorf("failed to reload config after updating route: %w", err)
		}
	}

	return nil
}

// ListRoutes returns a list of all configured route IDs
func (cp *CaddyProxy) ListRoutes() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	routes := make([]string, 0, len(cp.routes))
	for id := range cp.routes {
		routes = append(routes, id)
	}
	return routes
}

// GetRoute returns a route configuration by ID
func (cp *CaddyProxy) GetRoute(routeID string) (*RouteConfig, error) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	route, exists := cp.routes[routeID]
	if !exists {
		return nil, fmt.Errorf("route %s not found", routeID)
	}

	return route, nil
}

// injectCustomTransports injects custom transports into provisioned handlers
// This must be called after httpApp.Provision() but before passing to Caddy.Run()
func (cp *CaddyProxy) injectCustomTransports(httpApp *caddyhttp.App) error {
	// Iterate through all servers
	for serverName, server := range httpApp.Servers {
		log.Debugf("Injecting custom transports for server: %s", serverName)

		// Iterate through all routes
		for routeIdx, route := range server.Routes {
			// Iterate through all handlers in the route
			for handlerIdx, handler := range route.Handlers {
				// Check if this is a reverse proxy handler
				if rpHandler, ok := handler.(*reverseproxy.Handler); ok {
					// Try to find a matching custom handler for this route
					// We need to match by handler configuration since we don't have route metadata here
					for handlerKey, customHandler := range cp.customHandlers {
						// Check if the upstream configuration matches
						if len(rpHandler.Upstreams) > 0 && len(customHandler.Upstreams) > 0 {
							if rpHandler.Upstreams[0].Dial == customHandler.Upstreams[0].Dial {
								// Match found! Inject the custom transport
								rpHandler.Transport = customHandler.Transport
								log.Infof("Injected custom transport for route %d, handler %d (key: %s)", routeIdx, handlerIdx, handlerKey)
								break
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// reloadConfig rebuilds and reloads the Caddy configuration
// Must be called without holding the lock
func (cp *CaddyProxy) reloadConfig() error {
	log.Info("Reloading Caddy configuration...")

	cfg, err := cp.buildCaddyConfig()
	if err != nil {
		return fmt.Errorf("failed to build config: %w", err)
	}

	if err := caddy.Run(cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	log.Info("Caddy configuration reloaded successfully")
	return nil
}

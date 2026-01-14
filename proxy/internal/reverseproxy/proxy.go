package reverseproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"

	log "github.com/sirupsen/logrus"
)

// Proxy wraps a reverse proxy with dynamic routing
type Proxy struct {
	config          Config
	mu              sync.RWMutex
	routes          map[string]*RouteConfig // key is host/domain (for fast O(1) lookup)
	server          *http.Server
	httpServer      *http.Server
	autocertManager *autocert.Manager
	isRunning       bool
	requestCallback RequestDataCallback
}

// Config holds the reverse proxy configuration
type Config struct {
	// ListenAddress is the address to listen on for HTTPS (default ":443")
	ListenAddress string

	// HTTPListenAddress is the address for HTTP (default ":80")
	// Used for ACME challenges when HTTPS is enabled, or as main listener when HTTPS is disabled
	HTTPListenAddress string

	// EnableHTTPS enables automatic HTTPS with Let's Encrypt
	EnableHTTPS bool

	// TLSEmail is the email for Let's Encrypt registration
	TLSEmail string

	// CertCacheDir is the directory to cache certificates (default "./certs")
	CertCacheDir string

	// RequestDataCallback is called for each proxied request with metrics
	RequestDataCallback RequestDataCallback

	// OIDCConfig is the global OIDC/OAuth configuration for authentication
	// This is shared across all routes that use Bearer authentication
	// If nil, routes with Bearer auth will fail to initialize
	OIDCConfig *OIDCConfig
}

// OIDCConfig holds the global OIDC/OAuth configuration
type OIDCConfig struct {
	// OIDC Provider settings
	ProviderURL  string   `env:"NB_OIDC_PROVIDER_URL" json:"provider_url"`   // Identity provider URL (e.g., "https://accounts.google.com")
	ClientID     string   `env:"NB_OIDC_CLIENT_ID" json:"client_id"`         // OAuth client ID
	ClientSecret string   `env:"NB_OIDC_CLIENT_SECRET" json:"client_secret"` // OAuth client secret (empty for public clients)
	RedirectURL  string   `env:"NB_OIDC_REDIRECT_URL" json:"redirect_url"`   // Redirect URL after auth (e.g., "http://localhost:54321/auth/callback")
	Scopes       []string `env:"NB_OIDC_SCOPES" json:"scopes"`               // Requested scopes (default: ["openid", "profile", "email"])

	// JWT Validation settings
	JWTKeysLocation             string   `env:"NB_OIDC_JWT_KEYS_LOCATION" json:"jwt_keys_location"`                             // JWKS URL for fetching public keys
	JWTIssuer                   string   `env:"NB_OIDC_JWT_ISSUER" json:"jwt_issuer"`                                           // Expected issuer claim
	JWTAudience                 []string `env:"NB_OIDC_JWT_AUDIENCE" json:"jwt_audience"`                                       // Expected audience claims
	JWTIdpSignkeyRefreshEnabled bool     `env:"NB_OIDC_JWT_IDP_SIGNKEY_REFRESH_ENABLED" json:"jwt_idp_signkey_refresh_enabled"` // Enable automatic refresh of signing keys

	// Session settings
	SessionCookieName string `env:"NB_OIDC_SESSION_COOKIE_NAME" json:"session_cookie_name"` // Cookie name for storing session (default: "auth_session")
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

	// Conn is the network connection to use for this route
	// This allows routing through specific tunnels (e.g., WireGuard) per route
	// This connection will be reused for all requests to this route
	Conn net.Conn

	// AuthConfig is optional authentication configuration for this route
	// Configure ONE of: BasicAuth, PIN, or Bearer (JWT/OIDC)
	// If nil, requests pass through without authentication
	AuthConfig *AuthConfig

	// AuthRejectResponse is an optional custom response for authentication failures
	// If nil, returns 401 Unauthorized with WWW-Authenticate header
	AuthRejectResponse func(w http.ResponseWriter, r *http.Request)
}

// routeEntry represents a compiled route with its proxy
type routeEntry struct {
	routeConfig *RouteConfig
	path        string
	target      string
	proxy       *httputil.ReverseProxy
	handler     http.Handler // handler wraps proxy with middleware (auth, logging, etc.)
}

// New creates a new reverse proxy
func New(config Config) (*Proxy, error) {
	// Set defaults
	if config.ListenAddress == "" {
		config.ListenAddress = ":443"
	}
	if config.HTTPListenAddress == "" {
		config.HTTPListenAddress = ":80"
	}
	if config.CertCacheDir == "" {
		config.CertCacheDir = "./certs"
	}

	// Validate HTTPS config
	if config.EnableHTTPS {
		if config.TLSEmail == "" {
			return nil, fmt.Errorf("TLSEmail is required when EnableHTTPS is true")
		}
	}

	// Set default OIDC session cookie name if not provided
	if config.OIDCConfig != nil && config.OIDCConfig.SessionCookieName == "" {
		config.OIDCConfig.SessionCookieName = "auth_session"
	}

	p := &Proxy{
		config:          config,
		routes:          make(map[string]*RouteConfig),
		isRunning:       false,
		requestCallback: config.RequestDataCallback,
	}

	return p, nil
}

// Start starts the reverse proxy server
func (p *Proxy) Start() error {
	p.mu.Lock()
	if p.isRunning {
		p.mu.Unlock()
		return fmt.Errorf("reverse proxy already running")
	}
	p.isRunning = true
	p.mu.Unlock()

	// Build the main HTTP handler
	handler := p.buildHandler()

	if p.config.EnableHTTPS {
		// Setup autocert manager with dynamic host policy
		p.autocertManager = &autocert.Manager{
			Cache:      autocert.DirCache(p.config.CertCacheDir),
			Prompt:     autocert.AcceptTOS,
			Email:      p.config.TLSEmail,
			HostPolicy: p.dynamicHostPolicy, // Use dynamic policy based on routes
		}

		// Start HTTP server for ACME challenges
		p.httpServer = &http.Server{
			Addr:    p.config.HTTPListenAddress,
			Handler: p.autocertManager.HTTPHandler(nil),
		}

		go func() {
			log.Infof("Starting HTTP server on %s for ACME challenges", p.config.HTTPListenAddress)
			if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Errorf("HTTP server error: %v", err)
			}
		}()

		// Start HTTPS server
		p.server = &http.Server{
			Addr:      p.config.ListenAddress,
			Handler:   handler,
			TLSConfig: p.autocertManager.TLSConfig(),
		}

		go func() {
			log.Infof("Starting HTTPS server on %s", p.config.ListenAddress)
			if err := p.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Errorf("HTTPS server error: %v", err)
				p.mu.Lock()
				p.isRunning = false
				p.mu.Unlock()
			}
		}()
	} else {
		// Start HTTP server only
		p.server = &http.Server{
			Addr:    p.config.HTTPListenAddress,
			Handler: handler,
		}

		go func() {
			log.Infof("Starting HTTP server on %s", p.config.HTTPListenAddress)
			if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Errorf("HTTP server error: %v", err)
				p.mu.Lock()
				p.isRunning = false
				p.mu.Unlock()
			}
		}()
	}

	log.Infof("Reverse proxy started with %d route(s)", len(p.routes))
	return nil
}

// dynamicHostPolicy is a custom host policy that allows certificates for any domain
// that has a configured route
func (p *Proxy) dynamicHostPolicy(ctx context.Context, host string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// O(1) lookup for exact domain match
	if _, exists := p.routes[host]; exists {
		log.Infof("Allowing certificate for domain: %s", host)
		return nil
	}

	log.Warnf("Rejecting certificate request for unknown domain: %s", host)
	return fmt.Errorf("domain %s not configured in routes", host)
}

// Stop gracefully stops the reverse proxy
func (p *Proxy) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.isRunning {
		p.mu.Unlock()
		return fmt.Errorf("reverse proxy not running")
	}
	p.mu.Unlock()

	log.Info("Stopping reverse proxy...")

	// Stop HTTPS server
	if p.server != nil {
		if err := p.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown HTTPS server: %w", err)
		}
	}

	// Stop HTTP server (ACME challenge server)
	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown HTTP server: %w", err)
		}
	}

	p.mu.Lock()
	p.isRunning = false
	p.mu.Unlock()

	log.Info("Reverse proxy stopped")
	return nil
}

// buildHandler creates the main HTTP handler with router for static endpoints
func (p *Proxy) buildHandler() http.Handler {
	router := mux.NewRouter()

	// Register static endpoints
	router.HandleFunc("/auth/callback", p.handleOIDCCallback).Methods("GET")

	// Catch-all handler for dynamic proxy routing
	router.PathPrefix("/").HandlerFunc(p.handleProxyRequest)

	return router
}

// handleProxyRequest handles all dynamic proxy requests
func (p *Proxy) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	routeEntry := p.findRoute(r.Host, r.URL.Path)
	if routeEntry == nil {
		log.Warnf("No route found for host=%s path=%s", r.Host, r.URL.Path)
		http.NotFound(w, r)
		return
	}

	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	routeEntry.handler.ServeHTTP(rw, r)

	if p.requestCallback != nil {
		duration := time.Since(startTime)

		host := r.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}

		authMechanism := r.Header.Get("X-Auth-Method")
		if authMechanism == "" {
			authMechanism = "none"
		}

		// Determine auth success based on status code
		authSuccess := rw.statusCode != http.StatusUnauthorized && rw.statusCode != http.StatusForbidden

		// Extract user ID (this would need to be enhanced to extract from tokens/headers)
		_, userID, _ := extractAuthInfo(r, rw.statusCode)

		data := RequestData{
			ServiceID:     routeEntry.routeConfig.ID,
			Host:          host,
			Path:          r.URL.Path,
			DurationMs:    duration.Milliseconds(),
			Method:        r.Method,
			ResponseCode:  int32(rw.statusCode),
			SourceIP:      extractSourceIP(r),
			AuthMechanism: authMechanism,
			UserID:        userID,
			AuthSuccess:   authSuccess,
		}

		p.requestCallback(data)
	}
}

// findRoute finds the matching route for a given host and path
func (p *Proxy) findRoute(host, path string) *routeEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Strip port from host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// O(1) lookup by host
	routeConfig, exists := p.routes[host]
	if !exists {
		return nil
	}

	// Build list of route entries sorted by path specificity
	var entries []*routeEntry

	// Create entries for each path mapping
	for routePath, target := range routeConfig.PathMappings {
		proxy := p.createProxy(routeConfig, target)

		// ALWAYS wrap proxy with auth middleware (even if no auth configured)
		// This ensures consistent auth handling and logging
		handler := wrapWithAuth(proxy, routeConfig.AuthConfig, routeConfig.ID, routeConfig.AuthRejectResponse, p.config.OIDCConfig)

		// Log auth configuration
		if routeConfig.AuthConfig != nil && !routeConfig.AuthConfig.IsEmpty() {
			var authType string
			if routeConfig.AuthConfig.BasicAuth != nil {
				authType = "basic_auth"
			} else if routeConfig.AuthConfig.PIN != nil {
				authType = "pin"
			} else if routeConfig.AuthConfig.Bearer != nil {
				authType = "bearer_jwt"
			}
			log.WithFields(log.Fields{
				"route_id":  routeConfig.ID,
				"auth_type": authType,
			}).Debug("Auth middleware enabled for route")
		} else {
			log.WithFields(log.Fields{
				"route_id": routeConfig.ID,
			}).Debug("No authentication configured for route")
		}

		entries = append(entries, &routeEntry{
			routeConfig: routeConfig,
			path:        routePath,
			target:      target,
			proxy:       proxy,
			handler:     handler,
		})
	}

	// Sort by path specificity (longest first)
	sort.Slice(entries, func(i, j int) bool {
		pi, pj := entries[i].path, entries[j].path
		// Empty string or "/" goes last (catch-all)
		if pi == "" || pi == "/" {
			return false
		}
		if pj == "" || pj == "/" {
			return true
		}
		return len(pi) > len(pj)
	})

	// Find first matching entry
	for _, entry := range entries {
		if entry.path == "" || entry.path == "/" {
			// Catch-all route
			return entry
		}
		if strings.HasPrefix(path, entry.path) {
			return entry
		}
	}

	return nil
}

// createProxy creates a reverse proxy for a target with the route's connection
func (p *Proxy) createProxy(routeConfig *RouteConfig, target string) *httputil.ReverseProxy {
	// Parse target URL
	targetURL, err := url.Parse("http://" + target)
	if err != nil {
		log.Errorf("Failed to parse target URL %s: %v", target, err)
		// Return a proxy that returns 502
		return &httputil.ReverseProxy{
			Director: func(req *http.Request) {},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			},
		}
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Check if this is a defaultConn (for testing)
	if dc, ok := routeConfig.Conn.(*defaultConn); ok {
		// For defaultConn, use its dialer directly
		proxy.Transport = &http.Transport{
			DialContext:           dc.dialer.DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		log.Infof("Using default network dialer for route %s (testing mode)", routeConfig.ID)
	} else {
		// Configure transport to use the provided connection (WireGuard, etc.)
		proxy.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				log.Debugf("Using custom connection for route %s to %s", routeConfig.ID, address)
				return routeConfig.Conn, nil
			},
			MaxIdleConns:          1,
			MaxIdleConnsPerHost:   1,
			IdleConnTimeout:       0, // Keep alive indefinitely
			DisableKeepAlives:     false,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		log.Infof("Using custom connection for route %s", routeConfig.ID)
	}

	// Custom error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Errorf("Proxy error for %s%s: %v", r.Host, r.URL.Path, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return proxy
}

// AddRoute adds a new route configuration
func (p *Proxy) AddRoute(route *RouteConfig) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}
	if route.ID == "" {
		return fmt.Errorf("route ID is required")
	}
	if route.Domain == "" {
		return fmt.Errorf("route Domain is required")
	}
	if len(route.PathMappings) == 0 {
		return fmt.Errorf("route must have at least one path mapping")
	}
	if route.Conn == nil {
		return fmt.Errorf("route connection (Conn) is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if route already exists for this domain
	if _, exists := p.routes[route.Domain]; exists {
		return fmt.Errorf("route for domain %s already exists", route.Domain)
	}

	// Add route with domain as key
	p.routes[route.Domain] = route

	log.WithFields(log.Fields{
		"route_id": route.ID,
		"domain":   route.Domain,
		"paths":    len(route.PathMappings),
	}).Info("Added route")

	// Note: With this architecture, we don't need to reload the server
	// The handler dynamically looks up routes on each request
	// Certificates will be obtained automatically when the domain is first accessed

	return nil
}

// RemoveRoute removes a route
func (p *Proxy) RemoveRoute(domain string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if route exists
	if _, exists := p.routes[domain]; !exists {
		return fmt.Errorf("route for domain %s not found", domain)
	}

	// Remove route
	delete(p.routes, domain)

	log.Infof("Removed route for domain: %s", domain)
	return nil
}

// UpdateRoute updates an existing route
func (p *Proxy) UpdateRoute(route *RouteConfig) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}
	if route.ID == "" {
		return fmt.Errorf("route ID is required")
	}
	if route.Domain == "" {
		return fmt.Errorf("route Domain is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if route exists for this domain
	if _, exists := p.routes[route.Domain]; !exists {
		return fmt.Errorf("route for domain %s not found", route.Domain)
	}

	// Update route using domain as key
	p.routes[route.Domain] = route

	log.WithFields(log.Fields{
		"route_id": route.ID,
		"domain":   route.Domain,
		"paths":    len(route.PathMappings),
	}).Info("Updated route")

	return nil
}

// ListRoutes returns a list of all configured domains
func (p *Proxy) ListRoutes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domains := make([]string, 0, len(p.routes))
	for domain := range p.routes {
		domains = append(domains, domain)
	}
	return domains
}

// GetRoute returns a route configuration by domain
func (p *Proxy) GetRoute(domain string) (*RouteConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	route, exists := p.routes[domain]
	if !exists {
		return nil, fmt.Errorf("route for domain %s not found", domain)
	}

	return route, nil
}

// IsRunning returns whether the proxy is running
func (p *Proxy) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.isRunning
}

// GetConfig returns the proxy configuration
func (p *Proxy) GetConfig() Config {
	return p.config
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// extractSourceIP extracts the source IP from the request
func extractSourceIP(r *http.Request) string {
	// Try X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Try X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// extractAuthInfo extracts authentication information from the request
// Returns: authMechanism, userID, authSuccess
func extractAuthInfo(r *http.Request, statusCode int) (string, string, bool) {
	// Check if authentication succeeded based on status code
	// 401 = Unauthorized, 403 = Forbidden
	authSuccess := statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden

	// Check for Bearer token (JWT, OAuth2, etc.)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			// Extract user ID from JWT if possible (you may want to decode the JWT here)
			// For now, we'll just indicate it's a bearer token
			return "bearer", extractUserIDFromBearer(auth), authSuccess
		}
		if strings.HasPrefix(auth, "Basic ") {
			// Basic authentication
			return "basic", extractUserIDFromBasic(auth), authSuccess
		}
		// Other authorization schemes
		return "other", "", authSuccess
	}

	// Check for API key in headers
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "api_key", "", authSuccess
	}
	if apiKey := r.Header.Get("X-Api-Key"); apiKey != "" {
		return "api_key", "", authSuccess
	}

	// Check for mutual TLS (client certificate)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// Extract Common Name from client certificate
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		return "mtls", cn, authSuccess
	}

	// Check for session cookie (common in web apps)
	if cookie, err := r.Cookie("session"); err == nil && cookie.Value != "" {
		return "session", "", authSuccess
	}

	// No authentication detected
	return "none", "", authSuccess
}

// extractUserIDFromBearer attempts to extract user ID from Bearer token
// Decodes the JWT (without verification) to extract the user ID from standard claims
func extractUserIDFromBearer(auth string) string {
	// Remove "Bearer " prefix
	tokenString := strings.TrimPrefix(auth, "Bearer ")
	if tokenString == "" {
		return ""
	}

	// JWT format: header.payload.signature
	// We only need the payload to extract user ID (no verification needed here)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		log.Debug("Invalid JWT format: expected 3 parts")
		return ""
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.WithError(err).Debug("Failed to decode JWT payload")
		return ""
	}

	// Parse JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		log.WithError(err).Debug("Failed to parse JWT claims")
		return ""
	}

	// Try standard user ID claims in order of preference
	// 1. "sub" (standard JWT subject claim)
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}

	// 2. "user_id" (common in some systems)
	if userID, ok := claims["user_id"].(string); ok && userID != "" {
		return userID
	}

	// 3. "email" (fallback)
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}

	// 4. "preferred_username" (used by some OIDC providers)
	if username, ok := claims["preferred_username"].(string); ok && username != "" {
		return username
	}

	return ""
}

// extractUserIDFromBasic extracts username from Basic auth header
func extractUserIDFromBasic(auth string) string {
	// Basic auth format: "Basic base64(username:password)"
	_ = strings.TrimPrefix(auth, "Basic ")
	// Note: We're not decoding it here for security reasons
	// The upstream service should handle the actual authentication
	// We just note that basic auth was used
	return ""
}

// defaultConn is a lazy connection wrapper that uses the standard network dialer
// This is useful for testing or development when not using WireGuard tunnels
type defaultConn struct {
	dialer *net.Dialer
	mu     sync.Mutex
	conns  map[string]net.Conn // cache connections by "network:address"
}

func (dc *defaultConn) Read(b []byte) (n int, err error) {
	return 0, fmt.Errorf("Read not supported on defaultConn - use dial via Transport")
}

func (dc *defaultConn) Write(b []byte) (n int, err error) {
	return 0, fmt.Errorf("Write not supported on defaultConn - use dial via Transport")
}

func (dc *defaultConn) Close() error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	for _, conn := range dc.conns {
		conn.Close()
	}
	dc.conns = make(map[string]net.Conn)
	return nil
}

func (dc *defaultConn) LocalAddr() net.Addr                { return nil }
func (dc *defaultConn) RemoteAddr() net.Addr               { return nil }
func (dc *defaultConn) SetDeadline(t time.Time) error      { return nil }
func (dc *defaultConn) SetReadDeadline(t time.Time) error  { return nil }
func (dc *defaultConn) SetWriteDeadline(t time.Time) error { return nil }

// NewDefaultConn creates a connection wrapper that uses the standard network dialer
// This is useful for testing or development when not using WireGuard tunnels
// The actual dialing happens when the HTTP Transport calls DialContext
func NewDefaultConn() net.Conn {
	return &defaultConn{
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		conns: make(map[string]net.Conn),
	}
}

// handleOIDCCallback handles the global /auth/callback endpoint for all routes
func (p *Proxy) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// Check if OIDC is configured globally
	if p.config.OIDCConfig == nil {
		log.Error("OIDC callback received but no OIDC config found")
		http.Error(w, "Authentication not configured", http.StatusInternalServerError)
		return
	}

	// Use the HandleOIDCCallback function from auth.go with global config
	handler := HandleOIDCCallback(p.config.OIDCConfig)
	handler(w, r)
}

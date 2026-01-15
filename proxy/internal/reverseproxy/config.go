package reverseproxy

import (
	"net/http"
	"net/http/httputil"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/auth/oidc"
)

// Config holds the reverse proxy configuration
type Config struct {
	// ListenAddress is the address to listen on for HTTPS (default ":443")
	ListenAddress string `env:"NB_REVERSE_PROXY_LISTEN_ADDRESS" envDefault:":443" json:"listen_address"`

	// ManagementURL is the URL of the management server
	ManagementURL string `env:"NB_REVERSE_PROXY_MANAGEMENT_URL" json:"management_url"`

	// HTTPListenAddress is the address for HTTP (default ":80")
	// Used for ACME challenges when HTTPS is enabled, or as main listener when HTTPS is disabled
	HTTPListenAddress string `env:"NB_REVERSE_PROXY_HTTP_LISTEN_ADDRESS" envDefault:":80" json:"http_listen_address"`

	// EnableHTTPS enables automatic HTTPS with Let's Encrypt
	EnableHTTPS bool `env:"NB_REVERSE_PROXY_ENABLE_HTTPS" envDefault:"false" json:"enable_https"`

	// TLSEmail is the email for Let's Encrypt registration
	TLSEmail string `env:"NB_REVERSE_PROXY_TLS_EMAIL" json:"tls_email"`

	// CertCacheDir is the directory to cache certificates (default "./certs")
	CertCacheDir string `env:"NB_REVERSE_PROXY_CERT_CACHE_DIR" envDefault:"./certs" json:"cert_cache_dir"`

	// OIDCConfig is the global OIDC/OAuth configuration for authentication
	// This is shared across all routes that use Bearer authentication
	// If nil, routes with Bearer auth will fail to initialize
	OIDCConfig *oidc.Config `json:"oidc_config"`
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

	SetupKey string
	nbClient *embed.Client

	// AuthConfig is optional authentication configuration for this route
	// Configure ONE of: BasicAuth, PIN, or Bearer (JWT/OIDC)
	// If nil, requests pass through without authentication
	AuthConfig *auth.Config

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

// RequestDataCallback is called for each proxied request with metrics
type RequestDataCallback func(data RequestData)

// RequestData contains metrics for a proxied request
type RequestData struct {
	ServiceID     string
	Host          string
	Path          string
	DurationMs    int64
	Method        string
	ResponseCode  int32
	SourceIP      string
	AuthMechanism string
	UserID        string
	AuthSuccess   bool
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

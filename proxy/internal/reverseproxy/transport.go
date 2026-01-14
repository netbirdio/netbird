package reverseproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// customTransportRegistry stores custom dialers and connections globally
// This allows them to be accessed after Caddy deserializes the configuration from JSON
var customTransportRegistry = &transportRegistry{
	transports: make(map[string]*customTransport),
}

// transportRegistry manages custom transports for routes
type transportRegistry struct {
	mu         sync.RWMutex
	transports map[string]*customTransport // key is "routeID:path"
}

// customTransport wraps either a net.Conn or a custom dialer
type customTransport struct {
	routeID       string
	path          string
	conn          net.Conn
	customDialer  func(ctx context.Context, network, address string) (net.Conn, error)
	defaultDialer *net.Dialer
}

// Register registers a custom transport for a route
func (r *transportRegistry) Register(routeID, path string, conn net.Conn, dialer func(ctx context.Context, network, address string) (net.Conn, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", routeID, path)
	r.transports[key] = &customTransport{
		routeID:       routeID,
		path:          path,
		conn:          conn,
		customDialer:  dialer,
		defaultDialer: &net.Dialer{Timeout: 30 * time.Second},
	}

	if conn != nil {
		log.Infof("Registered net.Conn transport for route %s (path: %s)", routeID, path)
	} else if dialer != nil {
		log.Infof("Registered custom dialer transport for route %s (path: %s)", routeID, path)
	}
}

// Get retrieves a custom transport for a route
func (r *transportRegistry) Get(routeID, path string) *customTransport {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", routeID, path)
	return r.transports[key]
}

// Unregister removes a custom transport
func (r *transportRegistry) Unregister(routeID, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", routeID, path)
	delete(r.transports, key)
	log.Infof("Unregistered transport for route %s (path: %s)", routeID, path)
}

// Clear removes all custom transports
func (r *transportRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.transports = make(map[string]*customTransport)
	log.Info("Cleared all custom transports")
}

// DialContext implements the DialContext function for custom transports
func (ct *customTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// If we have a pre-existing connection, return it
	if ct.conn != nil {
		log.Debugf("Reusing existing connection for route %s (path: %s) to %s", ct.routeID, ct.path, address)
		return ct.conn, nil
	}

	// If we have a custom dialer, use it
	if ct.customDialer != nil {
		log.Debugf("Using custom dialer for route %s (path: %s) to %s", ct.routeID, ct.path, address)
		return ct.customDialer(ctx, network, address)
	}

	// Fallback to default dialer (this shouldn't happen if registered correctly)
	log.Warnf("No custom transport found for route %s (path: %s), using default dialer", ct.routeID, ct.path)
	return ct.defaultDialer.DialContext(ctx, network, address)
}

// NewCustomHTTPTransport creates an HTTP transport that uses the custom dialer
func NewCustomHTTPTransport(routeID, path string) *http.Transport {
	transport := customTransportRegistry.Get(routeID, path)
	if transport == nil {
		// No custom transport registered, return standard transport
		log.Warnf("No custom transport found for route %s (path: %s), using standard transport", routeID, path)
		return &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	// Configure transport based on whether we're using a connection or dialer
	if transport.conn != nil {
		// Using a pre-existing connection - disable pooling
		return &http.Transport{
			DialContext:           transport.DialContext,
			MaxIdleConns:          1,
			MaxIdleConnsPerHost:   1,
			IdleConnTimeout:       0, // Keep alive indefinitely
			DisableKeepAlives:     false,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	// Using a custom dialer - use normal pooling
	return &http.Transport{
		DialContext:           transport.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

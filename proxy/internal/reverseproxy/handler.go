package reverseproxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/auth"
)

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

		// TODO: extract logging data
		authMechanism := r.Header.Get("X-Auth-Method")
		if authMechanism == "" {
			authMechanism = "none"
		}
		userID := r.Header.Get("X-Auth-User-ID")
		authSuccess := rw.statusCode != http.StatusUnauthorized && rw.statusCode != http.StatusForbidden
		sourceIP := extractSourceIP(r)

		data := RequestData{
			ServiceID:     routeEntry.routeConfig.ID,
			Host:          host,
			Path:          r.URL.Path,
			DurationMs:    duration.Milliseconds(),
			Method:        r.Method,
			ResponseCode:  int32(rw.statusCode),
			SourceIP:      sourceIP,
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

	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	routeConfig, exists := p.routes[host]
	if !exists {
		return nil
	}

	var entries []*routeEntry

	for routePath, target := range routeConfig.PathMappings {
		proxy := p.createProxy(routeConfig, target)

		handler := auth.Wrap(proxy, routeConfig.AuthConfig, routeConfig.ID, routeConfig.AuthRejectResponse, p.oidcHandler)

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
	targetURL, err := url.Parse("http://" + target)
	if err != nil {
		log.Errorf("Failed to parse target URL %s: %v", target, err)
		return &httputil.ReverseProxy{
			Director: func(req *http.Request) {},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			},
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	proxy.Transport = &http.Transport{
		DialContext:           routeConfig.nbClient.DialContext,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       0,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Errorf("Proxy error for %s%s: %v", r.Host, r.URL.Path, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return proxy
}

// handleOIDCCallback handles the global /auth/callback endpoint for all routes
func (p *Proxy) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if p.oidcHandler == nil {
		log.Error("OIDC callback received but no OIDC handler configured")
		http.Error(w, "Authentication not configured", http.StatusInternalServerError)
		return
	}

	handler := p.oidcHandler.HandleCallback()
	handler(w, r)
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

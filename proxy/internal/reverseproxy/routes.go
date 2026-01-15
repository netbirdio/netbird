package reverseproxy

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

// AddRoute adds a new route to the proxy
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

// RemoveRoute removes a route by domain
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

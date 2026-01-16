package reverseproxy

import (
	"context"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/embed"
)

const (
	clientStartupTimeout = 30 * time.Second
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
	if route.SetupKey == "" {
		return fmt.Errorf("route setup key is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.routes[route.Domain]; exists {
		return fmt.Errorf("route for domain %s already exists", route.Domain)
	}

	client, err := embed.New(embed.Options{DeviceName: fmt.Sprintf("ingress-%s", route.ID), ManagementURL: p.config.ManagementURL, SetupKey: route.SetupKey, LogOutput: io.Discard})
	if err != nil {
		return fmt.Errorf("failed to create embedded client for route %s: %v", route.ID, err)
	}

	ctx, _ := context.WithTimeout(context.Background(), clientStartupTimeout)
	err = client.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start embedded client for route %s: %v", route.ID, err)
	}

	route.nbClient = client

	p.routes[route.Domain] = route

	p.certManager.AddDomain(route.Domain)

	log.WithFields(log.Fields{
		"route_id": route.ID,
		"domain":   route.Domain,
		"paths":    len(route.PathMappings),
	}).Info("Added route")

	go func(domain string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if err := p.certManager.IssueCertificate(ctx, domain); err != nil {
			log.Errorf("Failed to issue certificate: %v", err)
			// TODO: Better error feedback mechanism
		}
	}(route.Domain)

	return nil
}

// RemoveRoute removes a route by domain
func (p *Proxy) RemoveRoute(domain string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.routes[domain]; !exists {
		return fmt.Errorf("route for domain %s not found", domain)
	}

	delete(p.routes, domain)

	p.certManager.RemoveDomain(domain)

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

	if _, exists := p.routes[route.Domain]; !exists {
		return fmt.Errorf("route for domain %s not found", route.Domain)
	}

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

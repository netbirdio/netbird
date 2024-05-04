package dynamic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

const interval = 5 * time.Minute

type domainMap map[domain.Domain][]netip.Prefix

type Route struct {
	route           *route.Route
	wgInterface     *iface.WGIface
	routeRefCounter *refcounter.Counter
	dynamicDomains  domainMap
	mu              sync.Mutex
	currentPeerKey  string
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

func NewRoute(rt *route.Route, wgIface *iface.WGIface, routeRefCounter *refcounter.Counter) *Route {
	return &Route{
		route:           rt,
		wgInterface:     wgIface,
		routeRefCounter: routeRefCounter,
		dynamicDomains:  domainMap{},
	}
}

func (r *Route) String() string {
	s, err := r.route.Domains.String()
	if err != nil {
		return r.route.Domains.PunycodeString()
	}
	return s
}

func (r *Route) AddRoute(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}

	ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go r.startResolver(ctx)

	return nil
}

// RemoveRoute will stop the dynamic resolver and remove all dynamic routes.
// It doesn't touch allowed IPs, these should be removed separately and before calling this method.
func (r *Route) RemoveRoute() error {
	if r.cancel != nil {
		r.cancel()

		// wait for dynamic updates to finish to avoid interference with the removal of routes
		r.wg.Wait()
	}

	var merr *multierror.Error
	for domain, prefixes := range r.dynamicDomains {
		for _, prefix := range prefixes {
			if err := r.routeRefCounter.Decrement(prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove dynamic route for IP %s: %w", prefix, err))
			}
		}
		log.Debugf("Removed dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", prefixes), " ", ", "))
	}

	r.dynamicDomains = domainMap{}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) AddAllowedIPs(peerKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var merr *multierror.Error
	for _, domainPrefixes := range r.dynamicDomains {
		for _, prefix := range domainPrefixes {
			if err := r.wgInterface.AddAllowedIP(peerKey, prefix.String()); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("add allowed IP %s: %w", prefix, err))
			}
		}
	}
	r.currentPeerKey = peerKey
	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) RemoveAllowedIPs(peerKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var merr *multierror.Error
	for _, domainPrefixes := range r.dynamicDomains {
		for _, prefix := range domainPrefixes {
			if err := r.wgInterface.RemoveAllowedIP(peerKey, prefix.String()); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %w", prefix, err))
			}
		}
	}
	if r.currentPeerKey == peerKey {
		r.currentPeerKey = ""
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) startResolver(ctx context.Context) {
	defer r.wg.Done()

	log.Debugf("Starting dynamic route resolver for domains [%v]", r)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	r.update()

	for {
		select {
		case <-ctx.Done():
			log.Debugf("Stopping dynamic route resolver for domains [%v]", r)
			return
		case <-ticker.C:
			r.update()
		}
	}
}

func (r *Route) update() {
	if resolved, err := r.resolveDomains(); err != nil {
		log.Errorf("Failed to resolve domains for route [%v]: %v", r, err)
	} else if err := r.updateDynamicRoutes(resolved); err != nil {
		log.Errorf("Failed to update dynamic routes for [%v]: %v", r, err)
	}
}

func (r *Route) resolveDomains() (domainMap, error) {
	type resolveResult struct {
		domain domain.Domain
		prefix netip.Prefix
		err    error
	}

	var wg sync.WaitGroup
	results := make(chan resolveResult)

	resolved := domainMap{}
	var merr *multierror.Error
	go func() {
		for result := range results {
			if result.err != nil {
				merr = multierror.Append(merr, result.err)
			} else {
				resolved[result.domain] = append(resolved[result.domain], result.prefix)
			}
		}
	}()

	for _, d := range r.route.Domains {
		wg.Add(1)
		go func(domain domain.Domain) {
			defer wg.Done()
			ips, err := net.LookupIP(string(domain))
			if err != nil {
				results <- resolveResult{domain: domain, err: fmt.Errorf("resolve d %s: %w", domain.SafeString(), err)}
				return
			}
			for _, ip := range ips {
				prefix, err := systemops.GetPrefixFromIP(ip)
				if err != nil {
					results <- resolveResult{domain: domain, err: fmt.Errorf("get prefix from IP %s: %w", ip.String(), err)}
					return
				}
				results <- resolveResult{domain: domain, prefix: *prefix}
			}
		}(d)
	}

	wg.Wait()
	close(results)

	return resolved, nberrors.FormatErrorOrNil(merr)
}

func (r *Route) updateDynamicRoutes(newDomains domainMap) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var merr *multierror.Error
	updatedDomains := domainMap{}

	for domain, newPrefixes := range newDomains {
		oldPrefixes := r.dynamicDomains[domain]
		toAdd, toRemove := determinePrefixChanges(oldPrefixes, newPrefixes)

		if removedPrefixes, err := r.removeRoutes(toRemove); err != nil {
			merr = multierror.Append(merr, err)
		} else if len(removedPrefixes) > 0 {
			log.Debugf("Removed dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", removedPrefixes), " ", ", "))
		}

		if addedPrefixes, err := r.addRoutes(toAdd); err != nil {
			merr = multierror.Append(merr, err)
		} else if len(addedPrefixes) > 0 {
			updatedDomains[domain] = addedPrefixes
			log.Debugf("Added dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", addedPrefixes), " ", ", "))
		}
	}

	r.dynamicDomains = updatedDomains

	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) addRoutes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	var addedPrefixes []netip.Prefix
	var merr *multierror.Error

	for _, prefix := range prefixes {
		if err := r.routeRefCounter.Increment(prefix); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add dynamic route for IP %s: %w", prefix, err))
			continue
		}
		if r.currentPeerKey != "" {
			if err := r.wgInterface.AddAllowedIP(r.currentPeerKey, prefix.String()); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("add allowed IP %s: %w", prefix, err))
			}
		}
		addedPrefixes = append(addedPrefixes, prefix)
	}

	return addedPrefixes, merr.ErrorOrNil()
}

func (r *Route) removeRoutes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	var removedPrefixes []netip.Prefix
	var merr *multierror.Error

	for _, prefix := range prefixes {
		if err := r.routeRefCounter.Decrement(prefix); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove dynamic route for IP %s: %w", prefix, err))
		}
		if r.currentPeerKey != "" {
			if err := r.wgInterface.RemoveAllowedIP(r.currentPeerKey, prefix.String()); err != nil && !errors.Is(err, iface.ErrPeerNotFound) {
				merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %w", prefix, err))
			}
		}
		removedPrefixes = append(removedPrefixes, prefix)
	}

	return removedPrefixes, merr.ErrorOrNil()
}

func determinePrefixChanges(oldPrefixes, newPrefixes []netip.Prefix) (toAdd, toRemove []netip.Prefix) {
	prefixSet := make(map[netip.Prefix]bool)
	for _, prefix := range oldPrefixes {
		prefixSet[prefix] = false
	}
	for _, prefix := range newPrefixes {
		if _, exists := prefixSet[prefix]; exists {
			prefixSet[prefix] = true
		} else {
			toAdd = append(toAdd, prefix)
		}
	}
	for prefix, inUse := range prefixSet {
		if !inUse {
			toRemove = append(toRemove, prefix)
		}
	}
	return
}

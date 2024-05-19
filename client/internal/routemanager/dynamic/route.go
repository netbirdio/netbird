package dynamic

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/util"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

const (
	DefaultInterval = time.Minute

	minInterval = 2 * time.Second
)

type domainMap map[domain.Domain][]netip.Prefix

type Route struct {
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	interval             time.Duration
	dynamicDomains       domainMap
	mu                   sync.Mutex
	currentPeerKey       string
	cancel               context.CancelFunc
	statusRecorder       *peer.Status
}

func NewRoute(
	rt *route.Route,
	routeRefCounter *refcounter.RouteRefCounter,
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter,
	interval time.Duration,
	statusRecorder *peer.Status,
) *Route {
	return &Route{
		route:                rt,
		routeRefCounter:      routeRefCounter,
		allowedIPsRefcounter: allowedIPsRefCounter,
		interval:             interval,
		dynamicDomains:       domainMap{},
		statusRecorder:       statusRecorder,
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
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel != nil {
		r.cancel()
	}

	ctx, r.cancel = context.WithCancel(ctx)

	go r.startResolver(ctx)

	return nil
}

// RemoveRoute will stop the dynamic resolver and remove all dynamic routes.
// It doesn't touch allowed IPs, these should be removed separately and before calling this method.
func (r *Route) RemoveRoute() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel != nil {
		r.cancel()
	}

	var merr *multierror.Error
	for domain, prefixes := range r.dynamicDomains {
		for _, prefix := range prefixes {
			if _, err := r.routeRefCounter.Decrement(prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove dynamic route for IP %s: %w", prefix, err))
			}
		}
		log.Debugf("Removed dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", prefixes), " ", ", "))

		r.statusRecorder.DeleteResolvedDomainsStates(domain)
	}

	r.dynamicDomains = domainMap{}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) AddAllowedIPs(peerKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var merr *multierror.Error
	for domain, domainPrefixes := range r.dynamicDomains {
		for _, prefix := range domainPrefixes {
			if err := r.incrementAllowedIP(domain, prefix, peerKey); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("add allowed IP %s: %w", prefix, err))
			}
		}
	}
	r.currentPeerKey = peerKey
	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) RemoveAllowedIPs() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var merr *multierror.Error
	for _, domainPrefixes := range r.dynamicDomains {
		for _, prefix := range domainPrefixes {
			if _, err := r.allowedIPsRefcounter.Decrement(prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %w", prefix, err))
			}
		}
	}

	r.currentPeerKey = ""
	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) startResolver(ctx context.Context) {
	log.Debugf("Starting dynamic route resolver for domains [%v]", r)

	interval := r.interval
	if interval < minInterval {
		interval = minInterval
		log.Warnf("Dynamic route resolver interval %s is too low, setting to minimum value %s", r.interval, minInterval)
	}

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

	done := make(chan struct{})
	go func() {
		for result := range results {
			if result.err != nil {
				merr = multierror.Append(merr, result.err)
			} else {
				resolved[result.domain] = append(resolved[result.domain], result.prefix)
			}
		}
		close(done)
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
				prefix, err := util.GetPrefixFromIP(ip)
				if err != nil {
					results <- resolveResult{domain: domain, err: fmt.Errorf("get prefix from IP %s: %w", ip.String(), err)}
					return
				}
				results <- resolveResult{domain: domain, prefix: prefix}
			}
		}(d)
	}

	wg.Wait()
	close(results)
	<-done

	return resolved, nberrors.FormatErrorOrNil(merr)
}

func (r *Route) updateDynamicRoutes(newDomains domainMap) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var merr *multierror.Error

	for domain, newPrefixes := range newDomains {
		oldPrefixes := r.dynamicDomains[domain]
		toAdd, toRemove := determinePrefixChanges(oldPrefixes, newPrefixes)

		addedPrefixes, err := r.addRoutes(domain, toAdd)
		if err != nil {
			merr = multierror.Append(merr, err)
		} else if len(addedPrefixes) > 0 {
			log.Debugf("Added dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", addedPrefixes), " ", ", "))
		}

		removedPrefixes, err := r.removeRoutes(toRemove)
		if err != nil {
			merr = multierror.Append(merr, err)
		} else if len(removedPrefixes) > 0 {
			log.Debugf("Removed dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", removedPrefixes), " ", ", "))
		}

		updatedPrefixes := combinePrefixes(oldPrefixes, removedPrefixes, addedPrefixes)
		r.dynamicDomains[domain] = updatedPrefixes

		r.statusRecorder.UpdateResolvedDomainsStates(domain, updatedPrefixes)
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) addRoutes(domain domain.Domain, prefixes []netip.Prefix) ([]netip.Prefix, error) {
	var addedPrefixes []netip.Prefix
	var merr *multierror.Error

	for _, prefix := range prefixes {
		if _, err := r.routeRefCounter.Increment(prefix, nil); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add dynamic route for IP %s: %w", prefix, err))
			continue
		}
		if r.currentPeerKey != "" {
			if err := r.incrementAllowedIP(domain, prefix, r.currentPeerKey); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("add allowed IP %s: %w", prefix, err))
			}
		}
		addedPrefixes = append(addedPrefixes, prefix)
	}

	return addedPrefixes, merr.ErrorOrNil()
}

func (r *Route) removeRoutes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	if r.route.KeepRoute {
		return nil, nil
	}

	var removedPrefixes []netip.Prefix
	var merr *multierror.Error

	for _, prefix := range prefixes {
		if _, err := r.routeRefCounter.Decrement(prefix); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove dynamic route for IP %s: %w", prefix, err))
		}
		if r.currentPeerKey != "" {
			if _, err := r.allowedIPsRefcounter.Decrement(prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %w", prefix, err))
			}
		}
		removedPrefixes = append(removedPrefixes, prefix)
	}

	return removedPrefixes, merr.ErrorOrNil()
}

func (r *Route) incrementAllowedIP(domain domain.Domain, prefix netip.Prefix, peerKey string) error {
	if ref, err := r.allowedIPsRefcounter.Increment(prefix, peerKey); err != nil {
		return fmt.Errorf("add allowed IP %s: %w", prefix, err)
	} else if ref.Count > 1 && ref.Out != peerKey {
		log.Warnf("IP [%s] for domain [%s] was already resolved for a different domain routed by peer [%s]. Routing for this IP will be done by peer [%s], HA routing disabled",
			prefix.Addr(),
			domain.SafeString(),
			ref.Out,
			ref.Out,
		)

	}
	return nil
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

func combinePrefixes(oldPrefixes, removedPrefixes, addedPrefixes []netip.Prefix) []netip.Prefix {
	prefixSet := make(map[netip.Prefix]struct{})
	for _, prefix := range oldPrefixes {
		prefixSet[prefix] = struct{}{}
	}
	for _, prefix := range removedPrefixes {
		delete(prefixSet, prefix)
	}
	for _, prefix := range addedPrefixes {
		prefixSet[prefix] = struct{}{}
	}

	var combinedPrefixes []netip.Prefix
	for prefix := range prefixSet {
		combinedPrefixes = append(combinedPrefixes, prefix)
	}

	return combinedPrefixes
}

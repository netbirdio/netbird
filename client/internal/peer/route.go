package peer

import (
	"net/netip"
	"sort"
	"sync"

	log "github.com/sirupsen/logrus"
)

// routeEntry holds the route prefix and the corresponding resource ID.
type routeEntry struct {
	prefix     netip.Prefix
	resourceID string
}

type routeIDLookup struct {
	localRoutes []routeEntry
	localLock   sync.RWMutex

	remoteRoutes []routeEntry
	remoteLock   sync.RWMutex

	resolvedIPs sync.Map
}

func (r *routeIDLookup) AddLocalRouteID(resourceID string, route netip.Prefix) {
	r.localLock.Lock()
	defer r.localLock.Unlock()

	// update the resource id if the route already exists.
	for i, entry := range r.localRoutes {
		if entry.prefix == route {
			r.localRoutes[i].resourceID = resourceID
			log.Tracef("resourceID for route %v updated to %s in local routes", route, resourceID)
			return
		}
	}

	// append and sort descending by prefix bits (more specific first)
	r.localRoutes = append(r.localRoutes, routeEntry{prefix: route, resourceID: resourceID})
	sort.Slice(r.localRoutes, func(i, j int) bool {
		return r.localRoutes[i].prefix.Bits() > r.localRoutes[j].prefix.Bits()
	})
}

func (r *routeIDLookup) RemoveLocalRouteID(route netip.Prefix) {
	r.localLock.Lock()
	defer r.localLock.Unlock()

	for i, entry := range r.localRoutes {
		if entry.prefix == route {
			r.localRoutes = append(r.localRoutes[:i], r.localRoutes[i+1:]...)
			return
		}
	}
}

func (r *routeIDLookup) AddRemoteRouteID(resourceID string, route netip.Prefix) {
	r.remoteLock.Lock()
	defer r.remoteLock.Unlock()

	for i, entry := range r.remoteRoutes {
		if entry.prefix == route {
			r.remoteRoutes[i].resourceID = resourceID
			log.Tracef("resourceID for route %v updated to %s in remote routes", route, resourceID)
			return
		}
	}

	// append and sort descending by prefix bits.
	r.remoteRoutes = append(r.remoteRoutes, routeEntry{prefix: route, resourceID: resourceID})
	sort.Slice(r.remoteRoutes, func(i, j int) bool {
		return r.remoteRoutes[i].prefix.Bits() > r.remoteRoutes[j].prefix.Bits()
	})
}

func (r *routeIDLookup) RemoveRemoteRouteID(route netip.Prefix) {
	r.remoteLock.Lock()
	defer r.remoteLock.Unlock()

	for i, entry := range r.remoteRoutes {
		if entry.prefix == route {
			r.remoteRoutes = append(r.remoteRoutes[:i], r.remoteRoutes[i+1:]...)
			return
		}
	}
}

func (r *routeIDLookup) AddResolvedIP(resourceID string, route netip.Prefix) {
	r.resolvedIPs.Store(route.Addr(), resourceID)
}

func (r *routeIDLookup) RemoveResolvedIP(route netip.Prefix) {
	r.resolvedIPs.Delete(route.Addr())
}

// Lookup returns the resource ID for the given IP address
// and a bool indicating if the IP is an exit node.
func (r *routeIDLookup) Lookup(ip netip.Addr) (string, bool) {
	if res, ok := r.resolvedIPs.Load(ip); ok {
		return res.(string), false
	}

	var resourceID string
	var isExitNode bool

	r.localLock.RLock()
	for _, entry := range r.localRoutes {
		if entry.prefix.Contains(ip) {
			resourceID = entry.resourceID
			isExitNode = (entry.prefix.Bits() == 0)
			break
		}
	}
	r.localLock.RUnlock()

	if resourceID == "" {
		r.remoteLock.RLock()
		for _, entry := range r.remoteRoutes {
			if entry.prefix.Contains(ip) {
				resourceID = entry.resourceID
				isExitNode = (entry.prefix.Bits() == 0)
				break
			}
		}
		r.remoteLock.RUnlock()
	}

	return resourceID, isExitNode
}

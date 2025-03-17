package peer

import (
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"
)

type routeIDLookup struct {
	localMap    sync.Map
	remoteMap   sync.Map
	resolvedIPs sync.Map
}

func (r *routeIDLookup) AddLocalRouteID(resourceID string, route netip.Prefix) {
	_, exists := r.localMap.LoadOrStore(route, resourceID)
	if exists {
		log.Tracef("resourceID %s already exists in local map", resourceID)
	}
}

func (r *routeIDLookup) RemoveLocalRouteID(route netip.Prefix) {
	r.localMap.Delete(route)
}

func (r *routeIDLookup) AddRemoteRouteID(resourceID string, route netip.Prefix) {
	_, exists := r.remoteMap.LoadOrStore(route, resourceID)
	if exists {
		log.Tracef("resourceID %s already exists in remote map", resourceID)
	}
}

func (r *routeIDLookup) RemoveRemoteRouteID(route netip.Prefix) {
	r.remoteMap.Delete(route)
}

func (r *routeIDLookup) AddResolvedIP(resourceID string, route netip.Prefix) {
	r.resolvedIPs.Store(route.Addr(), resourceID)
}

func (r *routeIDLookup) RemoveResolvedIP(route netip.Prefix) {
	r.resolvedIPs.Delete(route.Addr())
}

// Lookup returns the resource ID for the given IP address
// and a bool indicating if the IP is an exit node
func (r *routeIDLookup) Lookup(ip netip.Addr) (string, bool) {
	var isExitNode bool

	resId, ok := r.resolvedIPs.Load(ip)
	if ok {
		return resId.(string), false
	}

	var resourceID string
	r.localMap.Range(func(key, value interface{}) bool {
		pref := key.(netip.Prefix)
		if pref.Contains(ip) {
			resourceID = value.(string)
			isExitNode = pref.Bits() == 0
			return false

		}
		return true
	})

	if resourceID == "" {
		r.remoteMap.Range(func(key, value interface{}) bool {
			pref := key.(netip.Prefix)
			if pref.Contains(ip) {
				resourceID = value.(string)
				isExitNode = pref.Bits() == 0
				return false
			}
			return true
		})
	}

	return resourceID, isExitNode
}

package peer

import (
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
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

func (r *routeIDLookup) Lookup(src, dst netip.Addr, direction nftypes.Direction) (srcResourceID, dstResourceID string) {

	// check resolved ip's first
	resId, ok := r.resolvedIPs.Load(src)
	if ok {
		srcResourceID = resId.(string)
	} else {
		resId, ok := r.resolvedIPs.Load(dst)
		if ok {
			dstResourceID = resId.(string)
		}
	}

	switch direction {
	case nftypes.Ingress:
		if srcResourceID == "" || dstResourceID == "" {
			r.localMap.Range(func(key, value interface{}) bool {
				if srcResourceID == "" && key.(netip.Prefix).Contains(src) {
					srcResourceID = value.(string)

				} else if dstResourceID == "" && key.(netip.Prefix).Contains(dst) {
					dstResourceID = value.(string)
				}

				if srcResourceID != "" && dstResourceID != "" {
					return false
				}

				return true
			})
		}
	case nftypes.Egress:
		if srcResourceID == "" || dstResourceID == "" {
			r.remoteMap.Range(func(key, value interface{}) bool {
				if srcResourceID == "" && key.(netip.Prefix).Contains(src) {
					srcResourceID = value.(string)

				} else if dstResourceID == "" && key.(netip.Prefix).Contains(dst) {
					dstResourceID = value.(string)
				}

				if srcResourceID != "" && dstResourceID != "" {
					return false
				}

				return true
			})
		}
	}

	return srcResourceID, dstResourceID
}

//go:build !android

package routemanager

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

type RouteManager struct {
	// refCountMap keeps track of the reference count for prefixes
	refCountMap map[netip.Prefix]int
	// prefixMap keeps track of the prefixes associated with a connection ID for removal
	prefixMap   map[nbnet.ConnectionID][]netip.Prefix
	addRoute    AddRouteFunc
	removeRoute RemoveRouteFunc
	mutex       sync.Mutex
}

type AddRouteFunc func(prefix netip.Prefix) error
type RemoveRouteFunc func(prefix netip.Prefix) error

func NewRouteManager(addRoute AddRouteFunc, removeRoute RemoveRouteFunc) *RouteManager {
	// TODO: read initial routing table into refCountMap
	return &RouteManager{
		refCountMap: map[netip.Prefix]int{},
		prefixMap:   map[nbnet.ConnectionID][]netip.Prefix{},
		addRoute:    addRoute,
		removeRoute: removeRoute,
	}
}

func (rm *RouteManager) AddRouteRef(connID nbnet.ConnectionID, prefix netip.Prefix) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	log.Debugf("Increasing route ref count %d for prefix %s", rm.refCountMap[prefix], prefix)

	// Add route to the system, only if it's a new prefix
	if rm.refCountMap[prefix] == 0 {
		log.Debugf("Adding route for prefix %s", prefix)
		if err := rm.addRoute(prefix); err != nil {
			return fmt.Errorf("failed to add route for prefix %s: %w", prefix, err)
		}
	}

	rm.refCountMap[prefix]++
	rm.prefixMap[connID] = append(rm.prefixMap[connID], prefix)

	return nil
}

func (rm *RouteManager) RemoveRouteRef(connID nbnet.ConnectionID) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	prefixes, ok := rm.prefixMap[connID]
	if !ok {
		log.Debugf("No prefixes found for connection ID %s", connID)
		return nil
	}

	var result *multierror.Error
	for _, prefix := range prefixes {
		log.Debugf("Decreasing route ref count %d for prefix %s", rm.refCountMap[prefix], prefix)
		if rm.refCountMap[prefix] == 1 {
			log.Debugf("Removing route for prefix %s", prefix)
			// TODO: don't fail if the route is not found
			if err := rm.removeRoute(prefix); err != nil {
				result = multierror.Append(result, fmt.Errorf("remove route for prefix %s: %w", prefix, err))
				continue
			}
			delete(rm.refCountMap, prefix)
		} else {
			rm.refCountMap[prefix]--
		}
	}
	delete(rm.prefixMap, connID)

	return result.ErrorOrNil()
}

// Flush removes all references and routes from the system
func (rm *RouteManager) Flush() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	var result *multierror.Error
	for prefix := range rm.refCountMap {
		log.Debugf("Removing route for prefix %s", prefix)
		if err := rm.removeRoute(prefix); err != nil {
			result = multierror.Append(result, fmt.Errorf("remove route for prefix %s: %w", prefix, err))
		}
	}
	rm.refCountMap = map[netip.Prefix]int{}
	rm.prefixMap = map[nbnet.ConnectionID][]netip.Prefix{}

	return result.ErrorOrNil()
}

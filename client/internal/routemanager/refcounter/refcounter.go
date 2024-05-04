package refcounter

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

type ref struct {
	count   int
	nexthop netip.Addr
	intf    *net.Interface
}

type Counter struct {
	// refCountMap keeps track of the reference ref for prefixes
	refCountMap map[netip.Prefix]ref
	refCountMu  sync.Mutex
	// idMap keeps track of the prefixes associated with an ID for removal
	idMap       map[string][]netip.Prefix
	idMu        sync.Mutex
	addRoute    AddRouteFunc
	removeRoute RemoveRouteFunc
}

type AddRouteFunc func(prefix netip.Prefix) (nexthop netip.Addr, intf *net.Interface, err error)
type RemoveRouteFunc func(prefix netip.Prefix, nexthop netip.Addr, intf *net.Interface) error

// New creates a new Counter instance
func New(addRoute AddRouteFunc, removeRoute RemoveRouteFunc) *Counter {
	// TODO: read initial routing table into refCountMap
	return &Counter{
		refCountMap: map[netip.Prefix]ref{},
		idMap:       map[string][]netip.Prefix{},
		addRoute:    addRoute,
		removeRoute: removeRoute,
	}
}

// Increment increments the reference count for the given prefix.
// If this is the first reference to the prefix, the AddRouteFunc is called.
func (rm *Counter) Increment(prefix netip.Prefix) error {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()

	ref := rm.refCountMap[prefix]
	log.Tracef("Increasing route ref count %d for prefix %s", ref.count, prefix)

	// Call AddRouteFunc only if it's a new prefix
	if ref.count == 0 {
		log.Tracef("Adding route for prefix %s", prefix)
		nexthop, intf, err := rm.addRoute(prefix)
		if errors.Is(err, vars.ErrRouteNotFound) {
			return nil
		}
		if errors.Is(err, vars.ErrRouteNotAllowed) {
			log.Tracef("Adding route for prefix %s: %s", prefix, err)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to add route for prefix %s: %w", prefix, err)
		}
		ref.nexthop = nexthop
		ref.intf = intf
	}

	ref.count++
	rm.refCountMap[prefix] = ref

	return nil
}

// IncrementWithID increments the reference count for the given prefix and groups it under the given ID.
// If this is the first reference to the prefix, the AddRouteFunc is called.
func (rm *Counter) IncrementWithID(id string, prefix netip.Prefix) error {
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	if err := rm.Increment(prefix); err != nil {
		return fmt.Errorf("with ID: %w", err)
	}
	rm.idMap[id] = append(rm.idMap[id], prefix)

	return nil
}

// Decrement decrements the reference count for the given prefix.
// If the reference count reaches 0, the RemoveRouteFunc is called.
func (rm *Counter) Decrement(prefix netip.Prefix) error {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()

	ref, ok := rm.refCountMap[prefix]
	if !ok {
		log.Tracef("No reference found for prefix %s", prefix)
		return nil
	}

	log.Tracef("Decreasing route ref count %d for prefix %s", ref.count, prefix)
	if ref.count == 1 {
		log.Tracef("Removing route for prefix %s", prefix)
		if err := rm.removeRoute(prefix, ref.nexthop, ref.intf); err != nil {
			return fmt.Errorf("remove route for prefix %s: %w", prefix, err)
		}
		delete(rm.refCountMap, prefix)
	} else {
		ref.count--
		rm.refCountMap[prefix] = ref
	}

	return nil
}

// DecrementWithID decrements the reference count for all prefixes associated with the given ID.
// If the reference count reaches 0, the RemoveRouteFunc is called.
func (rm *Counter) DecrementWithID(id string) error {
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	var merr *multierror.Error
	for _, prefix := range rm.idMap[id] {
		if err := rm.Decrement(prefix); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	delete(rm.idMap, id)

	return nberrors.FormatErrorOrNil(merr)
}

// Flush removes all references and calls RemoveRouteFunc for each prefix.
func (rm *Counter) Flush() error {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	var merr *multierror.Error
	for prefix := range rm.refCountMap {
		log.Tracef("Removing route for prefix %s", prefix)
		ref := rm.refCountMap[prefix]
		if err := rm.removeRoute(prefix, ref.nexthop, ref.intf); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove route for prefix %s: %w", prefix, err))
		}
	}
	rm.refCountMap = map[netip.Prefix]ref{}

	rm.idMap = map[string][]netip.Prefix{}

	return nberrors.FormatErrorOrNil(merr)
}

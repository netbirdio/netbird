package routemanager

import (
	"context"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
	"net/netip"
	"sync"
	"time"
)

type Manager struct {
	ctx             context.Context
	mux             sync.Mutex
	routes          map[string]*route.Route
	managedPrefixes map[netip.Prefix]*managedPrefix
	statusRecorder  *status.Status
	//CheckInterval  time.Duration
}

func NewManager(ctx context.Context, statusRecorder *status.Status) *Manager {
	return &Manager{
		ctx:             ctx,
		routes:          make(map[string]*route.Route),
		managedPrefixes: make(map[netip.Prefix]*managedPrefix),
		statusRecorder:  statusRecorder,
	}
}

// DefaultCheckInterval default route worker check interval 5s
const DefaultCheckInterval time.Duration = 5000000000

type managedPrefix struct {
	ctx         context.Context
	stop        context.CancelFunc
	routes      map[string]*route.Route
	update      chan struct{}
	chosenRoute string
	mux         sync.Mutex
	prefix      netip.Prefix
}

func (m *Manager) removeFromPrefix(oldRoute *route.Route) {
	managed, found := m.managedPrefixes[oldRoute.Prefix]
	if !found {
		log.Debugf("managed prefix %s not found", oldRoute.Prefix.String())
		return
	}
	managed.mux.Lock()
	delete(managed.routes, oldRoute.ID)
	managed.mux.Unlock()
	managed.update <- struct{}{}
}

func (m *Manager) startPrefixWatcher(prefixString string) *managedPrefix {
	prefix, _ := netip.ParsePrefix(prefixString)
	ctx, cancel := context.WithCancel(m.ctx)
	managed := &managedPrefix{
		ctx:    ctx,
		stop:   cancel,
		routes: make(map[string]*route.Route),
		update: make(chan struct{}),
		prefix: prefix,
	}
	m.managedPrefixes[prefix] = managed
	go m.watchPrefix(prefix)
	return managed
}

func (m *Manager) updatePrefix(newRoute *route.Route) {
	managed, found := m.managedPrefixes[newRoute.Prefix]
	if !found {
		newRoute.Prefix.Masked()
		managed = m.startPrefixWatcher(newRoute.Prefix.String())
	}
	managed.mux.Lock()
	managed.routes[newRoute.ID] = newRoute
	managed.mux.Unlock()
	managed.update <- struct{}{}
}

func (m *Manager) watchPrefix(prefix netip.Prefix) {
	managed, found := m.managedPrefixes[prefix]
	if !found {
		log.Errorf("attepmt to watch prefix %s failed. prefix not found in manager map", prefix.String())
		return
	}
	ticker := time.NewTicker(DefaultCheckInterval)
	type prefixPeer struct {
		prefix netip.Prefix
		peer   string
	}
	for {
		select {
		case <-managed.ctx.Done():
			// close things
			// remove prefix from route table
			log.Debugf("stopping routine for prefix %s", managed.prefix)
		case <-ticker.C:
			// check things
			// check status recorder
			// calculate best
			// take action
			managed.mux.Lock()
			d := len(managed.routes)
			managed.mux.Unlock()
			log.Debugf("ticker ran with %d routes", d)
		case <-managed.update:
			// check things
			// check status recorder
			// calculate best
			// take action
			managed.mux.Lock()
			d := []prefixPeer{}
			for _, route := range managed.routes {
				d = append(d, prefixPeer{
					prefix: route.Prefix,
					peer:   route.Peer,
				})
			}
			managed.mux.Unlock()
			log.Debugf("update came with following routes: %#v", d)
		}
	}
}

func (m *Manager) UpdateRoutes(newRoutes []*route.Route) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	routesToRemove := make([]string, 0)
	routesToUpdate := make([]string, 0)
	routesToAdd := make([]string, 0)
	newRoutesMap := make(map[string]*route.Route)
	for _, route := range newRoutes {
		newRoutesMap[route.ID] = route
		_, found := m.routes[route.ID]
		if !found {
			routesToAdd = append(routesToAdd, route.ID)
		}
	}
	for routeID, _ := range m.routes {
		update, found := newRoutesMap[routeID]
		if !found {
			routesToRemove = append(routesToRemove, routeID)
			continue
		}

		if !update.IsEqual(m.routes[routeID]) {
			routesToUpdate = append(routesToUpdate, routeID)
		}
	}

	for _, routeID := range routesToRemove {
		oldRoute := m.routes[routeID]
		delete(m.routes, routeID)
		m.removeFromPrefix(oldRoute)
	}
	for _, routeID := range routesToUpdate {
		newRoute := newRoutesMap[routeID]
		oldRoute := m.routes[routeID]
		m.routes[routeID] = newRoute
		if newRoute.Prefix != oldRoute.Prefix {
			m.removeFromPrefix(oldRoute)
		}
		m.updatePrefix(newRoute)
	}
	for _, routeID := range routesToAdd {
		newRoute := newRoutesMap[routeID]
		m.routes[routeID] = newRoute
		m.updatePrefix(newRoute)
	}
	for id, prefix := range m.managedPrefixes {
		prefix.mux.Lock()
		if len(prefix.routes) == 0 {
			prefix.stop()
			delete(m.managedPrefixes, id)
		}
		prefix.mux.Unlock()
	}
	log.Info("routes added %d, removed % and updated %d", len(routesToAdd), len(routesToRemove), len(routesToUpdate))
	return nil
}

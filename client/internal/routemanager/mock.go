package routemanager

import (
	"context"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/util/net"
)

// MockManager is the mock instance of a route manager
type MockManager struct {
	ClassifyRoutesFunc           func(routes []*route.Route) (map[route.ID]*route.Route, route.HAMap)
	UpdateRoutesFunc             func(updateSerial uint64, serverRoutes map[route.ID]*route.Route, clientRoutes route.HAMap, useNewDNSRoute bool) error
	TriggerSelectionFunc         func(haMap route.HAMap)
	GetRouteSelectorFunc         func() *routeselector.RouteSelector
	GetClientRoutesFunc          func() route.HAMap
	GetClientRoutesWithNetIDFunc func() map[route.NetID][]*route.Route
	StopFunc                     func(manager *statemanager.Manager)
}

func (m *MockManager) Init() (net.AddHookFunc, net.RemoveHookFunc, error) {
	return nil, nil, nil
}

// InitialRouteRange mock implementation of InitialRouteRange from Manager interface
func (m *MockManager) InitialRouteRange() []string {
	return nil
}

// UpdateRoutes mock implementation of UpdateRoutes from Manager interface
func (m *MockManager) UpdateRoutes(updateSerial uint64, newRoutes map[route.ID]*route.Route, clientRoutes route.HAMap, useNewDNSRoute bool) error {
	if m.UpdateRoutesFunc != nil {
		return m.UpdateRoutesFunc(updateSerial, newRoutes, clientRoutes, useNewDNSRoute)
	}
	return nil
}

// ClassifyRoutes mock implementation of ClassifyRoutes from Manager interface
func (m *MockManager) ClassifyRoutes(routes []*route.Route) (map[route.ID]*route.Route, route.HAMap) {
	if m.ClassifyRoutesFunc != nil {
		return m.ClassifyRoutesFunc(routes)
	}
	return nil, nil
}

func (m *MockManager) TriggerSelection(networks route.HAMap) {
	if m.TriggerSelectionFunc != nil {
		m.TriggerSelectionFunc(networks)
	}
}

// GetRouteSelector mock implementation of GetRouteSelector from Manager interface
func (m *MockManager) GetRouteSelector() *routeselector.RouteSelector {
	if m.GetRouteSelectorFunc != nil {
		return m.GetRouteSelectorFunc()
	}
	return nil
}

// GetClientRoutes mock implementation of GetClientRoutes from Manager interface
func (m *MockManager) GetClientRoutes() route.HAMap {
	if m.GetClientRoutesFunc != nil {
		return m.GetClientRoutesFunc()
	}
	return nil
}

// GetClientRoutesWithNetID mock implementation of GetClientRoutesWithNetID from Manager interface
func (m *MockManager) GetClientRoutesWithNetID() map[route.NetID][]*route.Route {
	if m.GetClientRoutesWithNetIDFunc != nil {
		return m.GetClientRoutesWithNetIDFunc()
	}
	return nil
}

// Start mock implementation of Start from Manager interface
func (m *MockManager) Start(ctx context.Context, iface *iface.WGIface) {
}

// SetRouteChangeListener mock implementation of SetRouteChangeListener from Manager interface
func (m *MockManager) SetRouteChangeListener(listener listener.NetworkChangeListener) {

}

func (m *MockManager) EnableServerRouter(firewall firewall.Manager) error {
	panic("implement me")
}

// Stop mock implementation of Stop from Manager interface
func (m *MockManager) Stop(stateManager *statemanager.Manager) {
	if m.StopFunc != nil {
		m.StopFunc(stateManager)
	}
}

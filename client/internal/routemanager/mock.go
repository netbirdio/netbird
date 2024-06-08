package routemanager

import (
	"context"
	"fmt"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

// MockManager is the mock instance of a route manager
type MockManager struct {
	UpdateRoutesFunc     func(updateSerial uint64, newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap, error)
	TriggerSelectionFunc func(haMap route.HAMap)
	GetRouteSelectorFunc func() *routeselector.RouteSelector
	StopFunc             func()
}

func (m *MockManager) Init() (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return nil, nil, nil
}

// InitialRouteRange mock implementation of InitialRouteRange from Manager interface
func (m *MockManager) InitialRouteRange() []string {
	return nil
}

// UpdateRoutes mock implementation of UpdateRoutes from Manager interface
func (m *MockManager) UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap, error) {
	if m.UpdateRoutesFunc != nil {
		return m.UpdateRoutesFunc(updateSerial, newRoutes)
	}
	return nil, nil, fmt.Errorf("method UpdateRoutes is not implemented")
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

// Start mock implementation of Start from Manager interface
func (m *MockManager) Start(ctx context.Context, iface *iface.WGIface) {
}

// SetRouteChangeListener mock implementation of SetRouteChangeListener from Manager interface
func (m *MockManager) SetRouteChangeListener(listener listener.NetworkChangeListener) {

}

func (m *MockManager) EnableServerRouter(firewall firewall.Manager) error {
	panic("implement me")
}

func (m *MockManager) ResetV6Routes() {
	panic("implement me")
}

// Stop mock implementation of Stop from Manager interface
func (m *MockManager) Stop() {
	if m.StopFunc != nil {
		m.StopFunc()
	}
}

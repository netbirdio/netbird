package routemanager

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

// MockManager is the mock instance of a route manager
type MockManager struct {
	UpdateRoutesFunc func(updateSerial uint64, newRoutes []*route.Route) error
	StopFunc         func()
}

func (m *MockManager) InitialClientRoutesNetworks() []string {
	return nil
}

// UpdateRoutes mock implementation of UpdateRoutes from Manager interface
func (m *MockManager) UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error {
	if m.UpdateRoutesFunc != nil {
		return m.UpdateRoutesFunc(updateSerial, newRoutes)
	}
	return fmt.Errorf("method UpdateRoutes is not implemented")
}

// Start mock implementation of Start from Manager interface
func (m *MockManager) Start(ctx context.Context, iface *iface.WGIface) {
}

// Stop mock implementation of Stop from Manager interface
func (m *MockManager) Stop() {
	if m.StopFunc != nil {
		m.StopFunc()
	}
}

package routemanager

import (
	"fmt"
	"github.com/netbirdio/netbird/route"
)

// MockManager is the mock instance of a route manager
type MockManager struct {
	UpdateRoutesFunc func(updateSerial uint64, newRoutes []*route.Route) error
	StopFunc         func()
}

// UpdateRoutes mock implementation of UpdateRoutes from Manager interface
func (m *MockManager) UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error {
	if m.UpdateRoutesFunc != nil {
		return m.UpdateRoutesFunc(updateSerial, newRoutes)
	}
	return fmt.Errorf("method UpdateRoutes is not implemented")
}

// Stop mock implementation of Stop from Manager interface
func (m *MockManager) Stop() {
	if m.StopFunc != nil {
		m.StopFunc()
	}
}

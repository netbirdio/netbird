package routemanager

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

// DefaultManager dummy router manager for Android
type DefaultManager struct {
	ctx          context.Context
	serverRouter *serverRouter
	wgInterface  *iface.WGIface
}

// NewManager returns a new dummy route manager what doing nothing
func NewManager(ctx context.Context, pubKey string, wgInterface *iface.WGIface, statusRecorder *peer.Status) *DefaultManager {
	return &DefaultManager{}
}

// UpdateRoutes ...
func (m *DefaultManager) UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error {
	return nil
}

// Stop ...
func (m *DefaultManager) Stop() {

}

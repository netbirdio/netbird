package netflow

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/netbirdio/netbird/client/internal/netflow/conntrack"
	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

// Manager handles netflow tracking and logging
type Manager struct {
	mux        sync.Mutex
	logger     types.FlowLogger
	flowConfig *types.FlowConfig
	conntrack  types.ConnTracker
}

// NewManager creates a new netflow manager
func NewManager(ctx context.Context, iface types.IFaceMapper) *Manager {
	flowLogger := logger.New(ctx)

	var ct types.ConnTracker
	if runtime.GOOS == "linux" && iface != nil && !iface.IsUserspaceBind() {
		ct = conntrack.New(flowLogger, iface)
	}

	return &Manager{
		logger:    flowLogger,
		conntrack: ct,
	}
}

// Update applies new flow configuration settings
func (m *Manager) Update(update *types.FlowConfig) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	if update == nil {
		return nil
	}

	m.flowConfig = update

	if update.Enabled {
		if m.conntrack != nil {
			if err := m.conntrack.Start(); err != nil {
				return fmt.Errorf("start conntrack: %w", err)
			}
		}

		m.logger.Enable()
		return nil
	}

	if m.conntrack != nil {
		m.conntrack.Stop()
	}
	m.logger.Disable()

	return nil
}

// Close cleans up all resources
func (m *Manager) Close() {
	m.mux.Lock()
	defer m.mux.Unlock()

	if m.conntrack != nil {
		m.conntrack.Close()
	}
	m.logger.Close()
}

// GetLogger returns the flow logger
func (m *Manager) GetLogger() types.FlowLogger {
	return m.logger
}

package netflow

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

type Manager struct {
	mux        sync.Mutex
	logger     types.FlowLogger
	flowConfig *types.FlowConfig
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		logger: logger.New(ctx),
	}
}

func (m *Manager) Update(update *types.FlowConfig) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	if update == nil {
		return nil
	}

	m.flowConfig = update

	if update.Enabled {
		m.logger.Enable()
		return nil
	}

	m.logger.Disable()

	return nil
}

func (m *Manager) Close() {
	m.logger.Close()
}

func (m *Manager) GetLogger() types.FlowLogger {
	return m.logger
}

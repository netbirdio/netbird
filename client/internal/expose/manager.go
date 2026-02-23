package expose

import (
	"context"
	"time"

	mgm "github.com/netbirdio/netbird/shared/management/client"
)

const renewTimeout = 10 * time.Second

// Response holds the response from exposing a service.
type Response struct {
	ServiceName string
	ServiceURL  string
	Domain      string
}

type Request struct {
	NamePrefix string
	Domain     string
	Port       uint16
	Protocol   int
	Pin        uint32
	Password   string
	UserGroups []string
}

type ManagementClient interface {
	CreateExpose(ctx context.Context, req mgm.ExposeRequest) (*mgm.ExposeResponse, error)
	RenewExpose(ctx context.Context, domain string) error
	StopExpose(ctx context.Context, domain string) error
}

// Manager handles expose session lifecycle via the management client.
type Manager struct {
	mgmClient ManagementClient
}

// NewManager creates a new expose Manager using the given management client.
func NewManager(mgmClient ManagementClient) *Manager {
	return &Manager{mgmClient: mgmClient}
}

// Expose creates a new expose session via the management server.
func (m *Manager) Expose(ctx context.Context, req Request) (*Response, error) {
	resp, err := m.mgmClient.CreateExpose(ctx, toClientExposeRequest(req))
	if err != nil {
		return nil, err
	}

	return fromClientExposeResponse(resp), nil
}

// Renew extends the TTL of an active expose session.
func (m *Manager) Renew(ctx context.Context, domain string) error {
	renewCtx, cancel := context.WithTimeout(ctx, renewTimeout)
	defer cancel()
	return m.mgmClient.RenewExpose(renewCtx, domain)
}

// Stop terminates an active expose session.
func (m *Manager) Stop(ctx context.Context, domain string) error {
	return m.mgmClient.StopExpose(ctx, domain)
}

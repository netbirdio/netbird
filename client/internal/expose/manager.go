package expose

import (
	"context"
	"time"

	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

const renewTimeout = 10 * time.Second

// Result holds the response from creating an expose session.
type Result struct {
	ServiceName string
	ServiceURL  string
	Domain      string
}

// Manager handles expose session lifecycle via the management client.
type Manager struct {
	mgmClient mgm.Client
}

// NewManager creates a new expose Manager using the given management client.
func NewManager(mgmClient mgm.Client) *Manager {
	return &Manager{mgmClient: mgmClient}
}

// Expose creates a new expose session via the management server.
func (m *Manager) Expose(ctx context.Context, req *mgmProto.ExposeServiceRequest) (*Result, error) {
	resp, err := m.mgmClient.CreateExpose(ctx, req)
	if err != nil {
		return nil, err
	}

	return &Result{
		ServiceName: resp.ServiceName,
		ServiceURL:  resp.ServiceUrl,
		Domain:      resp.Domain,
	}, nil
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

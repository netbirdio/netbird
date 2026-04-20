package expose

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	mgm "github.com/netbirdio/netbird/shared/management/client"
)

const (
	renewTimeout = 10 * time.Second
)

// Response holds the response from exposing a service.
type Response struct {
	ServiceName      string
	ServiceURL       string
	Domain           string
	PortAutoAssigned bool
}

// Request holds the parameters for exposing a local service via the management server.
// It is part of the embed API surface and exposed via a type alias.
type Request struct {
	NamePrefix string
	Domain     string
	Port       uint16
	Protocol   ProtocolType
	Pin        string
	Password   string
	UserGroups []string
	ListenPort uint16
}

type ManagementClient interface {
	CreateExpose(ctx context.Context, req mgm.ExposeRequest) (*mgm.ExposeResponse, error)
	RenewExpose(ctx context.Context, domain string) error
	StopExpose(ctx context.Context, domain string) error
}

// Manager handles expose session lifecycle via the management client.
type Manager struct {
	mgmClient ManagementClient
	ctx       context.Context
}

// NewManager creates a new expose Manager using the given management client.
func NewManager(ctx context.Context, mgmClient ManagementClient) *Manager {
	return &Manager{mgmClient: mgmClient, ctx: ctx}
}

// Expose creates a new expose session via the management server.
func (m *Manager) Expose(ctx context.Context, req Request) (*Response, error) {
	log.Infof("exposing service on port %d", req.Port)
	resp, err := m.mgmClient.CreateExpose(ctx, toClientExposeRequest(req))
	if err != nil {
		return nil, err
	}

	log.Infof("expose session created for %s", resp.Domain)

	return fromClientExposeResponse(resp), nil
}

// KeepAlive periodically renews the expose session for the given domain until the context is canceled or an error occurs.
// It is part of the embed API surface and exposed via a type alias.
func (m *Manager) KeepAlive(ctx context.Context, domain string) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer m.stop(domain)

	for {
		select {
		case <-ctx.Done():
			log.Infof("context canceled, stopping keep alive for %s", domain)

			return nil
		case <-ticker.C:
			if err := m.renew(ctx, domain); err != nil {
				log.Errorf("renewing expose session for %s: %v", domain, err)
				return err
			}
		}
	}
}

// renew extends the TTL of an active expose session.
func (m *Manager) renew(ctx context.Context, domain string) error {
	renewCtx, cancel := context.WithTimeout(ctx, renewTimeout)
	defer cancel()
	return m.mgmClient.RenewExpose(renewCtx, domain)
}

// stop terminates an active expose session.
func (m *Manager) stop(domain string) {
	stopCtx, cancel := context.WithTimeout(m.ctx, renewTimeout)
	defer cancel()
	err := m.mgmClient.StopExpose(stopCtx, domain)
	if err != nil {
		log.Warnf("Failed stopping expose session for %s: %v", domain, err)
	}
}

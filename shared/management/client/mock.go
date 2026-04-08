package client

import (
	"context"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// MockClient is a mock implementation of the Client interface for testing.
type MockClient struct {
	CloseFunc                      func() error
	SyncFunc                       func(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error
	RegisterFunc                   func(setupKey string, jwtToken string, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	LoginFunc                      func(info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlowFunc func() (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlowFunc   func() (*proto.PKCEAuthorizationFlow, error)
	GetServerURLFunc               func() string
	HealthCheckFunc                func() error
	SyncMetaFunc                   func(sysInfo *system.Info) error
	LogoutFunc                     func() error
	JobFunc                        func(ctx context.Context, msgHandler func(msg *proto.JobRequest) *proto.JobResponse) error
	CreateExposeFunc               func(ctx context.Context, req ExposeRequest) (*ExposeResponse, error)
	RenewExposeFunc                func(ctx context.Context, domain string) error
	StopExposeFunc                 func(ctx context.Context, domain string) error
}

func (m *MockClient) IsHealthy() bool {
	return true
}

func (m *MockClient) Close() error {
	if m.CloseFunc == nil {
		return nil
	}
	return m.CloseFunc()
}

func (m *MockClient) Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error {
	if m.SyncFunc == nil {
		return nil
	}
	return m.SyncFunc(ctx, sysInfo, msgHandler)
}

func (m *MockClient) Job(ctx context.Context, msgHandler func(msg *proto.JobRequest) *proto.JobResponse) error {
	if m.JobFunc == nil {
		return nil
	}
	return m.JobFunc(ctx, msgHandler)
}

func (m *MockClient) Register(setupKey string, jwtToken string, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	if m.RegisterFunc == nil {
		return nil, nil
	}
	return m.RegisterFunc(setupKey, jwtToken, info, sshKey, dnsLabels)
}

func (m *MockClient) Login(info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	if m.LoginFunc == nil {
		return nil, nil
	}
	return m.LoginFunc(info, sshKey, dnsLabels)
}

func (m *MockClient) GetDeviceAuthorizationFlow() (*proto.DeviceAuthorizationFlow, error) {
	if m.GetDeviceAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetDeviceAuthorizationFlowFunc()
}

func (m *MockClient) GetPKCEAuthorizationFlow() (*proto.PKCEAuthorizationFlow, error) {
	if m.GetPKCEAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetPKCEAuthorizationFlowFunc()
}

func (m *MockClient) HealthCheck() error {
	if m.HealthCheckFunc == nil {
		return nil
	}
	return m.HealthCheckFunc()
}

// GetNetworkMap mock implementation of GetNetworkMap from Client interface.
func (m *MockClient) GetNetworkMap(_ *system.Info) (*proto.NetworkMap, error) {
	return nil, nil
}

// GetServerURL mock implementation of GetServerURL from mgm.Client interface
func (m *MockClient) GetServerURL() string {
	if m.GetServerURLFunc == nil {
		return ""
	}
	return m.GetServerURLFunc()
}

func (m *MockClient) SyncMeta(sysInfo *system.Info) error {
	if m.SyncMetaFunc == nil {
		return nil
	}
	return m.SyncMetaFunc(sysInfo)
}

func (m *MockClient) Logout() error {
	if m.LogoutFunc == nil {
		return nil
	}
	return m.LogoutFunc()
}

func (m *MockClient) CreateExpose(ctx context.Context, req ExposeRequest) (*ExposeResponse, error) {
	if m.CreateExposeFunc == nil {
		return nil, nil
	}
	return m.CreateExposeFunc(ctx, req)
}

func (m *MockClient) RenewExpose(ctx context.Context, domain string) error {
	if m.RenewExposeFunc == nil {
		return nil
	}
	return m.RenewExposeFunc(ctx, domain)
}

func (m *MockClient) StopExpose(ctx context.Context, domain string) error {
	if m.StopExposeFunc == nil {
		return nil
	}
	return m.StopExposeFunc(ctx, domain)
}

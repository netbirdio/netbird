package client

import (
	"context"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type MockClient struct {
	CloseFunc                      func() error
	SyncFunc                       func(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error
	RegisterFunc                   func(ctx context.Context, setupKey string, jwtToken string, info *system.Info, sshKey []byte, dnsLabels domain.List) error
	LoginFunc                      func(ctx context.Context, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlowFunc func(ctx context.Context) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlowFunc   func(ctx context.Context) (*proto.PKCEAuthorizationFlow, error)
	SyncMetaFunc                   func(ctx context.Context, sysInfo *system.Info) error
	HealthCheckFunc                func(ctx context.Context) error
	LogoutFunc                     func(ctx context.Context) error
	IsHealthyFunc                  func(ctx context.Context) bool
}

func (m *MockClient) IsHealthy(ctx context.Context) bool {
	if m.IsHealthyFunc == nil {
		return true
	}
	return m.IsHealthyFunc(ctx)
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

func (m *MockClient) Register(ctx context.Context, setupKey string, jwtToken string, info *system.Info, sshKey []byte, dnsLabels domain.List) error {
	if m.RegisterFunc == nil {
		return nil
	}
	return m.RegisterFunc(ctx, setupKey, jwtToken, info, sshKey, dnsLabels)
}

func (m *MockClient) Login(ctx context.Context, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	if m.LoginFunc == nil {
		return nil, nil
	}
	return m.LoginFunc(ctx, info, sshKey, dnsLabels)
}

func (m *MockClient) GetDeviceAuthorizationFlow(ctx context.Context) (*proto.DeviceAuthorizationFlow, error) {
	if m.GetDeviceAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetDeviceAuthorizationFlowFunc(ctx)
}

func (m *MockClient) GetPKCEAuthorizationFlow(ctx context.Context) (*proto.PKCEAuthorizationFlow, error) {
	if m.GetPKCEAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetPKCEAuthorizationFlowFunc(ctx)
}

// GetNetworkMap mock implementation of GetNetworkMap from mgm.Client interface
func (m *MockClient) GetNetworkMap(ctx context.Context, _ *system.Info) (*proto.NetworkMap, error) {
	return nil, nil
}

func (m *MockClient) SyncMeta(ctx context.Context, sysInfo *system.Info) error {
	if m.SyncMetaFunc == nil {
		return nil
	}
	return m.SyncMetaFunc(ctx, sysInfo)
}

func (m *MockClient) HealthCheck(ctx context.Context) error {
	if m.HealthCheckFunc == nil {
		return nil
	}
	return m.HealthCheckFunc(ctx)
}

func (m *MockClient) Logout(ctx context.Context) error {
	if m.LogoutFunc == nil {
		return nil
	}
	return m.LogoutFunc(ctx)
}

package client

import (
	"context"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type MockClient struct {
	CloseFunc                      func() error
	SyncFunc                       func(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error
	GetServerPublicKeyFunc         func() (*wgtypes.Key, error)
	RegisterFunc                   func(serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	LoginFunc                      func(serverKey wgtypes.Key, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlowFunc func(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlowFunc   func(serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error)
	SyncMetaFunc                   func(sysInfo *system.Info) error
	LogoutFunc                     func() error
	JobFunc                        func(ctx context.Context, msgHandler func(msg *proto.JobRequest) *proto.JobResponse) error
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

func (m *MockClient) GetServerPublicKey() (*wgtypes.Key, error) {
	if m.GetServerPublicKeyFunc == nil {
		return nil, nil
	}
	return m.GetServerPublicKeyFunc()
}

func (m *MockClient) Register(serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	if m.RegisterFunc == nil {
		return nil, nil
	}
	return m.RegisterFunc(serverKey, setupKey, jwtToken, info, sshKey, dnsLabels)
}

func (m *MockClient) Login(serverKey wgtypes.Key, info *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	if m.LoginFunc == nil {
		return nil, nil
	}
	return m.LoginFunc(serverKey, info, sshKey, dnsLabels)
}

func (m *MockClient) GetDeviceAuthorizationFlow(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error) {
	if m.GetDeviceAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetDeviceAuthorizationFlowFunc(serverKey)
}

func (m *MockClient) GetPKCEAuthorizationFlow(serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error) {
	if m.GetPKCEAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetPKCEAuthorizationFlow(serverKey)
}

// GetNetworkMap mock implementation of GetNetworkMap from mgm.Client interface
func (m *MockClient) GetNetworkMap(_ *system.Info) (*proto.NetworkMap, error) {
	return nil, nil
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

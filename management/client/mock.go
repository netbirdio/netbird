package client

import (
	"context"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/management/proto"
)

type MockClient struct {
	CloseFunc                      func() error
	SyncFunc                       func(ctx context.Context, sysInfo *system.Info, msgHandler func(ctx context.Context, msg *proto.SyncResponse) error) error
	GetServerPublicKeyFunc         func(ctx context.Context) (*wgtypes.Key, error)
	RegisterFunc                   func(ctx context.Context, serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	LoginFunc                      func(ctx context.Context, serverKey wgtypes.Key, info *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlowFunc func(ctx context.Context, serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlowFunc   func(ctx context.Context, serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error)
	SyncMetaFunc                   func(ctx context.Context, sysInfo *system.Info) error
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

func (m *MockClient) Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(ctx context.Context, msg *proto.SyncResponse) error) error {
	if m.SyncFunc == nil {
		return nil
	}
	return m.SyncFunc(ctx, sysInfo, msgHandler)
}

func (m *MockClient) GetServerPublicKey(ctx context.Context) (*wgtypes.Key, error) {
	if m.GetServerPublicKeyFunc == nil {
		return nil, nil
	}
	return m.GetServerPublicKeyFunc(ctx)
}

func (m *MockClient) Register(ctx context.Context, serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info, sshKey []byte) (*proto.LoginResponse, error) {
	if m.RegisterFunc == nil {
		return nil, nil
	}
	return m.RegisterFunc(ctx, serverKey, setupKey, jwtToken, info, sshKey)
}

func (m *MockClient) Login(ctx context.Context, serverKey wgtypes.Key, info *system.Info, sshKey []byte) (*proto.LoginResponse, error) {
	if m.LoginFunc == nil {
		return nil, nil
	}
	return m.LoginFunc(ctx, serverKey, info, sshKey)
}

func (m *MockClient) GetDeviceAuthorizationFlow(ctx context.Context, serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error) {
	if m.GetDeviceAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetDeviceAuthorizationFlowFunc(ctx, serverKey)
}

func (m *MockClient) GetPKCEAuthorizationFlow(ctx context.Context, serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error) {
	if m.GetPKCEAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetPKCEAuthorizationFlow(ctx, serverKey)
}

// GetNetworkMap mock implementation of GetNetworkMap from mgm.Client interface
func (m *MockClient) GetNetworkMap(_ context.Context, _ *system.Info) (*proto.NetworkMap, error) {
	return nil, nil
}

func (m *MockClient) SyncMeta(ctx context.Context, sysInfo *system.Info) error {
	if m.SyncMetaFunc == nil {
		return nil
	}
	return m.SyncMetaFunc(ctx, sysInfo)
}

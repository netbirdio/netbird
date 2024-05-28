package client

import (
	"context"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/management/proto"
)

type MockClient struct {
	CloseFunc                      func() error
	SyncFunc                       func(ctx context.Context, msgHandler func(msg *proto.SyncResponse) error) error
	GetServerPublicKeyFunc         func() (*wgtypes.Key, error)
	RegisterFunc                   func(serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	LoginFunc                      func(serverKey wgtypes.Key, info *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlowFunc func(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlowFunc   func(serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error)
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

func (m *MockClient) Sync(ctx context.Context, msgHandler func(msg *proto.SyncResponse) error) error {
	if m.SyncFunc == nil {
		return nil
	}
	return m.SyncFunc(ctx, msgHandler)
}

func (m *MockClient) GetServerPublicKey() (*wgtypes.Key, error) {
	if m.GetServerPublicKeyFunc == nil {
		return nil, nil
	}
	return m.GetServerPublicKeyFunc()
}

func (m *MockClient) Register(serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info, sshKey []byte) (*proto.LoginResponse, error) {
	if m.RegisterFunc == nil {
		return nil, nil
	}
	return m.RegisterFunc(serverKey, setupKey, jwtToken, info, sshKey)
}

func (m *MockClient) Login(serverKey wgtypes.Key, info *system.Info, sshKey []byte) (*proto.LoginResponse, error) {
	if m.LoginFunc == nil {
		return nil, nil
	}
	return m.LoginFunc(serverKey, info, sshKey)
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
func (m *MockClient) GetNetworkMap() (*proto.NetworkMap, error) {
	return nil, nil
}

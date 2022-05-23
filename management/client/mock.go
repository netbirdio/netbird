package client

import (
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type MockClient struct {
	CloseFunc                      func() error
	SyncFunc                       func(msgHandler func(msg *proto.SyncResponse) error) error
	GetServerPublicKeyFunc         func() (*wgtypes.Key, error)
	RegisterFunc                   func(serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info) (*proto.LoginResponse, error)
	LoginFunc                      func(serverKey wgtypes.Key) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlowFunc func(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error)
}

func (m *MockClient) Close() error {
	if m.CloseFunc == nil {
		return nil
	}
	return m.CloseFunc()
}

func (m *MockClient) Sync(msgHandler func(msg *proto.SyncResponse) error) error {
	if m.SyncFunc == nil {
		return nil
	}
	return m.SyncFunc(msgHandler)
}

func (m *MockClient) GetServerPublicKey() (*wgtypes.Key, error) {
	if m.GetServerPublicKeyFunc == nil {
		return nil, nil
	}
	return m.GetServerPublicKeyFunc()
}

func (m *MockClient) Register(serverKey wgtypes.Key, setupKey string, jwtToken string, info *system.Info) (*proto.LoginResponse, error) {
	if m.RegisterFunc == nil {
		return nil, nil
	}
	return m.RegisterFunc(serverKey, setupKey, jwtToken, info)
}

func (m *MockClient) Login(serverKey wgtypes.Key, info *system.Info) (*proto.LoginResponse, error) {
	if m.LoginFunc == nil {
		return nil, nil
	}
	return m.LoginFunc(serverKey)
}

func (m *MockClient) GetDeviceAuthorizationFlow(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error) {
	if m.GetDeviceAuthorizationFlowFunc == nil {
		return nil, nil
	}
	return m.GetDeviceAuthorizationFlowFunc(serverKey)
}

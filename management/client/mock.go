package client

import (
	"github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type MockClient struct {
	CloseFunc              func() error
	SyncFunc               func(msgHandler func(msg *proto.SyncResponse) error) error
	GetServerPublicKeyFunc func() (*wgtypes.Key, error)
	RegisterFunc           func(serverKey wgtypes.Key, setupKey string) (*proto.LoginResponse, error)
	LoginFunc              func(serverKey wgtypes.Key) (*proto.LoginResponse, error)
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

func (m *MockClient) Register(serverKey wgtypes.Key, setupKey string) (*proto.LoginResponse, error) {
	if m.RegisterFunc == nil {
		return nil, nil
	}
	return m.RegisterFunc(serverKey, setupKey)
}

func (m *MockClient) Login(serverKey wgtypes.Key) (*proto.LoginResponse, error) {
	if m.LoginFunc == nil {
		return nil, nil
	}
	return m.LoginFunc(serverKey)
}

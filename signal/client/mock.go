package client

import (
	"context"

	"github.com/netbirdio/netbird/signal/proto"
)

type MockClient struct {
	CloseFunc               func() error
	GetStatusFunc           func() Status
	StreamConnectedFunc     func() bool
	ReadyFunc               func() bool
	WaitStreamConnectedFunc func()
	ReceiveFunc             func(ctx context.Context, msgHandler func(msg *proto.Message) error) error
	SendToStreamFunc        func(msg *proto.EncryptedMessage) error
	SendFunc                func(msg *proto.Message) error
}

func (sm *MockClient) IsHealthy() bool {
	return true
}

func (sm *MockClient) Close() error {
	if sm.CloseFunc == nil {
		return nil
	}
	return sm.CloseFunc()
}

func (sm *MockClient) GetStatus() Status {
	if sm.GetStatusFunc == nil {
		return ""
	}
	return sm.GetStatusFunc()
}

func (sm *MockClient) StreamConnected() bool {
	if sm.StreamConnectedFunc == nil {
		return false
	}
	return sm.StreamConnectedFunc()
}

func (sm *MockClient) Ready() bool {
	if sm.ReadyFunc == nil {
		return false
	}
	return sm.ReadyFunc()
}

func (sm *MockClient) WaitStreamConnected() {
	if sm.WaitStreamConnectedFunc == nil {
		return
	}
	sm.WaitStreamConnectedFunc()
}

func (sm *MockClient) Receive(ctx context.Context, msgHandler func(msg *proto.Message) error) error {
	if sm.ReceiveFunc == nil {
		return nil
	}
	return sm.ReceiveFunc(ctx, msgHandler)
}

func (sm *MockClient) SendToStream(msg *proto.EncryptedMessage) error {
	if sm.SendToStreamFunc == nil {
		return nil
	}
	return sm.SendToStreamFunc(msg)
}

func (sm *MockClient) Send(msg *proto.Message) error {
	if sm.SendFunc == nil {
		return nil
	}
	return sm.SendFunc(msg)
}

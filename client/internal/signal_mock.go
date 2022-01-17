package internal

import (
	"github.com/wiretrustee/wiretrustee/signal/client"
	"github.com/wiretrustee/wiretrustee/signal/proto"
)

type SignalClientMock struct {
	CloseFunc               func() error
	GetStatusFunc           func() client.Status
	StreamConnectedFunc     func() bool
	ReadyFunc               func() bool
	WaitStreamConnectedFunc func()
	ReceiveFunc             func(msgHandler func(msg *proto.Message) error) error
	SendToStreamFunc        func(msg *proto.EncryptedMessage) error
	SendFunc                func(msg *proto.Message) error
}

func (sm *SignalClientMock) Close() error {
	if sm.CloseFunc == nil {
		return nil
	}
	return sm.CloseFunc()
}

func (sm *SignalClientMock) GetStatus() client.Status {
	if sm.GetStatusFunc == nil {
		return ""
	}
	return sm.GetStatusFunc()
}

func (sm *SignalClientMock) StreamConnected() bool {
	if sm.StreamConnectedFunc == nil {
		return false
	}
	return sm.StreamConnectedFunc()
}

func (sm *SignalClientMock) Ready() bool {
	if sm.ReadyFunc == nil {
		return false
	}
	return sm.ReadyFunc()
}

func (sm *SignalClientMock) WaitStreamConnected() {
	if sm.WaitStreamConnectedFunc == nil {
		return
	}
	sm.WaitStreamConnectedFunc()
}

func (sm *SignalClientMock) Receive(msgHandler func(msg *proto.Message) error) error {
	if sm.ReceiveFunc == nil {
		return nil
	}
	return sm.ReceiveFunc(msgHandler)
}

func (sm *SignalClientMock) SendToStream(msg *proto.EncryptedMessage) error {
	if sm.SendToStreamFunc == nil {
		return nil
	}
	return sm.SendToStreamFunc(msg)
}

func (sm *SignalClientMock) Send(msg *proto.Message) error {
	if sm.SendFunc == nil {
		return nil
	}
	return sm.SendFunc(msg)
}

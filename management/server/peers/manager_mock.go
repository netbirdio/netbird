// Code generated by MockGen. DO NOT EDIT.
// Source: ./manager.go

// Package peers is a generated GoMock package.
package peers

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	peer "github.com/netbirdio/netbird/management/server/peer"
)

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// GetAllPeers mocks base method.
func (m *MockManager) GetAllPeers(ctx context.Context, accountID, userID string) ([]*peer.Peer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllPeers", ctx, accountID, userID)
	ret0, _ := ret[0].([]*peer.Peer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllPeers indicates an expected call of GetAllPeers.
func (mr *MockManagerMockRecorder) GetAllPeers(ctx, accountID, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllPeers", reflect.TypeOf((*MockManager)(nil).GetAllPeers), ctx, accountID, userID)
}

// GetPeer mocks base method.
func (m *MockManager) GetPeer(ctx context.Context, accountID, userID, peerID string) (*peer.Peer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPeer", ctx, accountID, userID, peerID)
	ret0, _ := ret[0].(*peer.Peer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPeer indicates an expected call of GetPeer.
func (mr *MockManagerMockRecorder) GetPeer(ctx, accountID, userID, peerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPeer", reflect.TypeOf((*MockManager)(nil).GetPeer), ctx, accountID, userID, peerID)
}

// GetPeerAccountID mocks base method.
func (m *MockManager) GetPeerAccountID(ctx context.Context, peerID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPeerAccountID", ctx, peerID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPeerAccountID indicates an expected call of GetPeerAccountID.
func (mr *MockManagerMockRecorder) GetPeerAccountID(ctx, peerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPeerAccountID", reflect.TypeOf((*MockManager)(nil).GetPeerAccountID), ctx, peerID)
}

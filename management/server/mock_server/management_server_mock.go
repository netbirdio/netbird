package mock_server

import (
	"context"

	"github.com/netbirdio/netbird/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ManagementServiceServerMock struct {
	proto.UnimplementedManagementServiceServer

	LoginFunc                      func(context.Context, *proto.EncryptedMessage) (*proto.EncryptedMessage, error)
	SyncFunc                       func(*proto.EncryptedMessage, proto.ManagementService_SyncServer)
	GetServerKeyFunc               func(context.Context, *proto.Empty) (*proto.ServerKeyResponse, error)
	IsHealthyFunc                  func(context.Context, *proto.Empty) (*proto.Empty, error)
	GetDeviceAuthorizationFlowFunc func(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error)
	GetPKCEAuthorizationFlowFunc   func(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error)
}

func (m ManagementServiceServerMock) Login(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}

func (m ManagementServiceServerMock) Sync(msg *proto.EncryptedMessage, sync proto.ManagementService_SyncServer) error {
	if m.SyncFunc != nil {
		return m.Sync(msg, sync)
	}
	return status.Errorf(codes.Unimplemented, "method Sync not implemented")
}

func (m ManagementServiceServerMock) GetServerKey(ctx context.Context, empty *proto.Empty) (*proto.ServerKeyResponse, error) {
	if m.GetServerKeyFunc != nil {
		return m.GetServerKeyFunc(ctx, empty)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetServerKey not implemented")
}

func (m ManagementServiceServerMock) IsHealthy(ctx context.Context, empty *proto.Empty) (*proto.Empty, error) {
	if m.IsHealthyFunc != nil {
		return m.IsHealthyFunc(ctx, empty)
	}
	return nil, status.Errorf(codes.Unimplemented, "method IsHealthy not implemented")
}

func (m ManagementServiceServerMock) GetDeviceAuthorizationFlow(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	if m.GetDeviceAuthorizationFlowFunc != nil {
		return m.GetDeviceAuthorizationFlowFunc(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetDeviceAuthorizationFlow not implemented")
}

func (m ManagementServiceServerMock) GetPKCEAuthorizationFlow(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	if m.GetPKCEAuthorizationFlowFunc != nil {
		return m.GetPKCEAuthorizationFlowFunc(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPKCEAuthorizationFlow not implemented")
}

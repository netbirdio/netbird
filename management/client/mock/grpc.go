package mock

import (
	"context"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"google.golang.org/grpc"
)

type ManagementServiceClientMock struct {
	LoginFunc        func(ctx context.Context, in *proto.EncryptedMessage, opts ...grpc.CallOption) (*proto.EncryptedMessage, error)
	GetServerKeyFunc func(ctx context.Context, in *proto.Empty, opts ...grpc.CallOption) (*proto.ServerKeyResponse, error)
	SyncFunc         func(ctx context.Context, in *proto.EncryptedMessage, opts ...grpc.CallOption) (proto.ManagementService_SyncClient, error)
	IsHealthyFunc    func(ctx context.Context, in *proto.Empty, opts ...grpc.CallOption) (*proto.Empty, error)
}

func (c *ManagementServiceClientMock) Login(ctx context.Context, in *proto.EncryptedMessage, opts ...grpc.CallOption) (*proto.EncryptedMessage, error) {
	if c.LoginFunc != nil {
		return c.LoginFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (c *ManagementServiceClientMock) Sync(ctx context.Context, in *proto.EncryptedMessage, opts ...grpc.CallOption) (proto.ManagementService_SyncClient, error) {
	if c.SyncFunc != nil {
		return c.SyncFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (c *ManagementServiceClientMock) GetServerKey(ctx context.Context, in *proto.Empty, opts ...grpc.CallOption) (*proto.ServerKeyResponse, error) {
	if c.GetServerKeyFunc != nil {
		return c.GetServerKeyFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (c *ManagementServiceClientMock) IsHealthy(ctx context.Context, in *proto.Empty, opts ...grpc.CallOption) (*proto.Empty, error) {
	if c.IsHealthyFunc != nil {
		return c.IsHealthyFunc(ctx, in, opts...)
	}
	return nil, nil
}

type ManagementServiceSyncClientMock struct {
	grpc.ClientStream
}

func (x *ManagementServiceSyncClientMock) Recv() (*proto.EncryptedMessage, error) {
	return nil, nil
}

type GrpcConnectorMock struct {
	ClientMock *ManagementServiceClientMock
	ConnMock   *grpc.ClientConn
}

func (c *GrpcConnectorMock) Connect() (proto.ManagementServiceClient, *grpc.ClientConn, error) {
	return c.ClientMock, c.ConnMock, nil
}

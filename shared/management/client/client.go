package client

import (
	"context"
	"io"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type Client interface {
	io.Closer
	Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error
	Register(ctx context.Context, setupKey string, jwtToken string, sysInfo *system.Info, sshKey []byte, dnsLabels domain.List) error
	Login(ctx context.Context, sysInfo *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlow(ctx context.Context) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlow(ctx context.Context) (*proto.PKCEAuthorizationFlow, error)
	GetNetworkMap(ctx context.Context, sysInfo *system.Info) (*proto.NetworkMap, error)
	IsHealthy(ctx context.Context) bool
	HealthCheck(ctx context.Context) error
	SyncMeta(ctx context.Context, sysInfo *system.Info) error
	Logout(ctx context.Context) error
}

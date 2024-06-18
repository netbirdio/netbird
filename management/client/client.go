package client

import (
	"context"
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/management/proto"
)

type Client interface {
	io.Closer
	Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(ctx context.Context, msg *proto.SyncResponse) error) error
	GetServerPublicKey(ctx context.Context) (*wgtypes.Key, error)
	Register(ctx context.Context, serverKey wgtypes.Key, setupKey string, jwtToken string, sysInfo *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	Login(ctx context.Context, serverKey wgtypes.Key, sysInfo *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlow(ctx context.Context, serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlow(ctx context.Context, serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error)
	GetNetworkMap(ctx context.Context, sysInfo *system.Info) (*proto.NetworkMap, error)
	IsHealthy() bool
	SyncMeta(ctx context.Context, sysInfo *system.Info) error
}

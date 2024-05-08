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
	Sync(ctx context.Context, msgHandler func(msg *proto.SyncResponse) error) error
	GetServerPublicKey() (*wgtypes.Key, error)
	Register(serverKey wgtypes.Key, setupKey string, jwtToken string, sysInfo *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	Login(serverKey wgtypes.Key, sysInfo *system.Info, sshKey []byte) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlow(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlow(serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error)
	GetNetworkMap() (*proto.NetworkMap, error)
	IsHealthy() bool
}

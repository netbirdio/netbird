package client

import (
	"context"
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type Client interface {
	io.Closer
	Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error
	Job(ctx context.Context, msgHandler func(msg *proto.JobRequest) error) error 
	GetServerPublicKey() (*wgtypes.Key, error)
	Register(serverKey wgtypes.Key, setupKey string, jwtToken string, sysInfo *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	Login(serverKey wgtypes.Key, sysInfo *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlow(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlow(serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error)
	GetNetworkMap(sysInfo *system.Info) (*proto.NetworkMap, error)
	IsHealthy() bool
	SyncMeta(sysInfo *system.Info) error
	Logout() error
}

package client

import (
	"io"

	"github.com/wiretrustee/wiretrustee/client/system"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Client interface {
	io.Closer
	Sync(msgHandler func(msg *proto.SyncResponse) error) error
	GetServerPublicKey() (*wgtypes.Key, error)
	Register(serverKey wgtypes.Key, setupKey string, info *system.Info) (*proto.LoginResponse, error)
	// RegisterV2(serverKey wgtypes.Key, setupKey string, info *system.Info) (*proto.LoginResponse, error)
	Login(serverKey wgtypes.Key) (*proto.LoginResponse, error)
}
